"""Patching and SSH-access operations: the multi-step work the connector does for CPU patching.

Same rule as operations.py: the control plane only names an operation and sends values. The connector checks every
value here and builds each command and script itself from fixed templates. The apply scripts, the staging copy and the
authorized_keys edits all live in this file, on the client's side.

Operations
  catalog        latest JDK / WebLogic / Tuxedo / Database client levels (Oracle Java releases, Oracle Support)
  patch.download download patches into the connector's cache (all from Oracle Support)
  patch.stage    copy cached patches to a server's staging folder, checksum-verified
  host.idle      fail if WebLogic or Tuxedo processes are still running (checked before patching binaries)
  patch.apply    back up a home and apply a staged patch as the software owner, detached on the server
  access.check / access.add / access.remove   a person's SSH public key in an account's authorized_keys
  os.check       Linux package updates available on a server (read-only)
  os.download    download them ahead of the maintenance window (yum update --downloadonly)
  os.update      yum update (all available updates), detached on the server, and report whether a reboot is needed
  host.reboot    reboot only if Linux says it's needed, then wait until the server is back
"""
import base64
import hashlib
import re
import secrets
import shlex
import time
from pathlib import Path

import paramiko

from . import discovery, oracle
from .operations import SAFE_ABS_PATH, SAFE_NAME, OperationError, check_target

SAFE_FILE = re.compile(r"^[A-Za-z0-9_.+\-]{1,200}$")
PATCH_NO = re.compile(r"^\d{5,12}$")
PLATFORM = re.compile(r"^\d{1,5}[PL]$")
JDK_VERSION = re.compile(r"^[0-9][0-9._]{0,30}$")
MAJOR = re.compile(r"^\d{1,3}$")
COMPONENTS = ("jdk", "weblogic", "dbclient", "tuxedo")
PROTECTED_DIRS = {"/", "/u01", "/u01/app", "/u01/app/oracle", "/u01/app/oracle/product", "/home", "/root", "/etc",
                  "/usr", "/var", "/opt", "/tmp", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys"}
HANDLED = ("catalog", "patch.download", "patch.stage", "patch.apply", "host.idle",
           "access.check", "access.add", "access.remove", "discover", "hostkey.trust",
           "os.check", "os.download", "os.update", "host.reboot")


def q(v):
    return shlex.quote(v or "")


def as_owner(os_user, ssh_user, inner):
    """Run `inner` in the software owner's login shell (sudo -n -iu) unless the SSH user is the owner."""
    if os_user and os_user != ssh_user:
        return f"sudo -n -iu {q(os_user)} bash -lc {q(inner)}"
    return f"bash -lc {q(inner)}"


def owner_shell(owner, ssh_user):
    return f"sudo -n -iu {q(owner)} bash -l -s" if owner and owner != ssh_user else "bash -l -s"


def abs_path(v, what, allow_empty=True):
    v = str(v or "")
    if not v and allow_empty:
        return ""
    if not SAFE_ABS_PATH.match(v) or ".." in v:
        raise OperationError(f"{what} must be an absolute path without unusual characters")
    return v.rstrip("/") or "/"


def patch_key(text):
    """'patch|platform|filter' (an Oracle Support patch) or 'version|java|' (a JDK). Returns the parts, validated."""
    parts = str(text or "").split("|")
    if len(parts) != 3:
        raise OperationError("a patch key looks like patch|platform|filter")
    patch, platform, filt = parts
    if platform == "java":
        if not JDK_VERSION.match(patch) or filt:
            raise OperationError("a JDK key looks like 21.0.6|java|")
    else:
        if not PATCH_NO.match(patch) or not PLATFORM.match(platform):
            raise OperationError("an Oracle Support key needs a patch number and a platform code like 226P")
        if filt and not re.match(r"^[A-Za-z0-9_.\-]{1,40}$", filt):
            raise OperationError("the file filter may use letters, digits, . _ and - only")
    return patch, platform, filt


# ---------------------------------------------------------------- validation (before anything runs)
def validate(op, step, ssh_user):
    """Check a step's values. Returns a clean dict the runner uses; raises OperationError for anything else."""
    if op == "catalog":
        majors = [str(m) for m in step.get("jdk_majors") or []]
        versions = [str(v) for v in step.get("jdk_versions") or []]
        if len(majors) > 10 or len(versions) > 50 or not all(MAJOR.match(m) for m in majors) \
                or not all(JDK_VERSION.match(v) for v in versions):
            raise OperationError("JDK versions have unexpected characters")
        return {"majors": majors, "versions": versions, "refresh": bool(step.get("refresh"))}
    if op in ("discover", "hostkey.trust"):
        return discovery.validate(op, step)
    if op == "patch.download":
        keys = [patch_key(k) for k in step.get("keys") or []]
        if not keys or len(keys) > 20:
            raise OperationError("choose between 1 and 20 patches to download")
        return {"keys": keys}
    t = check_target(step.get("target"))
    if op == "host.idle":
        return {"t": t}
    if op in ("os.check", "os.download", "os.update"):
        return {"t": t}
    if op == "host.reboot":
        return {"t": t, "if_needed": step.get("if_needed", True) is not False}
    if op == "patch.stage":
        root = abs_path(step.get("stage_root"), "the staging folder", allow_empty=False)
        items = []
        for it in step.get("items") or []:
            label = str(it.get("label") or "")
            if not SAFE_NAME.match(label):
                raise OperationError("staging folder names may use letters, digits, . _ and - only")
            items.append({"key": patch_key(it.get("key")), "label": label})
        if not items:
            raise OperationError("nothing to stage")
        return {"t": t, "root": root, "items": items}
    if op == "patch.apply":
        comp = str(step.get("component") or "")
        if comp not in COMPONENTS:
            raise OperationError("unknown component")
        owner = str(step.get("owner") or "")
        if not SAFE_NAME.match(owner) or owner == "root":
            raise OperationError("the software owner has unexpected characters")
        staged = step.get("staged") or {}
        files = [str(f) for f in staged.get("files") or []]
        if not files or not all(SAFE_FILE.match(f) for f in files):
            raise OperationError("no staged files, or file names with unexpected characters")
        version = str(step.get("version") or "")
        if version and not re.match(r"^[A-Za-z0-9._\-]{1,40}$", version):
            raise OperationError("version has unexpected characters")
        ids = [str(i) for i in step.get("ids") or [] if str(i).isdigit()]
        home = abs_path(step.get("home"), "the home", allow_empty=False)
        clean = {"t": t, "component": comp, "owner": owner, "home": home,
                 "jdk_home": abs_path(step.get("jdk_home"), "the JDK home"),
                 "wl_home": abs_path(step.get("wl_home"), "the WebLogic home"),
                 "stage_dir": abs_path(staged.get("dir"), "the staging folder", allow_empty=False),
                 "files": files, "version": version, "ids": ids,
                 "level": re.sub(r"\D", "", str(step.get("level") or "")) or "0",
                 "opatch_zip": abs_path(step.get("opatch_zip"), "the OPatch zip")}
        if comp == "jdk" and not JDK_VERSION.match(version):
            raise OperationError("a JDK update needs the exact new version")
        if home.rstrip("/") in PROTECTED_DIRS or home.count("/") < 2:
            raise OperationError(f"{home} is too general a folder to patch")
        clean["script"] = build_apply_script(clean)
        return clean
    if op.startswith("access."):
        account = str(step.get("account") or "")
        if account and not SAFE_NAME.match(account):
            raise OperationError("the account name may use letters, digits, . _ and - only")
        if account == "root":
            raise OperationError("Pegasus doesn't manage root's keys")
        key, err = parse_pubkey(step.get("key"))
        if err:
            raise OperationError(err)
        return {"t": t, "account": account, "key": key, "mode": op.split(".", 1)[1]}
    raise OperationError("unhandled operation")


# ---------------------------------------------------------------- running
class Context:
    def __init__(self, runner, config_path, cache_dir, job_id, poll_interval=5.0):
        self.runner, self.config_path, self.cache_dir = runner, config_path, Path(cache_dir)
        self.job_id, self.poll_interval = job_id, poll_interval

    def sh(self, t, cmd, stdin=None, timeout=300, stdin_path=None):
        buf = []
        code = self.runner.run(t, cmd, stdin, on_output=buf.append, timeout=timeout, stdin_path=stdin_path)
        return code, "".join(buf)


def run(op, c, ctx, out):
    """Run a validated step. Returns (exit code, data for the control plane)."""
    if op == "catalog":
        data = oracle.catalog(ctx.config_path, ctx.cache_dir, c["majors"], c["versions"], c["refresh"], log=out)
        for m, info in data["java"].items():
            out(f"JDK {m}: latest {info.get('version') or info.get('error')}\n")
        o = data["oracle"]
        if o.get("error"):
            out(f"Oracle Support: {o['error']}\n")
        for k, title in (("weblogic", "WebLogic 14.1.2"), ("tuxedo", "Tuxedo 22.1"), ("dbclient", "Database 19c")):
            v = o.get(k) or {}
            if v.get("stamp"):
                out(f"{title}: PSU 14.1.2.0.{v['stamp']} (patch {v.get('spb_patch') or v['psu_patch']})\n")
            elif v.get("rp"):
                out(f"{title}: RP{v['rp']:03d} (patch {v['patch']})\n")
            elif v.get("ru"):
                out(f"{title}: RU 19.{v['ru']} (patch {v['patch']})\n")
        return 0, data
    if op in ("discover", "hostkey.trust"):
        return discovery.run(op, c, ctx, out)
    if op == "patch.download":
        return download(c, ctx, out)
    if op == "patch.stage":
        return stage(c, ctx, out)
    if op == "host.idle":
        left = processes_running(ctx, c["t"])
        if left:
            out("PeopleSoft processes are still running, so nothing will be patched on this server:\n  "
                + "\n  ".join(left[:10]) + "\n")
            return 1, {"running": left[:20]}
        out("No WebLogic or Tuxedo processes are running.\n")
        return 0, {"running": []}
    if op == "patch.apply":
        return apply(c, ctx, out)
    if op == "os.check":
        return os_check(c, ctx, out)
    if op == "os.download":
        return os_download(c, ctx, out)
    if op == "os.update":
        return os_update(c, ctx, out)
    if op == "host.reboot":
        return host_reboot(c, ctx, out)
    if op.startswith("access."):
        return access(c, ctx, out)
    raise OperationError("unhandled operation")


def download(c, ctx, out):
    files, mos, code = {}, None, 0
    for patch, platform, filt in c["keys"]:
        key = f"{patch}|{platform}|{filt}"
        try:
            if platform == "java":
                got = oracle.download_jdk(ctx.config_path, ctx.cache_dir, patch, out)
            else:
                got, mos = oracle.download_patch(ctx.config_path, ctx.cache_dir, patch, platform, filt, out, mos)
            files[key] = [{"name": p.name, "size": p.stat().st_size} for p in got]
        except Exception as e:
            out(f"Error with {key.rstrip('|')}: {e}\n")
            code = 1
    return code, {"files": files}


def prepare_stage_root(ctx, t, ssh_user, root, out):
    """Make sure the software owner can write to the staging folder; if not, create it with sudo as the SSH user and
    give it to the owner, readable by everyone. Only ever touches the staging folder itself."""
    owner = t["os_user"] or ssh_user
    probe = as_owner(t["os_user"], ssh_user, f"mkdir -p {q(root)} 2>&1 && test -w {q(root)} && echo PSOK")
    code, text = ctx.sh(t, probe, timeout=60)
    if "PSOK" in text:
        return
    if root in PROTECTED_DIRS or root.count("/") < 3:
        raise RuntimeError(f"{owner} can't write to {root}, and it's too general a folder to change. Pick a "
                           "dedicated staging folder such as /u01/app/oracle/staging/cpu.")
    out(f"    {owner} can't write to {root}; creating it with sudo and giving it to {owner}\n")
    fix = (f"sudo -n mkdir -p {q(root)} && sudo -n chown -R {q(owner)}:\"$(id -gn {q(owner)})\" {q(root)} && "
           f"sudo -n chmod 755 {q(root)} && sudo -n find {q(root)} -type d -exec chmod 755 {{}} + && "
           f"sudo -n find {q(root)} -type f -exec chmod 644 {{}} + && echo PSFIXED")
    code, text = ctx.sh(t, fix, timeout=120)
    if "PSFIXED" not in text:
        raise RuntimeError(f"{owner} can't write to {root}, and sudo as {ssh_user} didn't work either "
                           f"({text.strip()[-200:] or 'no output'}). On the server run: sudo mkdir -p {root} && "
                           f"sudo chown -R {owner}: {root} && sudo chmod 755 {root}")
    code, text = ctx.sh(t, probe, timeout=60)
    if "PSOK" not in text:
        raise RuntimeError(f"Created {root}, but {owner} still can't write to it: {text.strip()[-200:]}")


def stage_file(ctx, t, ssh_user, local, stage_dir, out):
    name, size = local.name, local.stat().st_size
    digest = oracle.sha256_file(local)
    dest = f"{stage_dir}/{name}"
    code, text = ctx.sh(t, as_owner(t["os_user"], ssh_user, f"mkdir -p {q(stage_dir)} && "
                                    f"(sha256sum {q(dest)} 2>/dev/null || true) && df -Pk {q(stage_dir)} | tail -1"))
    if code != 0:
        raise RuntimeError(f"Couldn't create {stage_dir} as {t['os_user'] or ssh_user}: {text.strip()[-300:]}")
    if digest in text:
        out(f"    {name}: already staged (checksum matches)\n")
        return
    m = re.search(r"\s(\d+)\s+\d+%\s", text)
    if m and int(m.group(1)) * 1024 < size + 50 * 1048576:
        raise RuntimeError(f"Not enough space in {stage_dir}: {int(m.group(1)) // 1024} MB free, "
                           f"{size // 1048576} MB needed.")
    tmp = f"{dest}.part"
    code, text = ctx.sh(t, as_owner(t["os_user"], ssh_user, f"cat > {q(tmp)} && mv -f {q(tmp)} {q(dest)} && "
                                    f"sha256sum {q(dest)}"), timeout=3600, stdin_path=str(local))
    if code != 0 or digest not in text:
        raise RuntimeError(f"Copy of {name} failed or its checksum didn't match: {text.strip()[-300:]}")
    out(f"    {name}: staged and verified (sha256 {digest[:12]}...)\n")


def stage(c, ctx, out):
    t, ssh_user = c["t"], ctx.runner.user
    staged = {}
    prepare_stage_root(ctx, t, ssh_user, c["root"], out)
    for it in c["items"]:
        patch, platform, filt = it["key"]
        local = oracle.cached_files(ctx.cache_dir, oracle.cache_folder(patch, platform), filt)
        if not local:
            raise RuntimeError(f"{patch} isn't in the connector's cache. Download it first.")
        stage_dir = f"{c['root']}/{it['label']}"
        out(f"  {it['label']} -> {stage_dir}\n")
        for f in local:
            stage_file(ctx, t, ssh_user, f, stage_dir, out)
        staged["|".join(it["key"])] = {"dir": stage_dir, "files": [f.name for f in local]}
    return 0, {"staged": staged}


def processes_running(ctx, t):
    owner = t["os_user"] or ctx.runner.user
    # bracketed first letters stop the pattern matching this command's own process line
    cmd = as_owner(t["os_user"], ctx.runner.user, "ps -u " + q(owner) + " -o pid=,args= | grep -E "
                   "'[w]eblogic[.]Server|[B]BL -|[P]SAPPSRV|[P]SPRCSRV|[P]SMSTPRC|[P]SDSTSRV' || true")
    code, text = ctx.sh(t, cmd, timeout=60)
    return [l.strip() for l in text.splitlines() if re.match(r"^\s*\d+\s", l)]


# ---------------------------------------------------------------- apply scripts (run on the server as the owner)
APPLY_COMMON = r'''
set -u
unset _JAVA_OPTIONS JDK_JAVA_OPTIONS JAVA_TOOL_OPTIONS
fail() { echo "APPLY FAILED: $*"; exit 1; }
TS=$(date +%Y%m%d%H%M%S)
backup_home() {
  local H="$1" P; P=$(dirname "$H")
  local need free; need=$(du -sk "$H" 2>/dev/null | cut -f1); free=$(df -Pk "$P" | tail -1 | awk '{print $4}')
  [ "$free" -gt $(( need / 2 + 1048576 )) ] || fail "not enough free space in $P to back up $H (${need} KB to copy, ${free} KB free)"
  BK="$P/$(basename "$H").bak.$TS.tar.gz"
  echo "Backing up $H to $BK"
  tar -czf "$BK" -C "$P" "$(basename "$H")" || fail "backup of $H failed"
  echo "Backup done ($(du -sh "$BK" | cut -f1))"
}
unpack() {
  mkdir -p "$WORK" || fail "can't create $WORK"
  for z in "$@"; do echo "Unpacking $(basename "$z")"; unzip -oq "$z" -d "$WORK" || fail "couldn't unzip $z"; done
}
'''

APPLY_JDK = r'''
JH=__JH__; TAR=__TAR__; NEWVER=__VER__
P=$(dirname "$JH"); BKD="$JH.bak.$TS"; T="$P/.pegasus_jdk_$TS"
jver() { "$1/bin/java" -version 2>&1 | grep -i -m1 ' version "'; }
echo "Current JDK: $(jver "$JH")"
[ -w "$P" ] || fail "$(id -un) can't write to $P"
mkdir -p "$T" && tar -xzf "$TAR" -C "$T" || fail "couldn't extract $TAR"
NEW=$(find "$T" -mindepth 1 -maxdepth 1 -type d | head -1)
[ -x "$NEW/bin/java" ] || fail "the tarball has no bin/java"
jver "$NEW" | grep -q "\"$NEWVER\"" || fail "the tarball is $(jver "$NEW"), expected $NEWVER"
OLDC="$JH/lib/security/cacerts"; NEWC="$NEW/lib/security/cacerts"
if [ -f "$OLDC" ] && ! cmp -s "$OLDC" "$NEWC"; then
  echo "Merging certificates from the current cacerts into the new JDK"
  "$NEW/bin/keytool" -importkeystore -noprompt -srckeystore "$OLDC" -destkeystore "$NEWC" \
     -srcstorepass changeit -deststorepass changeit >/dev/null 2>&1 \
     || echo "WARNING: couldn't merge cacerts (non-default password?). Copy custom certificates from $BKD/lib/security/cacerts by hand."
fi
mv "$JH" "$BKD" || fail "couldn't move the current JDK aside"
if ! mv "$NEW" "$JH"; then mv "$BKD" "$JH"; fail "couldn't put the new JDK in place; the old JDK was restored"; fi
rmdir "$T" 2>/dev/null
V=$(jver "$JH"); echo "New JDK: $V"
if ! echo "$V" | grep -q "\"$NEWVER\""; then rm -rf "$JH"; mv "$BKD" "$JH"; fail "the new JDK didn't verify; the old JDK was restored"; fi
echo "The previous JDK is kept at $BKD"
echo "APPLY OK"
'''

APPLY_WEBLOGIC = r'''
W=__W__; JH=__JH__; WORK=__WORK__; IDS=__IDS__; OPZ=__OPATCHZIP__
export ORACLE_HOME="$W"; JDKARG=""; [ -n "$JH" ] && JDKARG="-jdk $JH"
cd "$W" || fail "can't cd to $W"
backup_home "$W"
if [ -n "$OPZ" ]; then
  NEWV=$(unzip -p "$OPZ" OPatch/version.txt 2>/dev/null | grep -o '[0-9][0-9.]*' | tail -1)
  CURV=$(grep -o '[0-9][0-9.]*' "$W/OPatch/version.txt" 2>/dev/null | tail -1)
  echo "OPatch in this home: ${CURV:-unknown}; downloaded OPatch: ${NEWV:-unknown}"
  if [ -n "$NEWV" ] && [ "$CURV" != "$NEWV" ] && [ "$(printf '%s\n%s\n' "$CURV" "$NEWV" | sort -V | tail -1)" = "$NEWV" ]; then
    echo "Upgrading OPatch to $NEWV (previous OPatch kept as OPatch.bak.$TS)"
    mv "$W/OPatch" "$W/OPatch.bak.$TS" || fail "couldn't move the old OPatch aside"
    if ! unzip -oq "$OPZ" -d "$W"; then rm -rf "$W/OPatch"; mv "$W/OPatch.bak.$TS" "$W/OPatch"; fail "OPatch upgrade failed; the old OPatch was restored"; fi
    "$W/OPatch/opatch" version || { rm -rf "$W/OPatch"; mv "$W/OPatch.bak.$TS" "$W/OPatch"; fail "new OPatch doesn't run; the old OPatch was restored"; }
  fi
fi
unpack __FILES__
SPB=$(find "$WORK" -name spbat.sh -path '*SPBAT*' | head -1)
if [ -n "$SPB" ]; then
  echo "Stack Patch Bundle found: $SPB"
  bash "$SPB" -phase precheck -oracle_home "$W" || fail "SPB precheck failed. Nothing was changed. Backup: $BK"
  bash "$SPB" -phase apply -oracle_home "$W" || fail "SPB apply failed. Check the SPBAT logs. Backup: $BK"
else
  DIRS=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -regex '.*/[0-9]+$' | sort)
  [ -n "$DIRS" ] || fail "no OPatch patch directory found in the download"
  for d in $DIRS; do
    echo "Conflict check for patch $(basename "$d")"
    "$W/OPatch/opatch" prereq CheckConflictAgainstOHWithDetail -ph "$d" -oh "$W" $JDKARG || fail "conflict check failed for $(basename "$d"). Nothing was changed. Backup: $BK"
    echo "Applying patch $(basename "$d")"
    "$W/OPatch/opatch" apply -silent "$d" -oh "$W" $JDKARG || fail "opatch apply failed for $(basename "$d"). Backup: $BK"
  done
fi
L=$("$W/OPatch/opatch" lspatches -oh "$W" $JDKARG 2>&1); echo "$L"
for id in $IDS; do echo "$L" | grep -q "^$id;" || fail "patch $id isn't listed after the apply. Backup: $BK"; done
rm -rf "$WORK"
echo "Backup kept at $BK"
echo "APPLY OK"
'''

APPLY_TUXEDO = r'''
TD=__TD__; JH=__JH__; WORK=__WORK__; LEVEL=__LEVEL__; WL=__W__
TOH=$(dirname "$TD"); OP="$TOH/OPatch/opatch"; [ -x "$OP" ] || OP="$WL/OPatch/opatch"
[ -x "$OP" ] || fail "no OPatch found in $TOH or $WL"
export ORACLE_HOME="$TOH" TUXDIR="$TD" PATH="$TD/bin:$PATH" LD_LIBRARY_PATH="$TD/lib:${LD_LIBRARY_PATH:-}"
JDKARG=""; [ -n "$JH" ] && JDKARG="-jdk $JH"
echo "Current: $("$TD/bin/tmadmin" -v 2>&1 | grep -i -m1 version)"
backup_home "$TOH"
unpack __FILES__
PT=$(find "$WORK" -maxdepth 2 -name '[0-9]*.zip' | head -1)
[ -n "$PT" ] || PT=$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -regex '.*/[0-9]+$' | head -1)
[ -n "$PT" ] || fail "no rolling patch found in the download"
echo "Applying $(basename "$PT") with $OP"
"$OP" apply -silent "$PT" -oh "$TOH" $JDKARG || fail "opatch apply failed. Backup: $BK"
NOW=$("$TD/bin/tmadmin" -v 2>&1 | grep -i -m1 version); echo "Now: $NOW"
L=$(echo "$NOW" | grep -o -i 'patch level [0-9]*' | grep -o '[0-9]*')
[ -n "$L" ] && [ "$((10#$L))" -ge "$((10#$LEVEL))" ] || fail "Tuxedo reports patch level ${L:-unknown} after the apply, expected $LEVEL. Backup: $BK"
rm -rf "$WORK"
echo "Backup kept at $BK"
echo "APPLY OK"
'''


def build_apply_script(c):
    paths = [f"{c['stage_dir']}/{f}" for f in c["files"]]
    work = f"{c['home'].rstrip('/').rsplit('/', 1)[0] or '/tmp'}/.pegasus_work_{secrets.token_hex(3)}"
    comp = c["component"]
    if comp == "jdk":
        body = APPLY_JDK.replace("__JH__", q(c["home"])).replace("__TAR__", q(paths[0])).replace("__VER__", q(c["version"]))
    elif comp in ("weblogic", "dbclient"):
        body = (APPLY_WEBLOGIC.replace("__W__", q(c["home"]))
                .replace("__JH__", q(c["jdk_home"] if comp == "weblogic" else ""))
                .replace("__WORK__", q(work)).replace("__IDS__", q(" ".join(c["ids"])))
                .replace("__FILES__", " ".join(q(p) for p in paths)).replace("__OPATCHZIP__", q(c["opatch_zip"])))
    else:
        body = (APPLY_TUXEDO.replace("__TD__", q(c["home"])).replace("__JH__", q(c["jdk_home"]))
                .replace("__WORK__", q(work)).replace("__LEVEL__", q(c["level"])).replace("__W__", q(c["wl_home"]))
                .replace("__FILES__", " ".join(q(p) for p in paths)))
    return APPLY_COMMON + body


def apply(c, ctx, out):
    """Launch the apply script detached on the server as the owner (so a dropped connection can't interrupt an opatch
    run halfway), then follow its log until it finishes."""
    t, user = c["t"], ctx.runner.user
    if not c.get("owner"):
        c = dict(c, owner=user)
    tag = f"pegasus_apply/{re.sub(r'[^A-Za-z0-9_-]', '', ctx.job_id)}-{secrets.token_hex(3)}"
    launcher = (f'D="$HOME/{tag}"; mkdir -p "$D" || exit 1\n'
                f'cat > "$D/apply.sh" <<\'PEGASUS_APPLY_EOF\'\n{c["script"]}\nPEGASUS_APPLY_EOF\n'
                f'( nohup setsid bash -c \'bash "$0/apply.sh"; echo $? > "$0/apply.rc"\' "$D" > "$D/apply.log" 2>&1 < /dev/null & )\n'
                f'echo "PSA|started|$D"\n')
    poll = (f'D="$HOME/{tag}"; echo "RC=$(cat "$D/apply.rc" 2>/dev/null)"; '
            f'echo "SIZE=$(stat -c %s "$D/apply.log" 2>/dev/null || echo 0)"; '
            f'tail -c +$((OFFSET+1)) "$D/apply.log" 2>/dev/null | head -c 200000\n')
    cmd = owner_shell(c["owner"], user)
    code, text = ctx.sh(t, cmd, stdin=launcher, timeout=120)
    m = re.search(r"PSA\|started\|(\S+)", text)
    if not m:
        out(f"Couldn't start the apply as {c['owner']}: {text.strip()[-400:]}\n")
        return 1, {"applied": False}
    out(f"Running as {c['owner']} in the background; log on the server: {m.group(1)}/apply.log\n")
    offset, deadline, failures = 0, time.time() + 4 * 3600, 0
    while time.time() < deadline:
        time.sleep(ctx.poll_interval)
        try:
            code, text = ctx.sh(t, cmd, stdin=f"OFFSET={offset}\n" + poll, timeout=120)
            failures = 0
        except Exception as e:
            failures += 1
            out(f"(lost contact with {t['host']}: {e}; the apply keeps running there, retrying)\n")
            if failures > 30:
                out("Lost contact with the server for too long. Check apply.log on the server.\n")
                return 1, {"applied": False, "unknown": True}
            continue
        i = text.find("RC=")       # skip anything the owner's login profile printed first
        lines = text[i:].split("\n", 2) if i >= 0 else ["", "", ""]
        rc = re.sub(r"\D", "", lines[0])
        chunk = lines[2] if len(lines) > 2 else ""
        if chunk:
            offset += len(chunk.encode("utf-8"))
            out(chunk if chunk.endswith("\n") else chunk + "\n")
        if rc != "" and len(chunk.encode("utf-8")) < 200000:
            ok = int(rc) == 0
            return (0 if ok else 1), {"applied": ok}
    out("The apply didn't finish within 4 hours. Check apply.log on the server.\n")
    return 1, {"applied": False, "unknown": True}


# ---------------------------------------------------------------- SSH access
KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
PUBKEY_RE = re.compile(r"^(\S+) ([A-Za-z0-9+/]+={0,3})(?: (.*))?$")


def parse_pubkey(text):
    """Validate one OpenSSH public key line. Returns (key dict, None) or (None, error)."""
    text = str(text or "").replace("\r", "").strip()
    if "PRIVATE KEY" in text:
        return None, "That's a private key. Never share it. Ask the person for their public key (the .pub file)."
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return None, "Paste the public key, or choose the .pub file."
    if lines[0].startswith("---- BEGIN SSH2 PUBLIC KEY"):
        return None, ("That's a PuTTY/SSH2-format key. Convert it to OpenSSH format first: in PuTTYgen, load the key "
                      "and copy the box 'Public key for pasting into OpenSSH authorized_keys file'.")
    if len(lines) > 1:
        joined = "".join(lines)
        if PUBKEY_RE.match(lines[0]) and not PUBKEY_RE.match(joined):
            return None, "Paste one key at a time."
        lines = [joined]
    if re.match(r"^(from|command|environment|permitopen|permitlisten|principals|tunnel|no-|restrict|cert-authority)",
                lines[0]):
        return None, "Paste the key without authorized_keys options (from=, command= and so on)."
    m = PUBKEY_RE.match(re.sub(r"\s+", " ", lines[0]))
    if not m:
        return None, "That doesn't look like an OpenSSH public key (it should start with ssh-ed25519, ssh-rsa or ecdsa-)."
    kind, b64, comment = m.group(1), m.group(2), (m.group(3) or "").strip()
    if kind not in KEY_TYPES:
        return None, f"'{kind[:40]}' isn't a supported key type. Use ssh-ed25519, ssh-rsa or ecdsa."
    try:
        blob = base64.b64decode(b64, validate=True)
        parts, i = [], 0
        while i < len(blob):
            n = int.from_bytes(blob[i:i + 4], "big")
            if len(blob[i:i + 4]) < 4 or i + 4 + n > len(blob):
                raise ValueError
            parts.append(blob[i + 4:i + 4 + n])
            i += 4 + n
        need = {"ssh-ed25519": 2, "ssh-rsa": 3, "sk-ssh-ed25519@openssh.com": 3}.get(kind, 3)
        if not parts or parts[0].decode() != kind or len(parts) < need or (kind == "ssh-ed25519" and len(parts[1]) != 32):
            raise ValueError
    except Exception:
        return None, "The key data is damaged (it may have been cut short when it was copied)."
    bits = None
    if kind == "ssh-rsa":
        try:
            bits = paramiko.RSAKey(data=blob).get_bits()
        except Exception:
            return None, "The RSA key data is damaged."
        if bits < 2048:
            return None, f"That RSA key is only {bits} bits. Ask for an ed25519 key, or RSA of at least 2048 bits."
    comment = re.sub(r"[^\x20-\x7e]", "", comment)[:120]
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    line = f"{kind} {b64}" + (f" {comment}" if comment else "")
    return {"type": kind, "bits": bits, "comment": comment, "fingerprint": fp, "body": b64, "line": line}, None


ACCESS_SCRIPT = r'''
set -u
AK="$HOME/.ssh/authorized_keys"
has_key() { [ -f "$AK" ] && awk -v b="$BODY" '{for(i=1;i<=NF;i++) if($i==b) f=1} END{exit !f}' "$AK"; }
echo "ACCOUNT:$(id -un)"
case "$MODE" in
check)
  if has_key; then echo "RESULT:PRESENT"; else echo "RESULT:ABSENT"; fi ;;
add)
  umask 077
  mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh" || { echo "RESULT:FAILED couldn't create ~/.ssh"; exit 0; }
  [ -f "$AK" ] || touch "$AK"
  chmod 600 "$AK"
  if has_key; then echo "RESULT:EXISTS"; exit 0; fi
  cp -p "$AK" "$AK.bak.$(date +%Y%m%d_%H%M%S)"
  [ -s "$AK" ] && [ -n "$(tail -c1 "$AK")" ] && echo >> "$AK"
  printf '%s\n' "$KEY" >> "$AK"
  command -v restorecon >/dev/null 2>&1 && restorecon -R "$HOME/.ssh" 2>/dev/null
  if has_key; then echo "RESULT:ADDED"; else echo "RESULT:FAILED the key isn't in the file after writing it"; fi ;;
remove)
  if ! has_key; then echo "RESULT:NOT_PRESENT"; exit 0; fi
  cp -p "$AK" "$AK.bak.$(date +%Y%m%d_%H%M%S)"
  awk -v b="$BODY" '{k=1; for(i=1;i<=NF;i++) if($i==b) k=0} k' "$AK" > "$AK.pegasus.tmp" && cat "$AK.pegasus.tmp" > "$AK"
  rm -f "$AK.pegasus.tmp"
  if has_key; then echo "RESULT:FAILED the key is still in the file"; else echo "RESULT:REMOVED"; fi ;;
esac
'''


def access(c, ctx, out):
    t, user, key, account = c["t"], ctx.runner.user, c["key"], c["account"]
    script = f"MODE={q(c['mode'])}\nKEY={q(key['line'])}\nBODY={q(key['body'])}\n" + ACCESS_SCRIPT
    cmd = f"sudo -n -iu {q(account)} bash -s" if account and account != user else "bash -s"
    code, text = ctx.sh(t, cmd, stdin=script, timeout=60)
    m = re.findall(r"RESULT:([A-Z_]+)(.*)", text)
    acct = (re.findall(r"ACCOUNT:(\S+)", text) or [account or user])[-1]
    if not m:
        hint = ""
        if "sudo" in text and ("password" in text or "not allowed" in text or "a terminal" in text):
            hint = f" (needs a passwordless sudo rule: {user} ALL=({account}) NOPASSWD: ALL)"
        out(f"{t['host']}: couldn't run: {(text.strip().splitlines() or ['no output'])[-1][:200]}{hint}\n")
        return 1, {"result": "ERROR", "account": acct}
    result, detail = m[-1][0], m[-1][1].strip()
    out(f"{t['host']} ({acct}): {result.replace('_', ' ').lower()}{(': ' + detail) if detail else ''}\n")
    return (1 if result == "FAILED" else 0), {"result": result, "account": acct, "fingerprint": key["fingerprint"]}


# ---------------------------------------------------------------- Linux OS updates (yum update, with sudo)
# The same command the team runs by hand: yum update (on Oracle Linux 8 and 9, yum is dnf under its old name)
OS_FIND_PM = 'PM=$(command -v yum); [ -n "$PM" ] || { echo "OS|error|yum is not installed"; exit 0; }\n'
OS_REBOOT_CHECK = r"""
reboot_needed() {
  if command -v needs-restarting >/dev/null 2>&1; then
    sudo -n needs-restarting -r >/dev/null 2>&1 && return 1 || return 0
  fi
  local NEWK; NEWK=$(rpm -q --last kernel kernel-uek kernel-core 2>/dev/null | head -1 | awk '{print $1}' | sed -E 's/^kernel(-uek|-core)?-//')
  [ -n "$NEWK" ] && [ "$NEWK" != "$(uname -r)" ]
}
"""
OS_CHECK_SCRIPT = OS_FIND_PM + OS_REBOOT_CHECK + r"""
. /etc/os-release 2>/dev/null; echo "OS|name|${PRETTY_NAME:-unknown}"
echo "OS|kernel|$(uname -r)"
echo "OS|pm|$(basename "$PM")"
OUT=$(sudo -n "$PM" -q check-update 2>&1); RC=$?
echo "OS|rc|$RC"
if [ "$RC" = 1 ]; then echo "$OUT" | grep -v '^\s*$' | tail -3 | sed 's/^/OS|err|/'; fi
echo "$OUT" | awk 'NF==3 && $1 ~ /\./ && $2 ~ /[0-9]/ {print "OS|pkg|"$1"|"$2}'
sudo -n "$PM" -q updateinfo list --security 2>/dev/null | awk 'NF>=3 {print "OS|sec|"$1"|"$2}'
if reboot_needed; then echo "OS|reboot|yes"; else echo "OS|reboot|no"; fi
"""
OS_UPDATE_SCRIPT = "set -u\n" + OS_FIND_PM + OS_REBOOT_CHECK + r"""
echo "Running: sudo yum -y update"
sudo -n "$PM" -y update || { echo "OS UPDATE FAILED: yum update returned an error (see above)"; exit 1; }
echo "Updates installed."
if reboot_needed; then echo "PEGASUS_REBOOT|yes"; echo "Linux reports a reboot is needed for these updates to take effect."
else echo "PEGASUS_REBOOT|no"; echo "No reboot needed."; fi
"""


def parse_os_check(text):
    """The OS| lines os.check prints, as the data the control plane stores with a server's levels."""
    d = {"name": "", "kernel": "", "pm": "", "updates": 0, "packages": [], "kernel_update": False,
         "security": {"advisories": 0, "critical": 0, "important": 0, "moderate": 0, "low": 0},
         "reboot_pending": False, "error": ""}
    seen_adv, errs = set(), []
    for line in (text or "").splitlines():
        p = line.strip().split("|")
        if p[0] != "OS" or len(p) < 3:
            continue
        k = p[1]
        if k in ("name", "kernel", "pm"):
            d[k] = p[2][:120]
        elif k == "rc" and p[2] not in ("0", "100"):
            d["error"] = "the package manager couldn't check for updates"
        elif k == "err":
            errs.append(p[2][:200])
        elif k == "error":
            d["error"] = p[2][:200]
        elif k == "pkg" and len(p) > 3:
            d["updates"] += 1
            if len(d["packages"]) < 400:
                d["packages"].append(f"{p[2][:80]} {p[3][:60]}")
            if re.match(r"^kernel(-uek|-core)?\.", p[2]):
                d["kernel_update"] = True
        elif k == "sec" and len(p) > 3 and p[2] not in seen_adv:
            seen_adv.add(p[2])
            d["security"]["advisories"] += 1
            sev = p[3].split("/")[0].lower()
            if sev in d["security"]:
                d["security"][sev] += 1
        elif k == "reboot":
            d["reboot_pending"] = p[2] == "yes"
    if d["error"] and errs:
        d["error"] += ": " + " / ".join(errs)
        if any("password is required" in e or "a terminal is required" in e for e in errs):
            d["error"] = ("the SSH user can't run yum with sudo without a password. Give it passwordless sudo "
                          "for yum, needs-restarting and systemctl reboot.")
    return d


def os_check(c, ctx, out):
    code, text = ctx.sh(c["t"], "bash -s", stdin=OS_CHECK_SCRIPT, timeout=600)
    d = parse_os_check(text)
    if d["error"]:
        out(f"Couldn't check OS updates on {c['t']['host']}: {d['error']}\n")
        return 1, {"os": d}
    sec = d["security"]
    out(f"{c['t']['host']}: {d['name']}, kernel {d['kernel']}: {d['updates']} update(s) available"
        + (f", {sec['advisories']} security advisories" if sec["advisories"] else "")
        + ("; includes a new kernel" if d["kernel_update"] else "")
        + ("; a reboot is already pending" if d["reboot_pending"] else "") + "\n")
    return 0, {"os": d}


def os_download(c, ctx, out):
    script = OS_FIND_PM + 'echo "Downloading updates with $(basename "$PM") (not installing)"\n' \
                          'sudo -n "$PM" -y -q update --downloadonly && echo "PEGASUS_DOWNLOADED" ' \
                          '|| echo "OS DOWNLOAD FAILED"\n'
    code, text = ctx.sh(c["t"], "bash -s", stdin=script, timeout=3600)
    out(text if text.endswith("\n") else text + "\n")
    ok = "PEGASUS_DOWNLOADED" in text
    return (0 if ok else 1), {"downloaded": ok}


def os_update(c, ctx, out):
    """Install every available update, detached on the server like a patch apply (a dropped connection can't stop
    yum halfway), and report whether Linux needs a reboot."""
    seen = []

    def keep(text):
        seen.append(text)
        out(text)
    code, data = apply({"t": c["t"], "owner": ctx.runner.user, "script": OS_UPDATE_SCRIPT}, ctx, keep)
    log = "".join(seen)
    reboot = "PEGASUS_REBOOT|yes" in log
    return code, {"updated": code == 0, "reboot_needed": reboot}


BOOT_ID = "cat /proc/sys/kernel/random/boot_id"


def host_reboot(c, ctx, out, wait_minutes=20):
    """Reboot only if Linux says it's needed (or always, if asked), then wait until the server answers again with a
    new boot id."""
    t = c["t"]
    code, before = ctx.sh(t, "bash -s", stdin=OS_REBOOT_CHECK + f"{BOOT_ID}\nif reboot_needed; then echo 'NEED|yes'; "
                                                               "else echo 'NEED|no'; fi\n", timeout=120)
    boot = (re.findall(r"^[0-9a-f-]{36}$", before, re.M) or [""])[0]
    if c["if_needed"] and "NEED|yes" not in before:
        out(f"{t['host']}: no reboot needed.\n")
        return 0, {"rebooted": False}
    if not boot:
        out(f"{t['host']}: couldn't read the boot id, so the reboot can't be confirmed; not rebooting.\n")
        return 1, {"rebooted": False}
    out(f"{t['host']}: rebooting.\n")
    ctx.sh(t, "sudo -n sh -c 'nohup sh -c \"sleep 3; systemctl reboot || /sbin/shutdown -r now\" >/dev/null 2>&1 &'; "
              "echo PEGASUS_REBOOT_SENT", timeout=60)
    deadline = time.time() + wait_minutes * 60
    time.sleep(min(30, ctx.poll_interval * 6))
    while time.time() < deadline:
        try:
            code, text = ctx.sh(t, BOOT_ID, timeout=30)
            now = (re.findall(r"^[0-9a-f-]{36}$", text, re.M) or [""])[0]
            if code == 0 and now and now != boot:
                out(f"{t['host']}: back up after the reboot.\n")
                return 0, {"rebooted": True}
        except Exception:
            pass
        time.sleep(max(ctx.poll_interval, 0.05) * 3)          # every 15 s with the usual 5 s poll interval
    out(f"{t['host']} didn't come back within {wait_minutes} minutes of the reboot. Check it in the OCI Console.\n")
    return 1, {"rebooted": "unknown"}
