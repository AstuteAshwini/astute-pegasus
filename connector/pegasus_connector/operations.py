"""The only things a connector will ever do on a client's servers.

Every job names one of the operations below with parameters that are validated here, on the client's side, before
anything runs. Nothing from the control plane is ever executed as a shell command: commands are built locally from
fixed templates, with every value checked and shell-quoted. This is the same model as the self-hosted Pegasus.
"""
import re
import shlex
import time

import paramiko

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./~\-]{1,255}$")
SAFE_ABS_PATH = re.compile(r"^/[A-Za-z0-9_./\-]{1,250}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")
CONNECT_TIMEOUT = 20

# psadmin per server role. {d} is the domain name (validated, shell-quoted).
COMMANDS = {
    "app":  {"start": "psadmin -c boot -d {d}",  "stop": "psadmin -c shutdown -d {d}", "status": "psadmin -c sstatus -d {d}"},
    "prcs": {"start": "psadmin -p start -d {d}", "stop": "psadmin -p stop -d {d}",     "status": "psadmin -p status -d {d}"},
    "web":  {"start": "psadmin -w start -d {d}", "stop": "psadmin -w shutdown -d {d}", "status": "psadmin -w status -d {d}"},
}

LEVELS_SCRIPT = r'''
JH=""
for c in "$JAVA_HOME" "__JH__" "$(dirname "$PS_HOME" 2>/dev/null)/jdk" /u01/app/oracle/product/pt/jdk \
         "$(dirname "$(readlink -f "$(command -v java 2>/dev/null)" 2>/dev/null)" 2>/dev/null)/.."; do
  if [ -n "$c" ] && [ -x "$c/bin/java" ]; then JH="$(cd "$c" && pwd)"; break; fi
done
echo "PL|pt|$(psadmin -v 2>/dev/null | grep -o -m1 '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)"
if [ -n "$JH" ]; then
  echo "PL|jdk|$("$JH/bin/java" -version 2>&1 | grep -m1 -i version | grep -o '"[^"]*"' | tr -d '"')|$JH"
else
  echo "PL|nojdk|JAVA_HOME isn't set and no JDK was found next to PS_HOME"
fi
if [ -n "$TUXDIR" ] && [ -x "$TUXDIR/bin/tmadmin" ]; then
  echo "PL|tuxedo|$("$TUXDIR/bin/tmadmin" -v 2>&1 | grep -i -m1 'version' | tr '|' ' ')|$TUXDIR"
fi
for d in "$JH" "$TUXDIR"; do [ -n "$d" ] && [ -d "$d" ] && echo "PL|owner|$d|$(stat -c %U "$d" 2>/dev/null)"; done
for C in "$(dirname "$PS_HOME" 2>/dev/null)"/oracle-client/*/ /u01/app/oracle/product/pt/oracle-client/*/; do
  C="${C%/}"; [ -x "$C/OPatch/opatch" ] || continue
  echo "PL|owner|$C|$(stat -c %U "$C" 2>/dev/null)"
  o=$(cd "$C" && ORACLE_HOME="$C" "$C/OPatch/opatch" lspatches -oh "$C" 2>&1)
  ru=$(printf '%s\n' "$o" | grep -o -m1 'Release Update : [0-9.]*' | grep -o '[0-9.]*$')
  echo "PL|dbclient|$(basename "$C")|$ru|$C"
  break
done
W=""
for c in "__WLH__" "$BEA_HOME" "$ORACLE_HOME" "$(dirname "$PS_HOME" 2>/dev/null)/bea"; do
  if [ -n "$c" ] && [ -x "$c/OPatch/opatch" ] && [ -d "$c/wlserver" ]; then W="$c"; break; fi
done
if [ -n "$W" ]; then
  echo "PL|wlver|$(grep -o 'name="WebLogic Server" version="[^"]*"' "$W/inventory/registry.xml" 2>/dev/null | head -1 | sed 's/.*version="//; s/"$//')|$W"
  echo "PL|owner|$W|$(stat -c %U "$W" 2>/dev/null)"
  export ORACLE_HOME="$W"
  unset _JAVA_OPTIONS JDK_JAVA_OPTIONS
  ok=""
  for args in "-jdk $JH" "-jre $JH" ""; do
    [ -z "$JH" ] && [ -n "$args" ] && continue
    out=$(cd "$W" && "$W/OPatch/opatch" lspatches $args -oh "$W" 2>&1)
    if printf '%s\n' "$out" | grep -qE '^[0-9]+;|OPatch succeeded'; then ok=1; break; fi
  done
  printf '%s\n' "$out" | grep -E '^[0-9]+;' | while IFS=';' read -r id desc; do echo "PL|wlpatch|$id|$desc"; done
  [ -n "$ok" ] || echo "PL|wlerr|$(printf '%s' "$out" | grep -v '^[[:space:]]*$' | tail -8 | tr '\n|' '  ')"
fi
true
'''

# Clears one domain's cache. Runs as the domain's owner, only while the domain is down, and only ever deletes inside
# that domain's own folder under PS_CFG_HOME:
#   app server / process scheduler: the CACHE folder (or the "Cache Base Directory" set in psappsrv.cfg / psprcs.cfg,
#     if that is inside the domain folder), then cleanipc
#   web server: the PIA site caches (PORTAL.war/<site>/cache*) and each WebLogic server's tmp and cache folders
CLEARCACHE_SCRIPT = r'''
fail() { echo "CC|error|$1"; exit "${2:-3}"; }
[ -n "$PS_CFG_HOME" ] || fail "PS_CFG_HOME isn't set for $(id -un)"
CFG=$(cd "$PS_CFG_HOME" 2>/dev/null && pwd -P) || fail "PS_CFG_HOME ($PS_CFG_HOME) isn't a folder"
case "$ROLE" in
  app)  D="$CFG/appserv/$DOM";      CFGFILE=psappsrv.cfg ;;
  prcs) D="$CFG/appserv/prcs/$DOM"; CFGFILE=psprcs.cfg ;;
  web)  D="$CFG/webserv/$DOM";      CFGFILE= ;;
  *)    fail "unknown role $ROLE" ;;
esac
[ -d "$D" ] || fail "$D doesn't exist"
D=$(cd "$D" && pwd -P)
if pgrep -u "$(id -un)" -f -- "$D/" >/dev/null 2>&1; then
  pgrep -a -u "$(id -un)" -f -- "$D/" | cut -c1-160 | head -5 | sed 's/^/    /'
  fail "the $ROLE domain $DOM still has processes running, so its cache wasn't touched" 4
fi
rc=0; n_dirs=0
clear_dir() {
  [ -d "$1" ] || return 0
  r=$(cd "$1" && pwd -P)
  case "$r/" in "$D/"?*) ;; *) echo "CC|skip|$1 is outside the domain folder, left alone"; return 0 ;; esac
  n=$(find "$r" -mindepth 1 | wc -l); sz=$(du -sh "$r" 2>/dev/null | cut -f1)
  if find "$r" -mindepth 1 -delete; then echo "CC|cleared|$r|$n|$sz"; n_dirs=$((n_dirs+1))
  else echo "CC|error|couldn't clear everything in $r"; rc=5; fi
}
if [ "$ROLE" = web ]; then
  for c in "$D"/applications/peoplesoft/PORTAL.war/*/cache*; do clear_dir "$c"; done
  for s in "$D"/servers/*/; do clear_dir "${s}tmp"; clear_dir "${s}cache"; done
else
  cb=$(grep -m1 -i '^[[:space:]]*Cache Base Directory[[:space:]]*=' "$D/$CFGFILE" 2>/dev/null | cut -d= -f2- | tr -d ' \r')
  case "$cb" in ""|*%*) clear_dir "$D/CACHE" ;; *) clear_dir "$cb" ;; esac
  if [ "$ROLE" = app ]; then psadmin -c cleanipc -d "$DOM" 2>&1 | tail -3; else psadmin -p cleanipc -d "$DOM" 2>&1 | tail -3; fi
fi
[ "$n_dirs" -gt 0 ] || echo "CC|nothing|no cache folders found under $D"
exit $rc
'''

OPERATIONS = {
    "ping": "Connect and report host name, user and uptime",
    "domain.status": "psadmin status for one domain",
    "domain.start": "psadmin start/boot for one domain",
    "domain.stop": "psadmin stop/shutdown for one domain",
    "domain.clearcache": "Clear a stopped domain's cache (only inside its own folder)",
    "levels": "Read PeopleTools, JDK, Tuxedo, WebLogic and Database client levels",
    "catalog": "Look up the latest JDK, WebLogic, Tuxedo and Database client patches (Oracle)",
    "patch.download": "Download patches into the connector's cache (all from Oracle Support)",
    "patch.stage": "Copy downloaded patches to a server's staging folder",
    "host.idle": "Check no WebLogic or Tuxedo processes are running",
    "patch.apply": "Back up a home and apply a staged patch as its owner",
    "access.check": "Check for a person's SSH public key in an account",
    "access.add": "Add a person's SSH public key to an account",
    "access.remove": "Remove a person's SSH public key from an account",
    "discover": "Find PeopleSoft domains on a server (read-only)",
    "hostkey.trust": "Trust a server's SSH host key after an operator compared its fingerprint",
}
# allowed when local policy is read_only: nothing here changes a server
READ_ONLY_OPERATIONS = {"ping", "domain.status", "levels", "catalog", "host.idle", "access.check", "discover"}


class OperationError(Exception):
    pass


def check_target(t):
    """Validate a server description sent by the control plane. Returns a clean copy."""
    if not isinstance(t, dict):
        raise OperationError("target must be an object")
    out = {}
    host = str(t.get("ip") or t.get("host") or "")
    if not SAFE_HOST.match(host):
        raise OperationError(f"host '{host[:60]}' has unexpected characters")
    out["address"] = host
    out["host"] = str(t.get("host") or host)
    if not SAFE_HOST.match(out["host"]):
        raise OperationError("host name has unexpected characters")
    out["role"] = str(t.get("role") or "")
    if out["role"] and out["role"] not in COMMANDS:
        raise OperationError(f"unknown role '{out['role'][:20]}'")
    for k, rx in (("os_user", SAFE_NAME), ("domain", SAFE_NAME), ("env_script", SAFE_PATH)):
        v = str(t.get(k) or "")
        if v and not rx.match(v):
            raise OperationError(f"{k} has unexpected characters")
        out[k] = v
    port = t.get("ssh_port") or 22
    try:
        port = int(port)
        assert 0 < port < 65536
    except (ValueError, AssertionError):
        raise OperationError("ssh_port must be a port number")
    out["ssh_port"] = port
    for k in ("java_home", "weblogic_home"):
        v = str(t.get(k) or "")
        if v and not SAFE_ABS_PATH.match(v):
            raise OperationError(f"{k} must be an absolute path")
        out[k] = v
    return out


def run_as(t, ssh_user, inner):
    """Wrap `inner` so it runs in the PeopleSoft owner's login shell, sourcing psconfig.sh if given."""
    if t["env_script"]:
        inner = f"cd {shlex.quote(t['env_script'].rsplit('/', 1)[0] or '.')} && . {shlex.quote(t['env_script'])} >/dev/null 2>&1; {inner}"
    if t["os_user"] and t["os_user"] != ssh_user:
        return f"sudo -n -iu {shlex.quote(t['os_user'])} bash -lc {shlex.quote(inner)}"
    return f"bash -lc {shlex.quote(inner)}"


def parse_levels(text):
    """The PL| lines the levels script prints, as a dict the control plane stores and compares."""
    r = {"pt": "", "jdk": None, "tuxedo": None, "weblogic": None, "dbclient": None}
    patches = []
    for line in (text or "").splitlines():
        p = line.strip().split("|")
        if p[0] != "PL" or len(p) < 2:
            continue
        if p[1] == "pt" and len(p) > 2:
            r["pt"] = p[2]
        elif p[1] == "jdk" and len(p) > 3 and p[2]:
            r["jdk"] = {"version": p[2], "home": p[3]}
        elif p[1] == "tuxedo" and len(p) > 3:
            v = re.search(r"Version\s+([\d.]+)", p[2])
            lvl = re.search(r"Patch Level\s+(\d+)", p[2], re.I)
            r["tuxedo"] = {"version": v.group(1) if v else "", "level": lvl.group(1) if lvl else "0",
                           "raw": p[2].strip(), "home": p[3]}
        elif p[1] == "wlver" and len(p) > 3:
            r["weblogic"] = {"version": p[2], "home": p[3], "patches": []}
        elif p[1] == "wlpatch" and len(p) > 2:
            patches.append({"id": p[2], "desc": "|".join(p[3:]).strip()})
        elif p[1] == "dbclient" and len(p) > 4:
            r["dbclient"] = {"version": p[2], "ru": p[3], "home": p[4]}
        elif p[1] == "owner" and len(p) > 3:
            r.setdefault("owners", {})[p[2]] = p[3]
        elif p[1] in ("nojdk", "wlerr") and len(p) > 2:
            r.setdefault("warnings", []).append(
                ("OPatch couldn't list WebLogic patches: " if p[1] == "wlerr" else "") + p[2].strip())
    if r["weblogic"] is not None:
        r["weblogic"]["patches"] = patches
    return r


def build(op, params, ssh_user):
    """(command, stdin) for an operation. Raises OperationError for anything not allowed."""
    if op not in OPERATIONS:
        raise OperationError(f"'{op[:40]}' isn't an operation this connector performs")
    t = check_target(params.get("target"))
    if op == "ping":
        return "hostname; id -un; uptime", None
    if op == "domain.clearcache":
        if not t["role"] or not t["domain"]:
            raise OperationError("clearing a cache needs the server's role and domain")
        script = f"ROLE={shlex.quote(t['role'])}\nDOM={shlex.quote(t['domain'])}\n" + CLEARCACHE_SCRIPT
        if t["env_script"]:
            script = f". {shlex.quote(t['env_script'])} >/dev/null 2>&1\n" + script
        wrapper = "bash -l -s"
        if t["os_user"] and t["os_user"] != ssh_user:
            wrapper = f"sudo -n -iu {shlex.quote(t['os_user'])} bash -l -s"
        return wrapper, script
    if op.startswith("domain."):
        action = op.split(".", 1)[1]
        if not t["role"] or not t["domain"]:
            raise OperationError("a domain operation needs the server's role and domain")
        if not SAFE_NAME.match(t["domain"]):
            raise OperationError("domain name has unexpected characters")
        return run_as(t, ssh_user, COMMANDS[t["role"]][action].format(d=shlex.quote(t["domain"]))), None
    if op == "levels":
        script = LEVELS_SCRIPT.replace("__JH__", t["java_home"]).replace("__WLH__", t["weblogic_home"])
        wrapper = "bash -l -s"
        if t["os_user"] and t["os_user"] != ssh_user:
            wrapper = f"sudo -n -iu {shlex.quote(t['os_user'])} bash -l -s"
        if t["env_script"]:
            script = f". {shlex.quote(t['env_script'])} >/dev/null 2>&1\n" + script
        return wrapper, script
    raise OperationError("unhandled operation")


def host_entry(address, port):
    return address if port == 22 else f"[{address}]:{port}"


def key_fingerprint(key):
    import base64
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


class SSHRunner:
    """Runs a command on a server over SSH with the connector's own key (which never leaves this machine)."""

    def __init__(self, user, key_path, passphrase=None, strict_host_keys=True, known_hosts=None):
        self.user, self.key_path, self.passphrase = user, key_path, passphrase
        self.strict, self.known_hosts = strict_host_keys, known_hosts

    def known_hosts_files(self):
        import os
        files = [os.path.expanduser("~/.ssh/known_hosts")]
        if self.known_hosts:
            files.append(self.known_hosts)
        return files

    def remote_key(self, target):
        t = paramiko.Transport((target["address"], target["ssh_port"]))
        try:
            t.banner_timeout = CONNECT_TIMEOUT
            t.start_client(timeout=CONNECT_TIMEOUT)
            return t.get_remote_server_key()
        finally:
            t.close()

    def host_key_status(self, target):
        """known / unknown / changed, with the server's key type and fingerprint."""
        import os
        key = self.remote_key(target)
        out = {"key_type": key.get_name(), "fingerprint": key_fingerprint(key)}
        if not self.strict:
            return dict(out, state="known")
        hk = paramiko.HostKeys()
        for f in self.known_hosts_files():
            if os.path.exists(f):
                try:
                    hk.load(f)
                except (OSError, paramiko.SSHException):
                    pass
        known = hk.lookup(host_entry(target["address"], target["ssh_port"]))
        if known is None or key.get_name() not in known:
            return dict(out, state="unknown")
        return dict(out, state="known" if known[key.get_name()] == key else "changed")

    def trust_host_key(self, target, fingerprint):
        """Add the server's key to ~/.ssh/known_hosts, only if it still has the fingerprint the operator approved."""
        import os
        key = self.remote_key(target)
        if key_fingerprint(key) != fingerprint:
            raise RuntimeError("The server's host key isn't the one you approved (it changed since the scan). "
                               "Scan again and compare.")
        if self.host_key_status(target)["state"] == "changed":
            raise RuntimeError("A different key is already trusted for this server. Check with its owner and "
                               "remove the old entry from known_hosts on the connector first.")
        path = os.path.expanduser("~/.ssh/known_hosts")
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        tail = b""
        if os.path.exists(path) and os.path.getsize(path):
            with open(path, "rb") as f:
                f.seek(-1, os.SEEK_END)
                tail = f.read(1)
        with open(path, "a", encoding="utf-8") as f:
            f.write(("\n" if tail and tail != b"\n" else "")
                    + f"{host_entry(target['address'], target['ssh_port'])} {key.get_name()} {key.get_base64()}\n")

    def run(self, target, command, stdin=None, on_output=None, timeout=900, stdin_path=None):
        """Run one command. stdin: text to send; stdin_path: a local file to stream (patch staging)."""
        c = paramiko.SSHClient()
        c.load_system_host_keys()
        if self.known_hosts:
            c.load_host_keys(self.known_hosts)
        c.set_missing_host_key_policy(paramiko.RejectPolicy() if self.strict else paramiko.WarningPolicy())
        try:
            c.connect(target["address"], port=target["ssh_port"], username=self.user, key_filename=self.key_path,
                      passphrase=self.passphrase or None, look_for_keys=False, allow_agent=False,
                      timeout=CONNECT_TIMEOUT, banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT)
            chan = c.get_transport().open_session()
            chan.set_combine_stderr(True)
            chan.exec_command(command)
            if stdin is not None:
                chan.sendall(stdin.encode())
                chan.shutdown_write()
            elif stdin_path:
                with open(stdin_path, "rb") as f:
                    for chunk in iter(lambda: f.read(256 * 1024), b""):
                        chan.sendall(chunk)
                chan.shutdown_write()
            deadline = time.time() + timeout
            while True:
                if chan.recv_ready():
                    data = chan.recv(65536).decode("utf-8", "replace")
                    if on_output:
                        on_output(data)
                elif chan.exit_status_ready():
                    while chan.recv_ready():
                        data = chan.recv(65536).decode("utf-8", "replace")
                        if on_output:
                            on_output(data)
                    return chan.recv_exit_status()
                elif time.time() > deadline:
                    chan.close()
                    raise TimeoutError(f"no answer after {timeout}s")
                else:
                    time.sleep(0.2)
        finally:
            c.close()
