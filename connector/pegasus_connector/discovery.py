"""Find PeopleSoft domains on a server, so it can be added to the inventory from just its IP address.

Read-only, like the self-hosted Pegasus scan: it lists the PeopleSoft owners' web, app server and process scheduler
domains (echo, globbing, grep, stat and ps only). A server the connector has never connected to is not scanned until
an operator has compared its SSH host key fingerprint and trusted it (hostkey.trust).
"""
import re
import shlex

from .operations import SAFE_NAME, OperationError, check_target

# Runs as each PeopleSoft owner (piped to the owner's login shell, so $variables expand in the right shell).
DISCOVER_INNER = r"""
echo "PSD|env|$PS_HOME|$PS_CFG_HOME|$JAVA_HOME|$(command -v psadmin 2>/dev/null)"
C="$PS_CFG_HOME"
if [ -n "$C" ]; then
  for d in "$C"/webserv/*/; do
    [ -f "${d}bin/startPIA.sh" ] || continue
    cfg=no; [ -f "${d}config/config.xml" ] && cfg=yes
    echo "PSD|web|$(basename "$d")||$(stat -c %U "$d" 2>/dev/null)|$cfg|$(cd "$d" && pwd -P)"
  done
  for d in "$C"/appserv/*/; do
    [ -f "${d}psappsrv.cfg" ] || continue
    cfg=no; [ -f "${d}PSTUXCFG" ] && cfg=yes
    echo "PSD|app|$(basename "$d")||$(stat -c %U "$d" 2>/dev/null)|$cfg|$(cd "$d" && pwd -P)"
  done
  for d in "$C"/appserv/prcs/*/; do
    [ -f "${d}psprcs.cfg" ] || continue
    cfg=no; [ -f "${d}PSTUXCFG" ] && cfg=yes
    echo "PSD|prcs|$(basename "$d")||$(stat -c %U "$d" 2>/dev/null)|$cfg|$(cd "$d" && pwd -P)"
  done
fi
true
"""

# Runs as the SSH user: finds the owners (from running processes, else psadm1-3), then runs the inner script as each.
DISCOVER_OUTER = r'''
echo "PSH|$(hostname -s)"
users="$*"
if [ -z "$users" ]; then
  users=$(ps -eo user:32,args --no-headers 2>/dev/null | grep -E "weblogic\.Server|PSAPPSRV|PSPRCSRV|PSMSTPRC|BBL -" | grep -v grep | awk '{print $1}' | grep -v "^root$" | sort -u | tr "\n" " ")
  [ -n "$users" ] && echo "PSN|running processes owned by: $users"
  [ -z "$users" ] && users="psadm2 psadm1 psadm3"
fi
me=$(id -un)
for u in $users; do
  id "$u" >/dev/null 2>&1 || continue
  if [ "$u" = "$me" ]; then
    out=$(printf "%s\n" "$INNER" | bash -l -s 2>/dev/null)
  else
    sudo -n -iu "$u" true >/dev/null 2>&1 || { echo "PSS|$u|sudo to $u was refused"; continue; }
    out=$(printf "%s\n" "$INNER" | sudo -n -iu "$u" bash -l -s 2>/dev/null)
  fi
  printf "%s\n" "$out" | grep "^PSD|" | sed "s/^PSD|/PSD|$u|/"
done
'''

FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def validate(op, step):
    t = check_target(step.get("target"))
    if op == "discover":
        users = [str(u) for u in step.get("users") or []]
        if len(users) > 5 or not all(SAFE_NAME.match(u) for u in users) or "root" in users:
            raise OperationError("OS users may use letters, digits, . _ and - only (at most 5, not root)")
        return {"t": t, "users": users}
    fp = str(step.get("fingerprint") or "")
    if not FINGERPRINT.match(fp):
        raise OperationError("that isn't an SSH host key fingerprint")
    return {"t": t, "fingerprint": fp}


def parse(text, ip, port, ssh_user):
    """Rows the inventory can take, plus notes, from the scan's PSH/PSN/PSS/PSD lines."""
    result = {"ip": ip, "port": port, "host": "", "rows": [], "notes": []}
    owners = {}
    for line in (text or "").splitlines():
        p = line.strip().split("|")
        if p[0] == "PSH" and len(p) > 1:
            result["host"] = p[1]
        elif p[0] == "PSN":
            result["notes"].append(p[1] if len(p) > 1 else "")
        elif p[0] == "PSS" and len(p) > 2:
            result["notes"].append(p[2])
        elif p[0] == "PSD" and len(p) > 2:
            u, kind = p[1], p[2]
            o = owners.setdefault(u, {"user": u, "ps_home": "", "ps_cfg_home": "", "psadmin": "",
                                      "web": [], "app": [], "prcs": []})
            if kind == "env":
                o.update(ps_home=p[3] if len(p) > 3 else "", ps_cfg_home=p[4] if len(p) > 4 else "",
                         psadmin=p[6] if len(p) > 6 else "")
            elif kind in ("web", "app", "prcs") and len(p) > 3:
                o[kind].append({"domain": p[3], "owner": p[5] if len(p) > 5 else "",
                                "configured": (p[6] if len(p) > 6 else "yes") == "yes",
                                "path": p[7] if len(p) > 7 else ""})
    host = result["host"] or ip
    seen = set()
    # A domain counts once, under the user that owns its folder (DPK installs often point several users at one
    # PS_CFG_HOME). Owners of at least one domain folder go first.
    ordered = sorted(owners.values(), key=lambda o: 0 if any(d["owner"] == o["user"]
                                                             for r in ("web", "app", "prcs") for d in o[r]) else 1)
    for o in ordered:
        for role in ("web", "app", "prcs"):
            for d in o[role]:
                ident = (role, d["path"] or f"{o['ps_cfg_home']}/{role}/{d['domain']}")
                if ident in seen or (d["owner"] and d["owner"] != o["user"] and d["owner"] in owners):
                    continue
                seen.add(ident)
                owner = d["owner"] or o["user"]
                note = [] if d["configured"] else [
                    "not configured (no " + ("config.xml" if role == "web" else "PSTUXCFG") + "); likely a copy or leftover"]
                if d["owner"] and d["owner"] not in owners:
                    note.append(f"owned by {d['owner']}, which wasn't scanned; check before adding")
                env_script = f"{o['ps_home']}/psconfig.sh" if o["ps_home"] and not o["psadmin"] else ""
                result["rows"].append({"host": host, "ip": ip, "role": role, "domain": d["domain"],
                                       "os_user": "" if owner == ssh_user else owner, "owner": owner,
                                       "env_script": env_script, "ssh_port": port, "path": d["path"],
                                       "configured": d["configured"], "use": d["configured"] and len(note) == 0,
                                       "note": "; ".join(note)})
    for o in owners.values():
        if o["ps_cfg_home"] and not o["psadmin"] and o["ps_home"]:
            result["notes"].append(f"{o['user']}: psadmin isn't on the login PATH, so env_script is set to "
                                   f"{o['ps_home']}/psconfig.sh.")
    if not result["rows"]:
        result["notes"].append("No PeopleSoft domains found. If they belong to a user other than psadm1, psadm2 or "
                               "psadm3 and aren't running, enter that user under OS users and scan again.")
    return result


def run(op, c, ctx, out):
    t, runner = c["t"], ctx.runner
    if op == "hostkey.trust":
        if not hasattr(runner, "trust_host_key"):
            raise OperationError("this connector can't save host keys")
        runner.trust_host_key(t, c["fingerprint"])
        out(f"Trusted the host key of {t['address']} ({c['fingerprint']}).\n")
        return 0, {"trusted": True, "fingerprint": c["fingerprint"]}
    status = runner.host_key_status(t) if hasattr(runner, "host_key_status") else {"state": "known"}
    if status["state"] == "unknown":
        out(f"The connector hasn't connected to {t['address']} before. Its {status['key_type']} host key fingerprint "
            f"is {status['fingerprint']}. Compare it with the server, then trust it in Pegasus.\n")
        return 0, {"ip": t["address"], "port": t["ssh_port"], "needs_trust": True, **status}
    if status["state"] == "changed":
        out(f"The host key of {t['address']} has CHANGED since it was trusted ({status['fingerprint']}). "
            "Check with the server's owner before changing known_hosts on the connector.\n")
        return 1, {"ip": t["address"], "port": t["ssh_port"], "error": "host key changed", **status}
    args = " ".join(shlex.quote(u) for u in c["users"])
    code, text = ctx.sh(t, f"INNER={shlex.quote(DISCOVER_INNER)} bash -s -- {args}", stdin=DISCOVER_OUTER, timeout=180)
    result = parse(text, t["address"], t["ssh_port"], runner.user)
    out(f"{result['host'] or t['address']}: found {len(result['rows'])} domain(s)\n")
    for r in result["rows"]:
        out(f"  {r['role']:<5} {r['domain']:<20} owner {r['owner']}{('  (' + r['note'] + ')') if r['note'] else ''}\n")
    for n in result["notes"]:
        out(f"  Note: {n}\n")
    return 0, result
