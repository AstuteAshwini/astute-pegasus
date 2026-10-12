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
W=""
for c in "__WLH__" "$BEA_HOME" "$ORACLE_HOME" "$(dirname "$PS_HOME" 2>/dev/null)/bea"; do
  if [ -n "$c" ] && [ -x "$c/OPatch/opatch" ] && [ -d "$c/wlserver" ]; then W="$c"; break; fi
done
if [ -n "$W" ]; then
  echo "PL|wlver|$(grep -o 'name="WebLogic Server" version="[^"]*"' "$W/inventory/registry.xml" 2>/dev/null | head -1 | sed 's/.*version="//; s/"$//')|$W"
  export ORACLE_HOME="$W"
  out=$(cd "$W" && "$W/OPatch/opatch" lspatches -oh "$W" 2>&1)
  printf '%s\n' "$out" | grep -E '^[0-9]+;' | while IFS=';' read -r id desc; do echo "PL|wlpatch|$id|$desc"; done
fi
true
'''

# operation name -> (needs a domain action?, read-only?)
OPERATIONS = {
    "ping": "Connect and report host name, user and uptime",
    "domain.status": "psadmin status for one domain",
    "domain.start": "psadmin start/boot for one domain",
    "domain.stop": "psadmin stop/shutdown for one domain",
    "levels": "Read PeopleTools, JDK, Tuxedo and WebLogic levels",
}
READ_ONLY_OPERATIONS = {"ping", "domain.status", "levels"}


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


def build(op, params, ssh_user):
    """(command, stdin) for an operation. Raises OperationError for anything not allowed."""
    if op not in OPERATIONS:
        raise OperationError(f"'{op[:40]}' isn't an operation this connector performs")
    t = check_target(params.get("target"))
    if op == "ping":
        return "hostname; id -un; uptime", None
    if op.startswith("domain."):
        action = op.split(".", 1)[1]
        if not t["role"] or not t["domain"]:
            raise OperationError("a domain operation needs the server's role and domain")
        if not SAFE_NAME.match(t["domain"]):
            raise OperationError("domain name has unexpected characters")
        return run_as(t, ssh_user, COMMANDS[t["role"]][action].format(d=shlex.quote(t["domain"]))), None
    if op == "levels":
        script = LEVELS_SCRIPT.replace("__JH__", t["java_home"]).replace("__WLH__", t["weblogic_home"])
        wrapper = "bash -s"
        if t["os_user"] and t["os_user"] != ssh_user:
            wrapper = f"sudo -n -iu {shlex.quote(t['os_user'])} bash -s"
        if t["env_script"]:
            script = f". {shlex.quote(t['env_script'])} >/dev/null 2>&1\n" + script
        return wrapper, script
    raise OperationError("unhandled operation")


class SSHRunner:
    """Runs a command on a server over SSH with the connector's own key (which never leaves this machine)."""

    def __init__(self, user, key_path, passphrase=None, strict_host_keys=True, known_hosts=None):
        self.user, self.key_path, self.passphrase = user, key_path, passphrase
        self.strict, self.known_hosts = strict_host_keys, known_hosts

    def run(self, target, command, stdin=None, on_output=None, timeout=900):
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
