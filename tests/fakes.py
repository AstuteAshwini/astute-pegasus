"""Simulated PeopleSoft servers, standing in for SSH in tests and demos."""
import hashlib
import re


def levels_output(jdk="21.0.5", psu="250705"):
    return (f"PL|pt|8.62.12\nPL|jdk|{jdk}|/u01/pt/jdk\nPL|owner|/u01/pt/jdk|psadm1\n"
            "PL|wlver|14.1.2.0.0|/u01/pt/bea\nPL|owner|/u01/pt/bea|psadm1\n"
            f"PL|wlpatch|37000001|WLS PATCH SET UPDATE 14.1.2.0.{psu}\n")


class FakeServers:
    """Answers psadmin, the levels script, staging copies, the apply launcher and poll, the process check and the
    authorized_keys script, keeping a little state so tests can see the effect."""

    def __init__(self):
        self.user = "opc"
        self.calls = []
        self.state = {}
        self.files = {}          # (host, path) -> sha256
        self.applied = set()     # (host, component) once an apply finished
        self.pending = {}        # host -> component being applied
        self.fail_apply = False
        self.running = []        # process lines host.idle should report
        self.keys = {}           # (host, account) -> set of key bodies
        self.trusted = {"10.0.1.11", "10.0.1.21", "10.0.9.21"}   # host keys already in known_hosts
        self.host_fp = "SHA256:" + "A" * 43

    def run(self, target, command, stdin=None, on_output=None, timeout=900, stdin_path=None):
        self.calls.append((target["host"], command))
        out, code, host = "", 0, target["host"]
        stdin = stdin or ""
        if "hostname" in command and "uptime" in command:
            out = f"{host}\nopc\n 10:00 up 3 days\n"
        elif "sstatus" in command or "-p status" in command or "-w status" in command:
            up = self.state.get(target["domain"], True)
            out = ("BBL  ( IDLE )\nPSAPPSRV ( IDLE )\n" if target["role"] == "app" else "started\n") if up else \
                "is not started\n"
        elif " boot " in command or "-p start" in command or "-w start" in command:
            self.state[target["domain"]] = True
            out = "started\n"
        elif "shutdown" in command or "-p stop" in command:
            self.state[target["domain"]] = False
            out = "stopped\n"
        elif "test -w" in command:
            out = "PSOK\n"
        elif "cat >" in command and stdin_path:
            dest = re.search(r"mv -f \S+ (\S+) &&", command).group(1).strip("'")
            with open(stdin_path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            self.files[(host, dest)] = digest
            out = f"{digest}  {dest}\n"
        elif "sha256sum" in command and "df -Pk" in command:
            out = "".join(f"{d}  {p}\n" for (h, p), d in self.files.items() if h == host)
            out += "/dev/sda1 100000000 1000 99999000 1% /u01\n"
        elif "ps -u" in command:
            out = "".join(f"{l}\n" for l in self.running)
        elif command.startswith("INNER="):
            out = ("PSH|fsdev01\nPSN|running processes owned by: psadm2\n"
                   "PSD|psadm2|env|/u01/pt/ps_home8.62.12|/u01/cfg|/u01/pt/jdk|\n"
                   "PSD|psadm2|web|peoplesoft||psadm2|yes|/u01/cfg/webserv/peoplesoft\n"
                   "PSD|psadm2|app|FSDEV||psadm2|yes|/u01/cfg/appserv/FSDEV\n"
                   "PSD|psadm2|prcs|PRCSDOM||psadm2|yes|/u01/cfg/appserv/prcs/PRCSDOM\n"
                   "PSD|psadm2|app|FSCOPY||psadm2|no|/u01/cfg/appserv/FSCOPY\n")
        elif "MODE=" in stdin:
            out = self.access(host, command, stdin)
        elif "PSA|started" in stdin:
            out = "PSA|started|/home/psadm1/pegasus_apply/x\n"
            self.pending[host] = "jdk" if "NEWVER=" in stdin else "weblogic" if "SPB=" in stdin else "other"
        elif "OFFSET=" in stdin:
            comp = self.pending.pop(host, None)
            if self.fail_apply:
                out = "RC=1\nSIZE=40\nAPPLY FAILED: opatch apply failed\n"
            else:
                self.applied.add((host, comp))
                out = "RC=0\nSIZE=40\nApplying patch\nAPPLY OK\n"
        elif command.endswith("bash -l -s") and "PL|" in stdin:
            out = levels_output("21.0.8" if (host, "jdk") in self.applied else "21.0.5",
                                "251015" if (host, "weblogic") in self.applied else "250705")
        else:
            out, code = f"unexpected command: {command[:80]}\n", 1
        if on_output:
            on_output(out)
        return code

    def host_key_status(self, target):
        state = "known" if target["address"] in self.trusted else "unknown"
        return {"state": state, "key_type": "ssh-ed25519", "fingerprint": self.host_fp}

    def trust_host_key(self, target, fingerprint):
        if fingerprint != self.host_fp:
            raise RuntimeError("The server's host key isn't the one you approved.")
        self.trusted.add(target["address"])

    def access(self, host, command, stdin):
        m = re.search(r"sudo -n -iu (\S+)", command)
        account = m.group(1).strip("'") if m else self.user
        mode = re.search(r"^MODE=(\S+)", stdin, re.M).group(1).strip("'")
        body = re.search(r"^BODY=(\S+)", stdin, re.M).group(1).strip("'")
        keys = self.keys.setdefault((host, account), set())
        res = {"check": "PRESENT" if body in keys else "ABSENT",
               "add": "EXISTS" if body in keys else "ADDED",
               "remove": "REMOVED" if body in keys else "NOT_PRESENT"}[mode]
        if mode == "add":
            keys.add(body)
        if mode == "remove":
            keys.discard(body)
        return f"ACCOUNT:{account}\nRESULT:{res}\n"
