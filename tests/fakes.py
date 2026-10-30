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
        self.os_updates = False   # yum check-update finds updates (off unless a test turns it on)
        self.os_kernel = True     # the available OS updates include a new kernel (so a reboot is needed)
        self.boot = {}            # host -> boot id; changes when the host reboots
        self.reboot_needed = set()
        self.os_downloaded = set()
        self.free_kb = {}          # mount -> free KB that df reports (default: plenty)
        self.home_kb = 3000000     # what du reports for a home

    def run(self, target, command, stdin=None, on_output=None, timeout=900, stdin_path=None):
        self.calls.append((target["host"], command))
        out, code, host = "", 0, target["host"]
        stdin = stdin or ""
        if "PEGASUS_REBOOT_SENT" in command:                         # host.reboot (checked first: it says "shutdown")
            self.boot[host] = "22222222-2222-2222-2222-" + "2" * 12
            self.reboot_needed.discard(host)
            self.rebooted = getattr(self, "rebooted", []) + [host]
            out = "PEGASUS_REBOOT_SENT\n"
        elif "hostname" in command and "uptime" in command:
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
        elif "SPACECHK" in stdin:                                    # space.check
            m = re.search(r"for d in (.*?); do \[", stdin)
            out = "SPACECHK\n" + "".join(f"DU|{d}|{self.home_kb}\n" for d in re.findall(r"'?([^' ]+)'?", m.group(1))
                                         if d.startswith("/"))
            out += "ST|104857600\n"
            m = re.search(r"for d in (.*?); do x=", stdin)
            for d in re.findall(r"'?([^' ]+)'?", m.group(1)):
                mount = "/" if d in ("/tmp", "/usr", "/var/cache", "/boot") else "/u01"
                out += f"DF|{d}|{mount}|{self.free_kb.get(mount, 99999000)}\n"
        elif "STAGECHK" in command:                                  # free space before staging
            out = f"STAGECHK\n/dev/sda1 100000000 1000 {self.free_kb.get('/u01', 99999000)} 1% /u01\n"
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
        elif "CC|" in stdin:
            if self.state.get(target["domain"], True):
                out, code = f"CC|error|the {target['role']} domain {target['domain']} still has processes running\n", 4
            else:
                self.cleared = getattr(self, "cleared", []) + [(host, target["role"], target["domain"])]
                out = f"CC|cleared|/u01/cfg/{target['role']}/{target['domain']}/CACHE|120|35M\n"
        elif "OS|name" in stdin:                                     # os.check
            out = "OS|name|Oracle Linux Server 8.10\nOS|kernel|5.15.0-200.el8uek.x86_64\nOS|pm|yum\n"
            if (host, "os") in self.applied or not self.os_updates:
                out += "OS|rc|0\n"
            else:
                out += ("OS|rc|100\nOS|pkg|openssl.x86_64|1:1.1.1k-14.el8_10\nOS|pkg|glibc.x86_64|2.28-251.0.3.el8\n"
                        + ("OS|pkg|kernel-uek.x86_64|5.15.0-210.el8uek\n" if self.os_kernel else "")
                        + "OS|sec|ELSA-2026-7001|Important/Sec.\nOS|sec|ELSA-2026-7002|Critical/Sec.\n")
            out += f"OS|reboot|{'yes' if host in self.reboot_needed else 'no'}\n"
        elif "--assumeno" in stdin:                                  # space.check: what yum says the updates need
            root = self.free_kb.get("/", 99999000)
            out = ("OSZ|Total download size: 312 M\nOSZ|Installed size: 1.1 G\n"
                   f"DF|/var/cache/dnf|/|{root}\nDF|/usr|/|{root}\nDF|/boot|/boot|{self.free_kb.get('/boot', 800000)}\n"
                   "BOOTK|120000\nCACHE|/var/cache/dnf\n")
        elif "--downloadonly" in stdin:                              # os.download
            self.os_downloaded.add(host)
            out = "Downloading updates with yum (not installing)\nPEGASUS_DOWNLOADED\n"
        elif "'NEED|yes'" in stdin:                                  # host.reboot: is one needed?
            out = self.boot.setdefault(host, "11111111-1111-1111-1111-" + "1" * 12) + "\n"
            out += "NEED|yes\n" if host in self.reboot_needed else "NEED|no\n"
        elif command == "cat /proc/sys/kernel/random/boot_id":
            out = self.boot.setdefault(host, "11111111-1111-1111-1111-" + "1" * 12) + "\n"
        elif "MODE=" in stdin:
            out = self.access(host, command, stdin)
        elif "PSA|started" in stdin:
            out = "PSA|started|/home/psadm1/pegasus_apply/x\n"
            self.pending[host] = ("os" if "PEGASUS_REBOOT" in stdin else "jdk" if "NEWVER=" in stdin
                                  else "weblogic" if "SPB=" in stdin else "other")
        elif "OFFSET=" in stdin:
            comp = self.pending.pop(host, None)
            if self.fail_apply:
                out = "RC=1\nSIZE=40\nAPPLY FAILED: opatch apply failed\n"
            elif comp == "os":
                self.applied.add((host, "os"))
                if self.os_kernel:
                    self.reboot_needed.add(host)
                out = ("RC=0\nSIZE=40\nRunning: sudo yum -y update\nUpdates installed.\n"
                       + ("PEGASUS_REBOOT|yes\n" if self.os_kernel else "PEGASUS_REBOOT|no\n"))
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
