"""
PeopleSoft Admin Dashboard
--------------------------
A small self-hosted web app for administering PeopleSoft environments.

* Environments are kept in data/environments.csv (one row per server).
* Start / stop / status run psadmin on each server over SSH (Paramiko).
* Every action is written to logs/actions.log, and full output to logs/jobs/.

Run it on an admin / jump host that can already SSH to the PeopleSoft servers.
See README.md for setup.
"""
import base64
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shlex
import shutil
import threading
import time
import uuid
from pathlib import Path

import paramiko
from flask import Flask, abort, jsonify, request, send_file, send_from_directory, session

# ---------------------------------------------------------------- settings
BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("PSDASH_DATA", BASE / "data"))
LOG_DIR = Path(os.environ.get("PSDASH_LOGS", BASE / "logs"))
CSV_PATH = DATA_DIR / "environments.csv"
HOST = os.environ.get("PSDASH_HOST", "127.0.0.1")
PORT = int(os.environ.get("PSDASH_PORT", "8080"))
PASSWORD = os.environ.get("PSDASH_PASSWORD", "")
STRICT_HOST_KEYS = os.environ.get("PSDASH_STRICT_HOST_KEYS", "true").lower() != "false"
ACTION_TIMEOUT = int(os.environ.get("PSDASH_ACTION_TIMEOUT", "900"))  # seconds per server step
CONNECT_TIMEOUT = 20

COLUMNS = ["environment", "client", "tier", "host", "ip", "role", "os_user", "domain",
           "env_script", "pt_home", "java_home", "weblogic_home", "ssh_user", "ssh_key", "ssh_port"]
ENV_FIELDS = ["client", "tier", "pt_home", "java_home", "weblogic_home"]

ALIASES = {
    "env": "environment", "environment": "environment", "envname": "environment",
    "environmentname": "environment", "database": "environment", "db": "environment",
    "client": "client", "customer": "client",
    "tier": "tier", "type": "tier", "envtype": "tier", "lifecycle": "tier",
    "host": "host", "hostname": "host", "server": "host", "servername": "host",
    "ip": "ip", "ipaddress": "ip", "address": "ip",
    "role": "role", "servertype": "role", "component": "role",
    "osuser": "os_user", "user": "os_user", "adminuser": "os_user", "account": "os_user", "psuser": "os_user",
    "domain": "domain", "domainname": "domain", "psdomain": "domain",
    "envscript": "env_script", "psconfig": "env_script", "profile": "env_script", "psconfigsh": "env_script",
    "pthome": "pt_home", "pshome": "pt_home", "peopletoolshome": "pt_home", "toolshome": "pt_home",
    "javahome": "java_home", "java": "java_home", "jdk": "java_home", "jdkhome": "java_home",
    "weblogichome": "weblogic_home", "weblogic": "weblogic_home", "oraclehome": "weblogic_home",
    "sshuser": "ssh_user", "sshkey": "ssh_key", "keypath": "ssh_key", "privatekey": "ssh_key",
    "sshport": "ssh_port", "port": "ssh_port",
}

# psadmin commands per server role. {d} is the domain name (validated, shell-quoted).
COMMANDS = {
    "app":  {"start": "psadmin -c boot -d {d}",  "stop": "psadmin -c shutdown -d {d}", "status": "psadmin -c sstatus -d {d}"},
    "prcs": {"start": "psadmin -p start -d {d}", "stop": "psadmin -p stop -d {d}",     "status": "psadmin -p status -d {d}"},
    "web":  {"start": "psadmin -w start -d {d}", "stop": "psadmin -w shutdown -d {d}", "status": "psadmin -w status -d {d}"},
}
START_ORDER = ["app", "prcs", "web"]
STOP_ORDER = ["web", "prcs", "app"]
ACTIONS = ["start", "stop", "status", "restart"]

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./~\-]{1,255}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("PSDASH_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  MAX_CONTENT_LENGTH=2 * 1024 * 1024)

csv_lock = threading.Lock()
jobs = {}            # job id -> dict
jobs_lock = threading.Lock()
passphrases = {}     # session token -> key passphrase (memory only, never written to disk)


# ---------------------------------------------------------------- helpers
def now():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def is_prd(tier):
    return (tier or "").strip().lower() in ("prd", "prod", "production")


def env_key(name):
    return (name or "").strip().upper()


def read_rows():
    if not CSV_PATH.exists():
        return []
    with csv_lock, open(CSV_PATH, newline="", encoding="utf-8") as f:
        rows = []
        for r in csv.DictReader(f):
            rows.append({c: (r.get(c) or "").strip() for c in COLUMNS})
        return [r for r in rows if r["environment"]]


def write_rows(rows):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with csv_lock:
        if CSV_PATH.exists():
            bdir = DATA_DIR / "backups"
            bdir.mkdir(exist_ok=True)
            shutil.copy2(CSV_PATH, bdir / f"environments-{dt.datetime.now():%Y%m%d-%H%M%S}.csv")
        tmp = CSV_PATH.with_suffix(".tmp")
        with open(tmp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=COLUMNS)
            w.writeheader()
            for r in rows:
                w.writerow({c: r.get(c, "") for c in COLUMNS})
        os.replace(tmp, CSV_PATH)


def group(rows):
    envs, order = {}, []
    for r in rows:
        k = env_key(r["environment"])
        if k not in envs:
            envs[k] = {"name": r["environment"], "servers": [], **{f: "" for f in ENV_FIELDS}}
            order.append(k)
        e = envs[k]
        for f in ENV_FIELDS:
            if not e[f] and r.get(f):
                e[f] = r[f]
        e["servers"].append({c: r.get(c, "") for c in
                             ["host", "ip", "role", "os_user", "domain", "env_script", "ssh_user", "ssh_key", "ssh_port"]})
    out = [envs[k] for k in order]
    out.sort(key=lambda e: (e["client"].lower(), not is_prd(e["tier"]), e["name"].lower()))
    return out


def split_line(line, delim):
    return next(csv.reader([line], delimiter=delim, skipinitialspace=True))


def parse_import(text):
    lines = [l for l in text.replace("\r", "").split("\n") if l.strip() and not l.lstrip().startswith("#")]
    if not lines:
        return None, "Paste or upload at least a heading row and one server row."
    first = lines[0]
    delim = "\t" if "\t" in first else (";" if first.count(";") > first.count(",") else ",")
    raw_head = split_line(first, delim)
    head = [ALIASES.get(re.sub(r"[^a-z]", "", h.lower())) for h in raw_head]
    if "environment" not in head:
        return None, "The first row needs column headings, including an environment column."
    if "host" not in head:
        return None, "Add a host column so each row names a server."
    rows, problems = [], []
    for n, line in enumerate(lines[1:], start=2):
        cells = split_line(line, delim)
        rec = {c: "" for c in COLUMNS}
        for i, k in enumerate(head):
            if k and i < len(cells):
                rec[k] = cells[i].strip()
        rec["role"] = rec["role"].lower()
        if not rec["environment"]:
            problems.append(f"Row {n}: no environment name, skipped.")
            continue
        if not rec["host"]:
            problems.append(f"Row {n}: no host, skipped.")
            continue
        rows.append(rec)
    ignored = [h for h, k in zip(raw_head, head) if not k and h.strip()]
    return {"rows": rows, "problems": problems, "ignored": ignored}, None


def audit(entry):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_DIR / "actions.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------- saved credentials
# SSH user and key path go in data/saved_credentials.json (not secret). The key passphrase and the
# Oracle Support password go in the OS credential store (Windows Credential Manager) via `keyring`,
# never in a file. The private key itself is never copied; only its path is remembered.
SAVED_PATH = DATA_DIR / "saved_credentials.json"
KEYRING_SERVICE = "psdash-peoplesoft-dashboard"


def _keyring():
    try:
        import keyring
        from keyring.backends import fail
        if isinstance(keyring.get_keyring(), fail.Keyring):
            return None
        return keyring
    except Exception:
        return None


def secret_set(name, value):
    kr = _keyring()
    if not kr:
        return False
    try:
        if value:
            kr.set_password(KEYRING_SERVICE, name, value)
        else:
            try:
                kr.delete_password(KEYRING_SERVICE, name)
            except Exception:
                pass
        return True
    except Exception:
        return False


def secret_get(name):
    kr = _keyring()
    try:
        return kr.get_password(KEYRING_SERVICE, name) if kr else None
    except Exception:
        return None


def saved():
    return read_json(SAVED_PATH, {})


def save_saved(data):
    write_json(SAVED_PATH, data)


def restore_saved_into_session():
    sv = saved()
    if sv.get("ssh"):
        session["ssh"] = sv["ssh"]
        pp = secret_get("ssh_passphrase")
        if pp:
            passphrases[session["token"]] = pp
    if sv.get("mos_user"):
        session["mos_user"] = sv["mos_user"]


def get_mos():
    """This session's Oracle Support client, signing in with saved credentials if needed."""
    c = mos_sessions.get(session.get("token"))
    if c:
        return c
    user = saved().get("mos_user")
    pw = secret_get(f"mos_password:{user}") if user else None
    if not (user and pw):
        return None
    c = MOSClient(user, pw)
    c.login()
    mos_sessions[session["token"]] = c
    return c


@app.get("/api/saved")
def saved_info():
    sv = saved()
    return jsonify(ssh=sv.get("ssh"), ssh_passphrase=bool(secret_get("ssh_passphrase")) if sv.get("ssh") else False,
                   mos_user=sv.get("mos_user"), secure_store=_keyring() is not None)


@app.delete("/api/saved/<kind>")
def forget_saved(kind):
    sv = saved()
    if kind == "ssh":
        sv.pop("ssh", None)
        secret_set("ssh_passphrase", "")
    elif kind == "mos":
        user = sv.pop("mos_user", None)
        if user:
            secret_set(f"mos_password:{user}", "")
    else:
        abort(404)
    save_saved(sv)
    audit({"time": now(), "who": session.get("who"), "event": f"forget_saved_{kind}"})
    return jsonify(ok=True)


# ---------------------------------------------------------------- auth
@app.before_request
def guard():
    if request.path.startswith("/api/") and request.path not in ("/api/login", "/api/session"):
        if not session.get("auth"):
            return jsonify(error="Sign in first."), 401
        if request.method != "GET" and request.headers.get("X-Requested-With") != "psdash":
            return jsonify(error="Bad request origin."), 400


@app.post("/api/login")
def login():
    pw = (request.get_json(silent=True) or {}).get("password", "")
    if not hmac.compare_digest(pw.encode(), PASSWORD.encode()):
        time.sleep(1.5)
        return jsonify(error="Wrong password."), 401
    session.clear()
    session["auth"] = True
    session["token"] = secrets.token_hex(16)
    restore_saved_into_session()
    session["who"] = (request.get_json(silent=True) or {}).get("name", "").strip()[:40] or "admin"
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    passphrases.pop(session.get("token"), None)
    mos_sessions.pop(session.get("token"), None)
    session.clear()
    return jsonify(ok=True)


@app.get("/api/session")
def session_info():
    return jsonify(auth=bool(session.get("auth")), who=session.get("who"), ssh=session.get("ssh"),
                   has_passphrase=session.get("token") in passphrases)


# ---------------------------------------------------------------- SSH credentials
@app.post("/api/credentials")
def set_credentials():
    body = request.get_json(silent=True) or {}
    user = (body.get("ssh_user") or "").strip()
    key = os.path.expanduser((body.get("key_path") or "").strip())
    if not SAFE_NAME.match(user):
        return jsonify(error="Enter a valid SSH user ID (letters, digits, . _ -)."), 400
    p = Path(key)
    if not key or not p.is_file():
        return jsonify(error=f"No private key file at {key or '(blank)'} on the dashboard host."), 400
    if not os.access(p, os.R_OK):
        return jsonify(error=f"The dashboard can't read {key}. Check the file's owner and permissions."), 400
    session["ssh"] = {"user": user, "key_path": str(p)}
    pp = body.get("passphrase") or ""
    if pp:
        passphrases[session["token"]] = pp
    elif body.get("clear_passphrase"):
        passphrases.pop(session["token"], None)
    note = ""
    if body.get("remember"):
        sv = saved()
        sv["ssh"] = session["ssh"]
        save_saved(sv)
        if pp and not secret_set("ssh_passphrase", pp):
            note = "Saved the user ID and key path, but not the passphrase: no secure credential store is available on this machine."
        audit({"time": now(), "who": session.get("who"), "event": "save_ssh_credentials", "target": user})
    return jsonify(ok=True, ssh=session["ssh"], note=note)


# ---------------------------------------------------------------- environments
@app.get("/api/environments")
def list_envs():
    return jsonify(environments=group(read_rows()), file=str(CSV_PATH))


@app.delete("/api/environments/<name>")
def delete_env(name):
    rows = read_rows()
    keep = [r for r in rows if env_key(r["environment"]) != env_key(name)]
    if len(keep) == len(rows):
        return jsonify(error="Environment not found."), 404
    write_rows(keep)
    audit({"time": now(), "who": session.get("who"), "event": "delete_environment", "environment": name})
    return jsonify(ok=True)


@app.post("/api/import/preview")
def import_preview():
    parsed, err = parse_import((request.get_json(silent=True) or {}).get("text", ""))
    if err:
        return jsonify(error=err), 400
    existing = {env_key(r["environment"]) for r in read_rows()}
    envs = group(parsed["rows"])
    for e in envs:
        e["exists"] = env_key(e["name"]) in existing
    return jsonify(environments=envs, problems=parsed["problems"], ignored=parsed["ignored"])


@app.post("/api/import")
def do_import():
    parsed, err = parse_import((request.get_json(silent=True) or {}).get("text", ""))
    if err:
        return jsonify(error=err), 400
    incoming = {env_key(r["environment"]) for r in parsed["rows"]}
    rows = [r for r in read_rows() if env_key(r["environment"]) not in incoming] + parsed["rows"]
    write_rows(rows)
    audit({"time": now(), "who": session.get("who"), "event": "import",
           "environments": sorted(incoming), "servers": len(parsed["rows"])})
    return jsonify(ok=True, environments=len(incoming), servers=len(parsed["rows"]))


@app.get("/api/environments.csv")
def download_csv():
    if not CSV_PATH.exists():
        abort(404)
    return send_file(CSV_PATH, mimetype="text/csv", as_attachment=True, download_name="environments.csv")


# ---------------------------------------------------------------- running actions
def build_command(server, action, ssh_user):
    role = server["role"]
    d = server["domain"]
    if role not in COMMANDS:
        raise ValueError(f"Role '{role or 'blank'}' has no psadmin actions.")
    if not SAFE_NAME.match(d or ""):
        raise ValueError(f"Domain name '{d}' is missing or has unexpected characters.")
    inner = COMMANDS[role][action].format(d=shlex.quote(d))
    script = server.get("env_script") or ""
    if script:
        if not SAFE_PATH.match(script):
            raise ValueError(f"env_script path '{script}' has unexpected characters.")
        inner = f"cd {shlex.quote(os.path.dirname(script) or '.')} && . {shlex.quote(script)} >/dev/null 2>&1; {inner}"
    os_user = server.get("os_user") or ""
    if os_user and os_user != ssh_user:
        if not SAFE_NAME.match(os_user):
            raise ValueError(f"OS user '{os_user}' has unexpected characters.")
        return f"sudo -n -iu {shlex.quote(os_user)} bash -lc {shlex.quote(inner)}"
    return f"bash -lc {shlex.quote(inner)}"


def plan_steps(env, action, host=None, role=None):
    servers = [s for s in env["servers"] if s["role"] in COMMANDS]
    if host:
        servers = [s for s in servers if s["host"] == host and (not role or s["role"] == role)]
    if not servers:
        raise ValueError("No web, app or prcs servers matched.")
    def ordered(order):
        return sorted(servers, key=lambda s: order.index(s["role"]))
    if action == "start":
        return [(s, "start") for s in ordered(START_ORDER)]
    if action == "stop":
        return [(s, "stop") for s in ordered(STOP_ORDER)]
    if action == "restart":
        return [(s, "stop") for s in ordered(STOP_ORDER)] + [(s, "start") for s in ordered(START_ORDER)]
    return [(s, "status") for s in ordered(START_ORDER)]


def ssh_client(server, creds, passphrase):
    target = server["ip"] or server["host"]
    if not SAFE_HOST.match(target):
        raise ValueError(f"Host '{target}' has unexpected characters.")
    user = server.get("ssh_user") or creds["user"]
    key = os.path.expanduser(server.get("ssh_key") or creds["key_path"])
    port = int(server.get("ssh_port") or 22)
    c = paramiko.SSHClient()
    c.load_system_host_keys()
    c.set_missing_host_key_policy(paramiko.RejectPolicy() if STRICT_HOST_KEYS else paramiko.WarningPolicy())
    c.connect(target, port=port, username=user, key_filename=key, passphrase=passphrase or None,
              look_for_keys=False, allow_agent=False, timeout=CONNECT_TIMEOUT,
              banner_timeout=CONNECT_TIMEOUT, auth_timeout=CONNECT_TIMEOUT)
    return c, user


def domain_state(role, action, output, code):
    """running / stopped / unknown, from what psadmin printed (its exit code is 0 even for a stopped domain)."""
    t = (output or "").lower()
    stopped = ("is not started", "not running", "has stopped", "is stopped", "no bulletin board exists",
               "tmadmin_cat:1330", "cannot attach", "unable to attach", "not booted", "server is not running")
    if re.search(r"^\s*stopped\s*$", t, re.M):
        return "stopped" if action == "status" else ("stopped" if action == "stop" else "unknown")
    if code is None:
        return "unknown"
    if action == "status":
        if any(k in t for k in stopped):
            return "stopped"
        if role == "app" and re.search(r"\b(psappsrv|bbl|jsl)\b.*\(\s*(idle|busy)", t):
            return "running"
        if role == "prcs" and re.search(r"\bstarted\b|\(\s*(idle|busy)", t):
            return "running"
        if role == "web" and re.search(r"\b(started|running)\b", t):
            return "running"
        return "unknown"
    if action == "start":
        return "running" if code == 0 else "unknown"
    if action == "stop":
        return "stopped" if code == 0 else "unknown"
    return "unknown"


DOMAIN_STATE_PATH = DATA_DIR / "domain_state.json"


def record_states(env_name, results):
    """results: [(server, action, exit_code, state)] -> remembered per domain, shown on the Environments page."""
    data = read_json(DOMAIN_STATE_PATH, {})
    e = data.setdefault(env_key(env_name), {})
    for server, act, code, state in results:
        if code is None:
            state = "unreachable"
        elif act == "stop" and code == 0:
            state = "stopped"
        elif act == "start" and code != 0:
            state = "unknown"
        e[f"{server['host']}|{server['role']}|{server['domain']}"] = {"state": state, "action": act, "time": now()}
    write_json(DOMAIN_STATE_PATH, data)


def run_job(job_id, env, steps, creds, passphrase):
    job = jobs[job_id]
    LOG_DIR.joinpath("jobs").mkdir(parents=True, exist_ok=True)
    logf = open(LOG_DIR / "jobs" / f"{job_id}.log", "w", encoding="utf-8")

    def out(text):
        with jobs_lock:
            job["output"].append(text)
        logf.write(text)
        logf.flush()

    clients = {}
    ok = True
    try:
        for server, act in steps:
            label = f"{server['host']} [{server['role']} {server['domain']}]"
            out(f"\n=== {act.upper()} {label} — {now()}\n")
            try:
                key = (server["ip"] or server["host"], server.get("ssh_user"), server.get("ssh_key"))
                if key not in clients:
                    clients[key] = ssh_client(server, creds, passphrase)
                client, user = clients[key]
                cmd = build_command(server, act, user)
                out(f"$ {cmd}\n")
                chan = client.get_transport().open_session()
                chan.set_combine_stderr(True)
                chan.exec_command(cmd)
                deadline = time.time() + ACTION_TIMEOUT
                step_text = []
                while True:
                    if chan.recv_ready():
                        t = chan.recv(8192).decode("utf-8", "replace")
                        step_text.append(t)
                        out(t)
                    elif chan.exit_status_ready():
                        while chan.recv_ready():
                            t = chan.recv(8192).decode("utf-8", "replace")
                            step_text.append(t)
                            out(t)
                        break
                    elif time.time() > deadline:
                        chan.close()
                        raise TimeoutError(f"No finish after {ACTION_TIMEOUT}s.")
                    else:
                        time.sleep(0.25)
                code = chan.recv_exit_status()
                state = domain_state(server["role"], act, "".join(step_text), code)
                job["steps"].append({"host": server["host"], "role": server["role"], "action": act, "exit": code,
                                     "state": state})
                if act == "status":
                    out(f"--- {server['role']} domain {server['domain']}: {state.upper()}\n")
                out(f"\n--- exit code {code}\n")
                if code != 0:
                    ok = False
                    if act in ("start", "stop") and job["action"] != "status":
                        out("Stopping here because this step failed. Check the output above before retrying.\n")
                        break
            except paramiko.SSHException as e:
                ok = False
                hint = (" The host isn't in known_hosts on the dashboard server. Run `ssh-keyscan <host> >> ~/.ssh/known_hosts` "
                        "as the dashboard's OS user, or set PSDASH_STRICT_HOST_KEYS=false.") if "not found in known_hosts" in str(e) else ""
                out(f"\nSSH error on {label}: {e}.{hint}\n")
                job["steps"].append({"host": server["host"], "role": server["role"], "action": act, "exit": None})
                break
            except Exception as e:
                ok = False
                out(f"\nError on {label}: {e}\n")
                job["steps"].append({"host": server["host"], "role": server["role"], "action": act, "exit": None})
                break
    finally:
        for c, _ in clients.values():
            c.close()
        job["status"] = "succeeded" if ok else "failed"
        job["finished"] = now()
        try:
            srv = {(x["host"], x["role"]): x for x, _ in steps}
            record_states(env["name"], [(srv[(st["host"], st["role"])], st["action"], st["exit"], st.get("state", "unknown"))
                                        for st in job["steps"] if (st["host"], st["role"]) in srv])
        except Exception:
            pass
        out(f"\n=== {job['status'].upper()} — {job['finished']}\n")
        logf.close()
        audit({"time": job["finished"], "who": job["who"], "event": "action", "job": job_id,
               "environment": env["name"], "action": job["action"], "target": job["target"],
               "result": job["status"], "steps": job["steps"]})


@app.post("/api/run")
def run():
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    if action not in ACTIONS:
        return jsonify(error="Unknown action."), 400
    envs = {env_key(e["name"]): e for e in group(read_rows())}
    env = envs.get(env_key(body.get("environment")))
    if not env:
        return jsonify(error="Environment not found."), 404
    creds = session.get("ssh")
    needs_default = any(not (s.get("ssh_user") and s.get("ssh_key")) for s in env["servers"])
    if needs_default and not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    creds = creds or {"user": "", "key_path": ""}
    if is_prd(env["tier"]) and action in ("stop", "restart") and env_key(body.get("confirm")) != env_key(env["name"]):
        return jsonify(error=f"Type {env['name']} to confirm.", need_confirm=True), 409
    try:
        steps = plan_steps(env, action, body.get("host"), body.get("role"))
        for s, a in steps:
            build_command(s, a, s.get("ssh_user") or creds["user"])  # validate before starting
    except ValueError as e:
        return jsonify(error=str(e)), 400
    job_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    target = body.get("host") or "all servers"
    with jobs_lock:
        jobs[job_id] = {"id": job_id, "environment": env["name"], "action": action, "target": target,
                        "who": session.get("who"), "started": now(), "finished": None,
                        "status": "running", "output": [], "steps": []}
    threading.Thread(target=run_job, args=(job_id, env, steps, creds, passphrases.get(session.get("token"))),
                     daemon=True).start()
    return jsonify(job=job_id)


# ---------------------------------------------------------------- discovery
# Runs on the target as the SSH user. Finds the PeopleSoft owner(s), then, as each owner,
# reads PS_HOME / PS_CFG_HOME and lists web, app server and process scheduler domains.
# Read-only: it only runs echo, ls-style globbing, grep and ps.
# The inner script is piped to the owner's shell on stdin: `sudo -i` would otherwise expand
# its $variables too early, in the wrong shell.
DISCOVER_INNER = r"""
ME=$(id -un)
echo "PSD|env|$PS_HOME|$PS_CFG_HOME|$JAVA_HOME|$(command -v psadmin 2>/dev/null)"
C="$PS_CFG_HOME"
if [ -n "$C" ]; then
  for d in "$C"/webserv/*/; do
    [ -f "${d}bin/startPIA.sh" ] || continue
    w=$(grep -h -o -m1 "BEA_HOME=[^ ;]*" "${d}bin/setEnv.sh" 2>/dev/null | head -1 | cut -d= -f2 | tr -d "\"'")
    cfg=no; [ -f "${d}config/config.xml" ] && cfg=yes
    echo "PSD|web|$(basename "$d")|$w|$(stat -c %U "$d" 2>/dev/null)|$cfg|$(cd "$d" && pwd -P)"
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


def known_hosts_path():
    return Path(os.path.expanduser("~/.ssh/known_hosts"))


def host_entry(ip, port):
    return ip if port == 22 else f"[{ip}]:{port}"


def remote_host_key(ip, port):
    t = paramiko.Transport((ip, port))
    try:
        t.banner_timeout = CONNECT_TIMEOUT
        t.start_client(timeout=CONNECT_TIMEOUT)
        return t.get_remote_server_key()
    finally:
        t.close()


def fingerprint(key):
    import base64, hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def parse_target(text):
    text = text.strip()
    port = 22
    m = re.match(r"^\[?([^\]]+?)\]?:(\d{1,5})$", text)
    if m:
        text, port = m.group(1), int(m.group(2))
    if not SAFE_HOST.match(text):
        raise ValueError(f"'{text}' isn't a valid IP address or host name.")
    return text, port


def discover_one(target, users, creds, passphrase):
    ip, port = parse_target(target)
    result = {"target": target, "ip": ip, "port": port, "host": "", "owners": [], "rows": [], "notes": []}
    # host key check first, so an unknown server can be trusted from the page
    key = remote_host_key(ip, port)
    entry = host_entry(ip, port)
    hk = paramiko.HostKeys()
    if known_hosts_path().exists():
        hk.load(str(known_hosts_path()))
    known = hk.lookup(entry)
    if known is None or key.get_name() not in known:
        if STRICT_HOST_KEYS:
            result.update(needs_trust=True, key_type=key.get_name(), fingerprint=fingerprint(key))
            return result
    elif known[key.get_name()] != key:
        result["error"] = (f"The host key for {entry} has CHANGED since it was trusted. "
                           "Confirm with the server owner before removing the old entry from known_hosts.")
        return result
    server = {"ip": ip, "host": ip, "ssh_port": str(port), "ssh_user": "", "ssh_key": ""}
    client, ssh_user = ssh_client(server, creds, passphrase)
    try:
        chan = client.get_transport().open_session()
        chan.settimeout(120)
        args = " ".join(shlex.quote(u) for u in users)
        chan.exec_command(f"INNER={shlex.quote(DISCOVER_INNER)} bash -s -- {args}")
        chan.sendall(DISCOVER_OUTER.encode())
        chan.shutdown_write()
        buf = b""
        while True:
            data = chan.recv(65536)
            if not data:
                break
            buf += data
        chan.recv_exit_status()
    finally:
        client.close()
    owners = {}
    for line in buf.decode("utf-8", "replace").splitlines():
        p = line.split("|")
        if p[0] == "PSH" and len(p) > 1:
            result["host"] = p[1]
        elif p[0] == "PSN":
            result["notes"].append(p[1] if len(p) > 1 else "")
        elif p[0] == "PSS" and len(p) > 2:
            result["notes"].append(p[2])
        elif p[0] == "PSD" and len(p) > 2:
            u, kind = p[1], p[2]
            o = owners.setdefault(u, {"user": u, "ps_home": "", "ps_cfg_home": "", "java_home": "",
                                      "psadmin": "", "web": [], "app": [], "prcs": []})
            if kind == "env":
                o.update(ps_home=p[3] if len(p) > 3 else "", ps_cfg_home=p[4] if len(p) > 4 else "",
                         java_home=p[5] if len(p) > 5 else "", psadmin=p[6] if len(p) > 6 else "")
            elif kind in ("web", "app", "prcs") and len(p) > 3:
                o[kind].append({"domain": p[3], "weblogic_home": p[4] if len(p) > 4 else "",
                                "owner": p[5] if len(p) > 5 else "", "configured": (p[6] if len(p) > 6 else "yes") == "yes",
                                "path": p[7] if len(p) > 7 else ""})
    result["owners"] = list(owners.values())
    host = result["host"] or ip
    seen = set()
    # a domain counts once, for the user that owns its folder; other users whose login points at the
    # same PS_CFG_HOME (common on DPK installs) would otherwise list it again
    for o in sorted(result["owners"], key=lambda o: 0 if any(d["owner"] == o["user"] for r in ("web", "app", "prcs") for d in o[r]) else 1):
        base = {"host": host, "ip": ip, "os_user": "" if o["user"] == ssh_user else o["user"],
                "pt_home": o["ps_home"], "java_home": o["java_home"], "env_script": "",
                "ssh_port": "" if port == 22 else str(port)}
        for role in ("web", "app", "prcs"):
            for d in o[role]:
                ident = (role, d["path"] or f"{o['ps_cfg_home']}/{role}/{d['domain']}")
                if ident in seen:
                    continue
                if d["owner"] and d["owner"] != o["user"]:
                    continue   # listed again under its real owner
                seen.add(ident)
                why = []
                if not d["configured"]:
                    why.append("not configured (no " + ("config.xml" if role == "web" else "PSTUXCFG") + "); likely a copy or leftover")
                result["rows"].append({**base, "role": role, "domain": d["domain"],
                                       "weblogic_home": d["weblogic_home"] if role == "web" else "",
                                       "owner": d["owner"], "configured": d["configured"], "path": d["path"],
                                       "use": d["configured"], "note": "; ".join(why)})
        if o["ps_cfg_home"] and not o["psadmin"]:
            result["notes"].append(f"{o['user']}: psadmin isn't on the login PATH. Set env_script to psconfig.sh before using Start/Stop.")
    # domains whose folder owner was never scanned (e.g. only psadm1 checked, folder owned by psadm2)
    for o in result["owners"]:
        for role in ("web", "app", "prcs"):
            for d in o[role]:
                ident = (role, d["path"] or f"{o['ps_cfg_home']}/{role}/{d['domain']}")
                if ident not in seen:
                    seen.add(ident)
                    result["rows"].append({"host": host, "ip": ip, "os_user": d["owner"] if d["owner"] != ssh_user else "",
                                           "pt_home": o["ps_home"], "java_home": o["java_home"], "env_script": "",
                                           "ssh_port": "" if port == 22 else str(port), "role": role, "domain": d["domain"],
                                           "weblogic_home": d["weblogic_home"] if role == "web" else "",
                                           "owner": d["owner"], "configured": d["configured"], "path": d["path"],
                                           "use": False, "note": f"owned by {d['owner']}, which wasn't scanned; check before importing"})
    if not result["rows"]:
        result["notes"].append("No PeopleSoft domains found. If the domains belong to a user other than "
                               "psadm1/psadm2/psadm3 and aren't running, enter that user in the OS user box and scan again.")
    return result


@app.post("/api/discover")
def discover():
    body = request.get_json(silent=True) or {}
    targets = [t for t in re.split(r"[\s,;]+", body.get("targets") or "") if t][:20]
    users = [u for u in re.split(r"[\s,;]+", body.get("users") or "") if u]
    if not targets:
        return jsonify(error="Enter at least one IP address."), 400
    bad = [u for u in users if not SAFE_NAME.match(u)]
    if bad:
        return jsonify(error=f"Unexpected characters in OS user: {', '.join(bad)}"), 400
    creds = session.get("ssh")
    if not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    pp = passphrases.get(session.get("token"))
    results = []
    for t in targets:
        try:
            results.append(discover_one(t, users, creds, pp))
        except paramiko.AuthenticationException:
            results.append({"target": t, "error": f"SSH login as {creds['user']} was rejected. Check the user ID and key."})
        except (paramiko.SSHException, OSError, ValueError) as e:
            results.append({"target": t, "error": str(e) or e.__class__.__name__})
    audit({"time": now(), "who": session.get("who"), "event": "discover", "targets": targets,
           "found": sum(len(r.get("rows", [])) for r in results)})
    return jsonify(results=results)


@app.post("/api/trust-host")
def trust_host():
    body = request.get_json(silent=True) or {}
    try:
        ip, port = parse_target(body.get("target") or "")
        key = remote_host_key(ip, port)
    except (paramiko.SSHException, OSError, ValueError) as e:
        return jsonify(error=str(e)), 400
    if fingerprint(key) != body.get("fingerprint"):
        return jsonify(error="The server's key changed between the scan and your approval. Scan again."), 409
    path = known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_newline = path.exists() and path.stat().st_size > 0 and not path.read_bytes().endswith(b"\n")
    with open(path, "a", encoding="utf-8") as f:
        f.write(("\n" if needs_newline else "") + f"{host_entry(ip, port)} {key.get_name()} {key.get_base64()}\n")
    audit({"time": now(), "who": session.get("who"), "event": "trust_host_key",
           "target": host_entry(ip, port), "fingerprint": fingerprint(key)})
    return jsonify(ok=True)


@app.post("/api/status-all")
def status_all():
    """Status of every domain in every environment, in one job."""
    creds = session.get("ssh")
    if not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    envs = group(read_rows())
    if not envs:
        return jsonify(error="No environments yet."), 400
    job_id = new_job("status_all", "all environments", "status", f"{len(envs)} environments")
    pp = passphrases.get(session.get("token"))

    def work():
        log = JobLog(job_id)
        ok = True
        for e in envs:
            log(f"\n=== {e['name']} — {now()}\n")
            res = domain_steps(e, log, creds, pp, "status")
            for server, act, code, state in res:
                jobs[job_id]["steps"].append({"environment": e["name"], "host": server["host"], "role": server["role"],
                                              "domain": server["domain"], "action": "status", "exit": code, "state": state})
                ok = ok and code is not None
        log.finish(ok)
    threading.Thread(target=work, daemon=True).start()
    return jsonify(job=job_id)


@app.get("/api/overview")
def overview():
    """Remembered domain states and patch posture for every environment. Uses cached data only (no SSH, no MOS)."""
    states = read_json(DOMAIN_STATE_PATH, {})
    levels = read_json(LEVELS_PATH, {})
    targets = read_targets()
    mosrel, latest = read_json(MOS_REL_PATH, {}), read_json(MOS_LATEST_PATH, {})
    java = {m: v[1] for m, v in _java_cache.items() if v and v[1]}
    java.update({m: v for m, v in read_json(DATA_DIR / "java_latest.json", {}).items() if m not in java})
    posture = {}
    for k, rec in levels.items():
        outstanding, comps = 0, set()
        for h in rec.get("hosts", []):
            if h.get("error"):
                continue
            for it in evaluate(h, targets, java, mosrel, latest):
                if it["status"] == "needed":
                    outstanding += 1
                    comps.add(it["component"])
        posture[k] = {"checked": rec.get("checked"), "outstanding": outstanding, "components": sorted(comps)}
    return jsonify(states=states, posture=posture)


@app.get("/api/jobs/<job_id>")
def job_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify(error="Job not found."), 404
    since = int(request.args.get("since", 0))
    with jobs_lock:
        chunk = job["output"][since:]
        n = len(job["output"])
    info = {k: v for k, v in job.items() if k != "output"}
    info.update(output="".join(chunk), next=n)
    return jsonify(info)


@app.get("/api/activity")
def activity():
    path = LOG_DIR / "actions.log"
    if not path.exists():
        return jsonify(entries=[])
    lines = path.read_text(encoding="utf-8").splitlines()[-200:]
    entries = []
    for l in reversed(lines):
        try:
            entries.append(json.loads(l))
        except ValueError:
            pass
    return jsonify(entries=entries)


@app.get("/api/jobs/<job_id>/log")
def job_log(job_id):
    if not re.match(r"^[0-9A-Za-z\-]+$", job_id):
        abort(404)
    p = LOG_DIR / "jobs" / f"{job_id}.log"
    if not p.exists():
        abort(404)
    return send_file(p, mimetype="text/plain")


# ---------------------------------------------------------------- patching: targets and settings
TARGETS_PATH = DATA_DIR / "cpu_targets.csv"
SETTINGS_PATH = DATA_DIR / "settings.json"
LEVELS_PATH = DATA_DIR / "patch_levels.json"
PATCH_CACHE = DATA_DIR / "patches"
TARGET_COLS = ["component", "applies_to", "target", "patch_number", "platform", "file_filter", "label", "notes"]
COMPONENTS = ["weblogic", "jdk", "dbclient", "tuxedo"]
DEFAULT_PLATFORM = {"jdk": "226P", "tuxedo": "226P", "weblogic": "2000P", "dbclient": "226P"}   # 226P Linux x86-64, 2000P Generic
SAFE_ABS_PATH = re.compile(r"^/[A-Za-z0-9_./\-]{1,250}$")
json_lock = threading.Lock()
mos_sessions = {}   # session token -> MOS client (memory only)


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with json_lock:
        tmp = Path(str(path) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)


def read_targets():
    if not TARGETS_PATH.exists():
        return []
    with open(TARGETS_PATH, newline="", encoding="utf-8") as f:
        return [{c: (r.get(c) or "").strip() for c in TARGET_COLS} for r in csv.DictReader(f)]


def settings():
    s = read_json(SETTINGS_PATH, {})
    s.setdefault("staging_root", "/u01/app/oracle/staging/cpu")
    return s


@app.get("/api/cpu-targets")
def get_targets():
    return jsonify(targets=read_targets(), components=COMPONENTS, default_platform=DEFAULT_PLATFORM, cpu=cpu_dates())


@app.put("/api/cpu-targets")
def put_targets():
    rows = (request.get_json(silent=True) or {}).get("targets") or []
    clean, problems = [], []
    for i, r in enumerate(rows, start=1):
        r = {c: str(r.get(c) or "").strip() for c in TARGET_COLS}
        if not any(r.values()):
            continue
        if r["component"] not in COMPONENTS:
            problems.append(f"Row {i}: choose jdk, weblogic or tuxedo.")
        if not r["target"]:
            problems.append(f"Row {i}: the target is empty.")
        if r["patch_number"] and not re.match(r"^\d{5,12}$", r["patch_number"]):
            problems.append(f"Row {i}: the MOS patch number should be digits only.")
        if r["platform"] and not re.match(r"^\d{1,5}[PL]$", r["platform"]):
            problems.append(f"Row {i}: platform codes look like 226P (Linux x86-64) or 2000P (Generic).")
        if r["label"] and not SAFE_NAME.match(r["label"]):
            problems.append(f"Row {i}: the label can only use letters, digits, . _ and -.")
        if r["file_filter"]:
            try:
                re.compile(r["file_filter"])
            except re.error:
                problems.append(f"Row {i}: the file filter isn't a valid regular expression.")
        clean.append(r)
    if problems:
        return jsonify(error=" ".join(problems)), 400
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(TARGETS_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TARGET_COLS)
        w.writeheader()
        w.writerows(clean)
    audit({"time": now(), "who": session.get("who"), "event": "update_cpu_targets", "rows": len(clean)})
    return jsonify(ok=True, targets=clean)


def public_settings():
    s = dict(settings())
    s["has_jms_token"] = bool(s.pop("jms_token", ""))
    return s


@app.get("/api/settings")
def get_settings():
    return jsonify(public_settings())


@app.put("/api/settings")
def put_settings():
    body = request.get_json(silent=True) or {}
    s = settings()
    root = (body.get("staging_root") or "").strip().rstrip("/")
    if root:
        if not SAFE_ABS_PATH.match(root) or ".." in root:
            return jsonify(error="The staging folder must be an absolute path like /u01/app/oracle/staging/cpu."), 400
        s["staging_root"] = root
    if "jms_token" in body:
        tok = (body.get("jms_token") or "").strip()
        if tok and not re.match(r"^[A-Za-z0-9._\-]{8,512}$", tok):
            return jsonify(error="That doesn't look like a Java Management Service download token."), 400
        s["jms_token"] = tok
    write_json(SETTINGS_PATH, s)
    return jsonify(public_settings())


# ---------------------------------------------------------------- patching: shared job helpers
def new_job(kind, env_name, action, target):
    job_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    with jobs_lock:
        jobs[job_id] = {"id": job_id, "kind": kind, "environment": env_name, "action": action, "target": target,
                        "who": session.get("who"), "started": now(), "finished": None,
                        "status": "running", "output": [], "steps": []}
    return job_id


class JobLog:
    def __init__(self, job_id):
        self.job = jobs[job_id]
        LOG_DIR.joinpath("jobs").mkdir(parents=True, exist_ok=True)
        self.f = open(LOG_DIR / "jobs" / f"{job_id}.log", "w", encoding="utf-8")

    def __call__(self, text):
        with jobs_lock:
            self.job["output"].append(text)
        self.f.write(text)
        self.f.flush()

    def finish(self, ok, extra=None):
        self.job["status"] = "succeeded" if ok else "failed"
        self.job["finished"] = now()
        self(f"\n=== {self.job['status'].upper()} — {self.job['finished']}\n")
        self.f.close()
        entry = {"time": self.job["finished"], "who": self.job["who"], "event": self.job["kind"], "job": self.job["id"],
                 "environment": self.job["environment"], "action": self.job["action"], "target": self.job["target"],
                 "result": self.job["status"]}
        entry.update(extra or {})
        audit(entry)


def run_remote(client, cmd, stdin_text=None, timeout=300):
    chan = client.get_transport().open_session()
    chan.set_combine_stderr(True)
    chan.exec_command(cmd)
    if stdin_text is not None:
        chan.sendall(stdin_text.encode())
        chan.shutdown_write()
    buf, deadline = b"", time.time() + timeout
    while True:
        if chan.recv_ready():
            buf += chan.recv(65536)
        elif chan.exit_status_ready():
            while chan.recv_ready():
                buf += chan.recv(65536)
            break
        elif time.time() > deadline:
            chan.close()
            raise TimeoutError(f"No answer after {timeout}s.")
        else:
            time.sleep(0.2)
    return chan.recv_exit_status(), buf.decode("utf-8", "replace")


def as_owner(os_user, ssh_user, inner):
    """Command that runs `inner` in the PeopleSoft owner's login shell. `inner` must not contain $ expansions."""
    if os_user and os_user != ssh_user:
        return f"sudo -n -iu {shlex.quote(os_user)} bash -lc {shlex.quote(inner)}"
    return f"bash -lc {shlex.quote(inner)}"


def env_hosts(env):
    """One entry per server (host + connection), merging hints from all of its rows."""
    hosts = {}
    for s in env["servers"]:
        key = (s["ip"] or s["host"], s.get("ssh_user"), s.get("ssh_key"), s.get("ssh_port"), s.get("os_user"))
        h = hosts.setdefault(key, {**s, "roles": []})
        if s["role"] and s["role"] not in h["roles"]:
            h["roles"].append(s["role"])
    for h in hosts.values():
        h["java_home"] = env.get("java_home") or ""
        h["weblogic_home"] = env.get("weblogic_home") or ""
        h["pt_home"] = env.get("pt_home") or ""
    return list(hosts.values())


# ---------------------------------------------------------------- patching: check installed levels
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


def levels_script(java_hint, wl_hint):
    for p in (java_hint, wl_hint):
        if p and not SAFE_ABS_PATH.match(p):
            raise ValueError(f"Path '{p}' has unexpected characters.")
    return LEVELS_SCRIPT.replace("__JH__", java_hint or "").replace("__WLH__", wl_hint or "")


def parse_levels(text):
    r = {"pt": "", "jdk": None, "tuxedo": None, "weblogic": None, "dbclient": None}
    patches = []
    for line in text.splitlines():
        p = line.split("|")
        if p[0] != "PL" or len(p) < 2:
            continue
        if p[1] == "pt" and len(p) > 2:
            r["pt"] = p[2]
        elif p[1] == "jdk" and len(p) > 3 and p[2]:
            r["jdk"] = {"version": p[2], "home": p[3]}
        elif p[1] == "tuxedo" and len(p) > 3:
            v = re.search(r"Version\s+([\d.]+)", p[2])
            lvl = re.search(r"Patch Level\s+(\d+)", p[2], re.I)
            r["tuxedo"] = {"version": v.group(1) if v else "", "level": lvl.group(1) if lvl else "0", "raw": p[2].strip(), "home": p[3]}
        elif p[1] == "wlver" and len(p) > 3:
            r["weblogic"] = {"version": p[2], "home": p[3], "patches": []}
        elif p[1] == "wlpatch" and len(p) > 2:
            patches.append({"id": p[2], "desc": "|".join(p[3:]).strip()})
        elif p[1] == "dbclient" and len(p) > 4:
            r["dbclient"] = {"version": p[2], "ru": p[3], "home": p[4]}
        elif p[1] == "owner" and len(p) > 3:
            r.setdefault("owners", {})[p[2]] = p[3]
        elif p[1] in ("nojdk", "wlerr") and len(p) > 2:
            r.setdefault("warnings", []).append(("OPatch couldn't list WebLogic patches: " if p[1] == "wlerr" else "") + p[2].strip())
    if r["weblogic"] is not None:
        r["weblogic"]["patches"] = patches
    return r


def collect_levels(env, creds, passphrase, log):
    results, ok = [], True
    for h in env_hosts(env):
        label = f"{h['host']} ({h['ip'] or h['host']})"
        log(f"\n=== Checking {label} — {now()}\n")
        entry = {"host": h["host"], "ip": h["ip"], "roles": h["roles"], "error": ""}
        try:
            client, user = ssh_client(h, creds, passphrase)
            try:
                script = levels_script(h["java_home"], h["weblogic_home"])
                os_user = h.get("os_user") or ""
                if os_user and not SAFE_NAME.match(os_user):
                    raise ValueError(f"OS user '{os_user}' has unexpected characters.")
                cmd = f"sudo -n -iu {shlex.quote(os_user)} bash -l -s" if os_user and os_user != user else "bash -l -s"
                code, out = run_remote(client, cmd, stdin_text=script, timeout=420)
            finally:
                client.close()
            entry.update(parse_levels(out))
            for k, title in (("pt", "PeopleTools"), ("jdk", "JDK"), ("tuxedo", "Tuxedo"), ("weblogic", "WebLogic")):
                v = entry.get(k)
                if k == "pt":
                    log(f"PeopleTools: {v or 'not found'}\n")
                elif v is None:
                    log(f"{title}: not found on this host\n")
                elif k == "jdk":
                    log(f"JDK: {v['version']}  ({v['home']})\n")
                elif k == "tuxedo":
                    log(f"Tuxedo: {v['version']} patch level {v['level']}  ({v['home']})\n")
                else:
                    log(f"WebLogic: {v['version']}  ({v['home']}), {len(v['patches'])} patches\n")
                    for p in v["patches"]:
                        log(f"    {p['id']}  {p['desc']}\n")
            for w in entry.get("warnings", []):
                log(f"Warning: {w}\n")
        except Exception as e:
            ok = False
            entry["error"] = str(e) or e.__class__.__name__
            log(f"Error: {entry['error']}\n")
        results.append(entry)
    return results, ok


def run_levels_job(job_id, env, creds, passphrase):
    log = JobLog(job_id)
    results, ok = collect_levels(env, creds, passphrase, log)
    data = read_json(LEVELS_PATH, {})
    data[env_key(env["name"])] = {"checked": now(), "hosts": results}
    write_json(LEVELS_PATH, data)
    log.finish(ok)


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


JAVA_API = os.environ.get("PSDASH_JAVA_API", "https://java.oraclecloud.com")
_java_cache = {}


def jdk_major(v):
    v = v or ""
    return v.split(".")[1] if v.startswith("1.") else v.split(".")[0]


def java_latest(major):
    """Latest Oracle JDK CPU release for a major version, from Oracle's public Java Releases API."""
    hit = _java_cache.get(major)
    if hit and time.time() - hit[0] < 6 * 3600:
        return hit[1]
    import requests
    info = None
    try:
        r = requests.get(f"{JAVA_API}/javaReleases", timeout=20,
                         params={"jdkVersion": major, "releaseType": "CPU", "sortBy": "releaseDate", "sortOrder": "DESC"})
        items = (r.json() or {}).get("items") or []
        if items:
            it = items[0]
            info = {"version": it.get("releaseVersion", ""), "date": (it.get("releaseDate") or "")[:10],
                    "license": (it.get("licenseDetails") or {}).get("licenseType", ""),
                    "notes": it.get("releaseNotesUrl", "")}
    except Exception:
        saved = read_json(DATA_DIR / "java_latest.json", {}).get(major)
        info = saved if saved else {"error": "Couldn't reach Oracle's Java release service (java.oraclecloud.com) "
                                             "from this machine. Check its internet or proxy access."}
        if saved:
            _java_cache[major] = (time.time() - 5 * 3600, info)   # retry in about an hour
            return info
    _java_cache[major] = (time.time(), info)
    if info and info.get("version"):
        jl = read_json(DATA_DIR / "java_latest.json", {})
        jl[major] = info
        write_json(DATA_DIR / "java_latest.json", jl)
    return info


def cpu_dates(today=None):
    """Oracle Critical Patch Updates ship on the third Tuesday of January, April, July and October."""
    today = today or dt.date.today()
    def third_tuesday(y, m):
        d = dt.date(y, m, 1)
        return d + dt.timedelta(days=(1 - d.weekday()) % 7 + 14)
    dates = sorted(third_tuesday(y, m) for y in (today.year - 1, today.year, today.year + 1) for m in (1, 4, 7, 10))
    last = max(d for d in dates if d <= today)
    nxt = min(d for d in dates if d > today)
    return {"last": last.isoformat(), "next": nxt.isoformat(), "label": last.strftime("%Y-%b")}


MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def month_label(yymmdd):
    try:
        return f"{MONTHS[int(yymmdd[2:4]) - 1]}{2000 + int(yymmdd[:2])}"
    except (ValueError, IndexError):
        return ""


def ru19_yymm(n):
    """Database 19c RUs are quarterly: 19.30 = January 2026, 19.31 = April 2026, ..."""
    months = 2026 * 12 + (n - 30) * 3
    return f"{months // 12 % 100:02d}{months % 12 + 1:02d}01"


def wls_psu(inst):
    """Date stamp of the installed WebLogic PSU or Stack Patch Bundle, e.g. 260823."""
    best = ""
    for p in (inst or {}).get("patches", []):
        m = re.search(r"(?:PATCH SET UPDATE|STACK PATCH BUNDLE)\s+\d+\.\d+\.\d+\.\d+\.(\d{6})", p.get("desc", ""), re.I)
        if m and m.group(1) > best:
            best = m.group(1)
    return best


_java_rel_cache = {}


def java_release_date(version):
    if version in _java_rel_cache:
        return _java_rel_cache[version]
    import requests
    d = ""
    try:
        r = requests.get(f"{JAVA_API}/javaReleases/{version}", timeout=15)
        d = (r.json().get("releaseDate") or "")[:10] if r.ok else ""
    except Exception:
        pass
    _java_rel_cache[version] = d
    return d


MOS_REL_PATH = DATA_DIR / "mos_releases.json"


def mos_release_levels(refresh=False):
    """Latest WebLogic 14.1.2.0 patch date and latest Database 19c RU, from Oracle Support's release list.
    Cached for 12 hours. Releases dated after today (announced ahead of a CPU) are ignored."""
    cache = read_json(MOS_REL_PATH, {})
    if cache.get("time") and not refresh and time.time() - cache["time"] < 12 * 3600:
        return cache
    try:
        mos = get_mos()
    except Exception as e:
        return {**cache, "error": f"Oracle Support sign-in failed: {e}"}
    if not mos:
        return {**cache, "error": "Sign in to Oracle Support to look up the latest WebLogic and Database Client levels."}
    try:
        page = mos.get(mos.BASE + "/Orion/SavedSearches/switch_to_simple", timeout=120).text
    except Exception as e:
        return {**cache, "error": f"Couldn't read Oracle Support's release list: {e}"}
    today = dt.date.today().strftime("%y%m%d")
    wls = {}
    for base, d in re.findall(r'orig_release_\d+="Oracle WebLogic Server (\d+\.\d+\.\d+\.\d+)\.(\d{6})"', page):
        if d <= today and d > wls.get(base, ""):
            wls[base] = d
    last_cpu = cpu_dates()["last"].replace("-", "")[2:]
    rus = [int(n) for n in re.findall(r'orig_release_\d+="Oracle Database 19\.(\d+)\.0\.0\.0 DBRU"', page)]
    rus = [n for n in rus if ru19_yymm(n) <= last_cpu]
    data = {"time": time.time(), "checked": now(), "weblogic": wls, "db19_ru": max(rus) if rus else None}
    if not wls and not rus:
        data["error"] = "Oracle Support's release list didn't contain WebLogic or Database releases; its format may have changed."
    write_json(MOS_REL_PATH, data)
    return data


# ---------------------------------------------------------------- latest patches from Oracle Support searches
# Product search (Patches & Updates > Product or Family) for each component, parsed from the results table:
# patch number, description, release, updated date, size and download links. This mirrors what Cloud Manager
# does, so no CPU targets are needed.
MOS_PRODUCTS = {
    "weblogic": {"product": "15991", "release": "600000000159803", "plat": "2000P"},   # WebLogic Server 14.1.2.0.0
    "tuxedo": {"product": "16021", "release": "600000000183513", "plat": "226P"},      # Tuxedo 22.1.0.0.0
    "peopletools": {"product": "21918", "release": "600000000214961", "plat": "226P"}, # PeopleTools 8.62
    "dbclient": {"product": "9480", "release": "600000000101150", "plat": "226P"},     # Oracle Database 19c
}
MOS_LATEST_PATH = DATA_DIR / "mos_latest.json"
OPATCH_19_KEY = ("6880880", "226P", "190000")   # OPatch 12.2.0.1.x for Database 19c, Linux x86-64
MON_NUM = {m.upper(): i + 1 for i, m in enumerate(MONTHS)}


def aru_date(text):
    m = re.match(r"(\d{1,2})-([A-Z]{3})-(\d{4})", (text or "").strip().upper())
    return f"{m.group(3)}-{MON_NUM.get(m.group(2), 1):02d}-{int(m.group(1)):02d}" if m else ""


def parse_aru_rows(page):
    """Rows of an ARU patch search results table."""
    import html as htmlmod
    rows = []
    for tr in re.findall(r'<tr class="OraBGAccent[^"]*"[^>]*>(.*?)</tr>', page, re.S):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        if len(tds) < 5:
            continue
        def txt(x):
            x = re.sub(r"<br\s*/?>", " | ", x)
            return re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", "", x))).strip()
        patch = txt(tds[0])
        if not patch.isdigit():
            continue
        desc = txt(tds[1])
        kind = "patchset" if ": Patchset" in desc.split("|")[0] else "patch"
        aru = re.search(r"aru=(\d+)", tr)
        files = []
        for u in re.findall(r"https://updates\.oracle\.com/Orion/Download/process_form/[^\"'\s]+", tr):
            u = htmlmod.unescape(u)
            files.append((u.split("process_form/")[1].split("?")[0], u))
        rows.append({"patch": patch, "kind": kind, "desc": desc.split("|", 1)[-1].strip(), "release": txt(tds[2]),
                     "updated": aru_date(txt(tds[3])), "size": txt(tds[4]), "aru": aru.group(1) if aru else "",
                     "files": files})
    return rows


def mos_product_rows(mos, key, description=None):
    from urllib.parse import urlencode
    p = MOS_PRODUCTS[key]
    if description:
        url = mos.BASE + "/Orion/AdvancedSearch/process_form?" + urlencode(
            {"product": p["product"], "release": p["release"], "plat_lang": p["plat"], "description": description})
    else:
        url = mos.BASE + "/Orion/SimpleSearch/process_form?" + urlencode(
            {"search_type": "prod", "product": p["product"], "release": p["release"], "plat_lang": p["plat"]})
    r = mos.get(url, timeout=180)
    if r.status_code != 200:
        raise MOSError(f"Oracle Support search returned HTTP {r.status_code}.")
    return parse_aru_rows(r.text)


def latest_weblogic(rows):
    psus, spbs = {}, []
    for r in rows:
        m = re.search(r"WLS PATCH SET UPDATE (\d+\.\d+\.\d+\.\d+)\.(\d{6})", r["desc"], re.I)
        if m:
            psus[m.group(2)] = r
        m = re.search(r"WLS STACK PATCH BUNDLE (\d+\.\d+\.\d+\.\d+)\.(\d{6})", r["desc"], re.I)
        if m:
            spbs.append((m.group(2), r))
    if not psus:
        return None
    stamp = max(psus)
    psu = psus[stamp]
    spb = max(spbs, key=lambda x: (x[1]["updated"], x[0]))[1] if spbs else None
    return {"stamp": stamp, "psu_patch": psu["patch"], "released": psu["updated"],
            "spb_patch": spb["patch"] if spb else "", "spb_desc": spb["desc"] if spb else "",
            "released_by_stamp": {k: v["updated"] for k, v in psus.items()}}


def latest_tuxedo(mos, rows):
    """Rolling patches are cumulative patchsets. Newer ones don't always put 'RPnnn' in the description, so an
    unnumbered patchset is numbered one above the previous one, and confirmed from its readme when possible."""
    rps = sorted([r for r in rows if r["kind"] == "patchset" or re.search(r"\bRP\d+", r["desc"])],
                 key=lambda r: (r["updated"], r["patch"]))
    prev = None
    for r in rps:
        m = re.search(r"\bRP0*(\d+)", r["desc"])
        r["rp"], r["rp_how"] = (int(m.group(1)), "description") if m else ((prev + 1, "inferred") if prev else (None, ""))
        prev = r["rp"] if r["rp"] else prev
    if not rps:
        return None
    last = rps[-1]
    if last["rp_how"] != "description" and last.get("aru"):
        try:
            readme = mos.get(f"{mos.BASE}/Orion/Readme/process_form?aru={last['aru']}&no_header=1", timeout=60).text
            m = re.search(r"\bRP0*(\d{2,3})\b", readme)
            if m:
                last["rp"], last["rp_how"] = int(m.group(1)), "readme"
        except Exception:
            pass
    return {"rp": last["rp"], "rp_how": last["rp_how"], "patch": last["patch"], "released": last["updated"],
            "released_by_rp": {str(r["rp"]): r["updated"] for r in rps if r["rp"]}}


def latest_dbclient(mos):
    """Newest Database 19c Release Update. The family has many one-off patches, so the description filter is
    tried with a few spellings until the RU rows come back."""
    tried = []
    for desc in (None, "DATABASE RELEASE UPDATE 19", "%DATABASE RELEASE UPDATE 19%", "*DATABASE RELEASE UPDATE 19*",
                 "Database Release Update"):
        try:
            rows = mos_product_rows(mos, "dbclient", desc)
        except Exception as e:
            tried.append(f"{desc or 'product search'}: {e}")
            continue
        rus = {}
        for r in rows:
            m = re.search(r"DATABASE RELEASE UPDATE\s*:?\s*19\.(\d+)\.0\.0\.\d+", r["desc"], re.I)
            if m and not re.search(r"\b(GI|OJVM|JAVAVM|REVISION|MERGE|OVERLAY)\b", r["desc"], re.I):
                n = int(m.group(1))
                if n not in rus or r["updated"] > rus[n]["updated"]:
                    rus[n] = r
        if rus:
            n = max(rus)
            return {"ru": n, "patch": rus[n]["patch"], "released": rus[n]["updated"], "how": desc or "product search",
                    "released_by_ru": {str(k): v["updated"] for k, v in rus.items()}}
        tried.append(f"{desc or 'product search'}: {len(rows)} rows, no Release Update")
    return {"error": "Couldn't find a Database 19c Release Update on Oracle Support (" + "; ".join(tried) + ")."}


def mos_latest(refresh=False):
    cache = read_json(MOS_LATEST_PATH, {})
    if cache.get("time") and not refresh and time.time() - cache["time"] < 12 * 3600:
        return cache
    try:
        mos = get_mos()
    except Exception as e:
        return {**cache, "error": f"Oracle Support sign-in failed: {e}"}
    if not mos:
        return {**cache, "error": "Sign in to Oracle Support to look up the latest patches."}
    data, errors = {"time": time.time(), "checked": now()}, []
    for key, fn in (("weblogic", lambda: latest_weblogic(mos_product_rows(mos, "weblogic"))),
                    ("tuxedo", lambda: latest_tuxedo(mos, mos_product_rows(mos, "tuxedo"))),
                    ("dbclient", lambda: latest_dbclient(mos))):
        try:
            data[key] = fn()
            if isinstance(data[key], dict) and data[key].get("error"):
                errors.append(data[key]["error"])
        except Exception as e:
            errors.append(f"{key}: {e}")
    try:
        infra = [r for r in mos_product_rows(mos, "peopletools") if "INFRA" in r["desc"].upper()]
        if infra:
            i = max(infra, key=lambda r: r["updated"])
            data["infra_dpk"] = {"patch": i["patch"], "desc": i["desc"], "released": i["updated"]}
    except Exception as e:
        errors.append(f"PeopleTools: {e}")
    if errors:
        data["error"] = " ".join(errors)
    write_json(MOS_LATEST_PATH, data)
    return data


def cpu_label(iso_date):
    return f"{MONTHS[int(iso_date[5:7]) - 1]}{iso_date[:4]}" if iso_date and len(iso_date) >= 7 else ""


def current_label(comp, inst, latest=None):
    v = inst.get("version", "")
    latest = latest or {}
    if comp == "weblogic":
        psu = wls_psu(inst)
        base = ".".join(v.split(".")[:4])
        rel = ((latest.get("weblogic") or {}).get("released_by_stamp") or {}).get(psu)
        return f"{base} {cpu_label(rel) or month_label(psu)} CPU" if psu else f"{v} ({len(inst.get('patches', []))} patches)"
    if comp == "jdk":
        d = java_release_date(v)
        return f"{v} {month_label(d[2:4] + d[5:7] + '01')} CPU" if d else v
    if comp == "dbclient":
        ru = inst.get("ru", "")
        stamp = ru.split(".")[-1] if ru.count(".") >= 4 else ""
        n = ru.split(".")[1] if ru.startswith("19.") else ""
        rel = ((latest.get("dbclient") or {}).get("released_by_ru") or {}).get(n)
        return f"{v} {cpu_label(rel) or month_label(stamp)} CPU" if (rel or stamp) else (f"{v} RU {ru}" if ru else v)
    return f"{v} RP{inst.get('level', '0')}"


def evaluate(host, targets, java=None, mosrel=None, oracle=None):
    """Compare one host's installed levels with the latest available.
    Sources, in order: a CPU target row (if you pinned one), Oracle's Java release service (JDK),
    Oracle Support's release list (WebLogic, Database Client)."""
    items = []
    java, mosrel, oracle = java or {}, mosrel or {}, oracle or {}
    for comp in COMPONENTS:
        inst = host.get(comp)
        if not inst:
            continue
        version = inst.get("version", "")
        installed = current_label(comp, inst, oracle)
        rows = [(i, t) for i, t in enumerate(targets) if t["component"] == comp and
                (not t["applies_to"] or not version or version.startswith(t["applies_to"]))]
        if not rows and comp == "jdk":
            latest = java.get(jdk_major(version)) or {}
            if latest.get("version"):
                needed = vtuple(version) < vtuple(latest["version"])
                d = latest.get("date", "")
                items.append({"component": comp, "installed": installed, "target": latest["version"],
                              "latest_label": f"{latest['version']} {month_label(d[2:4] + d[5:7] + '01')} CPU",
                              "auto": "jdk", "key": f"{latest['version']}|java|", "source": "Oracle Java releases",
                              "status": "needed" if needed else "ok",
                              "detail": f"Oracle's latest JDK {jdk_major(version)} release is {latest['version']} ({d})."})
                continue
            items.append({"component": comp, "installed": installed, "target": "", "status": "no-target",
                          "detail": latest.get("error") or f"No latest release found for JDK {version}"})
            continue
        lw, lt, ld = oracle.get("weblogic"), oracle.get("tuxedo"), oracle.get("dbclient")
        if not rows and comp == "weblogic" and lw and wls_psu(inst) and version.startswith("14.1.2.0"):
            psu = wls_psu(inst)
            needed = psu < lw["stamp"]
            patch = lw["spb_patch"] or lw["psu_patch"]
            items.append({"component": comp, "installed": installed, "target": lw["stamp"],
                          "latest_label": f"14.1.2.0 {cpu_label(lw['released'])} CPU", "source": "Oracle Support",
                          "auto": "mos", "patch_number": patch, "platform": "2000P", "file_filter": "",
                          "verify_ids": [lw["psu_patch"]], "key": f"{patch}|2000P|",
                          "status": "needed" if needed else "ok",
                          "detail": (f"Installed WLS PSU 14.1.2.0.{psu}; newest is 14.1.2.0.{lw['stamp']} (patch {lw['psu_patch']}, "
                                     f"released {lw['released']}). Download gets the Stack Patch Bundle {lw['spb_patch']}, "
                                     "the full set Cloud Manager applies." if needed else
                                     f"Installed PSU 14.1.2.0.{psu} is the newest on Oracle Support.")})
            continue
        if not rows and comp == "tuxedo" and lt and lt.get("rp") and version.startswith("22.1.0.0.0"):
            cur = int(inst.get("level") or 0)
            needed = cur < lt["rp"]
            items.append({"component": comp, "installed": installed, "target": str(lt["rp"]), "level": str(lt["rp"]),
                          "latest_label": f"{version} RP{lt['rp']:03d}", "source": "Oracle Support",
                          "auto": "mos", "patch_number": lt["patch"], "platform": "226P", "file_filter": "",
                          "key": f"{lt['patch']}|226P|", "status": "needed" if needed else "ok",
                          "detail": f"Newest rolling patch: RP{lt['rp']:03d}, patch {lt['patch']} (released {lt['released']}"
                                    + (", RP number inferred from the sequence" if lt.get("rp_how") == "inferred" else "") + ")."})
            continue
        if not rows and comp == "dbclient" and ld and ld.get("ru"):
            ru = inst.get("ru", "")
            cur = int(ru.split(".")[1]) if ru.startswith("19.") and ru.split(".")[1].isdigit() else None
            if cur is not None:
                needed = cur < ld["ru"]
                items.append({"component": comp, "installed": installed, "target": f"19.{ld['ru']}",
                              "latest_label": f"{version} {cpu_label(ld['released'])} CPU", "source": "Oracle Support",
                              "auto": "mos", "patch_number": ld["patch"], "platform": "226P", "file_filter": "",
                              "verify_ids": [ld["patch"]], "key": f"{ld['patch']}|226P|",
                              "status": "needed" if needed else "ok",
                              "detail": f"Installed Release Update {ru}; newest is 19.{ld['ru']} (patch {ld['patch']}, released {ld['released']})."})
                continue
        if not rows and comp == "weblogic":
            base = ".".join(version.split(".")[:4])
            latest, psu = (mosrel.get("weblogic") or {}).get(base), wls_psu(inst)
            if latest and psu:
                needed = psu[:4] < latest[:4]
                items.append({"component": comp, "installed": installed, "target": "",
                              "latest_label": f"{base} {month_label(latest)} CPU", "source": "Oracle Support release list",
                              "status": "needed" if needed else "ok",
                              "detail": f"Installed patch set {base}.{psu}; newest on Oracle Support is {base}.{latest}." +
                                        (" Add its patch number under CPU targets to download it." if needed else "")})
                continue
        if not rows and comp == "dbclient":
            ru = inst.get("ru", "")
            cur = int(ru.split(".")[1]) if ru.startswith("19.") and ru.count(".") >= 1 and ru.split(".")[1].isdigit() else None
            latest = mosrel.get("db19_ru")
            if cur is not None and latest:
                needed = cur < latest
                items.append({"component": comp, "installed": installed, "target": "",
                              "latest_label": f"{version} {month_label(ru19_yymm(latest))} CPU",
                              "source": "Oracle Support release list", "status": "needed" if needed else "ok",
                              "detail": f"Installed Release Update {ru}; newest is 19.{latest}." +
                                        (" Add its patch number under CPU targets to download it." if needed else "")})
                continue
        if not rows:
            why = mosrel.get("error") or ("Oracle Support's release list doesn't track Tuxedo rolling patches; "
                                          "add the latest RP under CPU targets." if comp == "tuxedo" else
                                          "Couldn't work out the installed level.")
            items.append({"component": comp, "installed": installed, "target": "", "status": "no-target", "detail": why})
            continue
        for i, t in rows:
            if comp == "jdk":
                needed = vtuple(version) < vtuple(t["target"])
                detail = f"Upgrade {version} to {t['target']}" if needed else "At or above target"
            elif comp == "tuxedo":
                needed = int(inst.get("level") or 0) < int(re.sub(r"\D", "", t["target"]) or 0)
                detail = f"Patch level {inst.get('level')} is below {t['target']}" if needed else "At or above target"
            else:
                have = {p["id"] for p in inst.get("patches", [])} | {re.sub(r"\D", "", inst.get("ru", ""))}
                missing = [p for p in re.split(r"[\s,;]+", t["target"]) if p and p not in have]
                if comp == "dbclient" and t["target"].startswith("19."):
                    missing = [] if vtuple(inst.get("ru", "")) >= vtuple(t["target"]) else [t["target"]]
                needed = bool(missing)
                detail = ("Missing " + ", ".join(missing)) if needed else "All target patches installed"
            label = (f"{version} RP{re.sub(chr(92) + 'D', '', t['target'])}" if comp == "tuxedo" else t["target"])
            items.append({"component": comp, "installed": installed, "target": t["target"], "target_index": i,
                          "latest_label": (t["label"] + ": " if t["label"] else "") + label,
                          "patch_number": t["patch_number"], "label": t["label"], "source": "CPU target",
                          "key": (f"{t['patch_number']}|{t['platform'] or DEFAULT_PLATFORM[comp]}|{t['file_filter']}"
                                  if t["patch_number"] else ""),
                          "status": "needed" if needed else "ok", "detail": detail})
    return items


@app.post("/api/patch-check")
def patch_check():
    body = request.get_json(silent=True) or {}
    env = {env_key(e["name"]): e for e in group(read_rows())}.get(env_key(body.get("environment")))
    if not env:
        return jsonify(error="Environment not found."), 404
    creds = session.get("ssh")
    if not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    job_id = new_job("patch_check", env["name"], "check patch levels", "all servers")
    threading.Thread(target=run_levels_job, args=(job_id, env, creds, passphrases.get(session.get("token"))),
                     daemon=True).start()
    return jsonify(job=job_id)


@app.get("/api/patch-levels/<name>")
def patch_levels(name):
    rec = read_json(LEVELS_PATH, {}).get(env_key(name))
    if not rec:
        return jsonify(checked=None, hosts=[])
    targets = read_targets()
    majors = {jdk_major(h["jdk"]["version"]) for h in rec["hosts"] if h.get("jdk") and h["jdk"].get("version")}
    java = {m: java_latest(m) for m in majors
            if not any(t["component"] == "jdk" and (not t["applies_to"] or t["applies_to"].split(".")[0] == m) for t in targets)}
    staged = read_json(STAGED_PATH, {}).get(env_key(name), {})
    refresh = request.args.get("refresh") == "1"
    latest = mos_latest(refresh=refresh)
    mosrel = mos_release_levels(refresh=refresh) if latest.get("error") else {}
    hosts = []
    for h in rec["hosts"]:
        items = [] if h.get("error") else evaluate(h, targets, java, mosrel, latest)
        for it in items:
            hs = staged.get(h["ip"] or h["host"], {})
            it["staged"] = hs.get(it.get("key") or "-")
            if it["staged"] and it["component"] == "dbclient" and it.get("auto") == "mos" and "|".join(OPATCH_19_KEY) not in hs:
                it["staged"] = None   # downloaded before OPatch was included; Download again fetches it
        hosts.append({"host": h["host"], "ip": h["ip"], "roles": h.get("roles", []), "pt": h.get("pt", ""),
                      "owners": h.get("owners", {}), "warnings": h.get("warnings", []), "error": h.get("error", ""),
                      "items": items})
    return jsonify(checked=rec["checked"], hosts=hosts, mos_checked=latest.get("checked") or mosrel.get("checked"),
                   mos_error=latest.get("error"), infra_dpk=latest.get("infra_dpk"))


# ---------------------------------------------------------------- patching: My Oracle Support
class MOSError(Exception):
    pass


class MOSClient:
    """Signs in to updates.oracle.com with HTTP Basic auth (the same flow as Oracle's wget scripts)
    and downloads patch files by patch number."""
    BASE = "https://updates.oracle.com"
    LINK_RE = r"""https://[^"'\s<>]+?Download/process_form/[^"'\s<>]+?\.zip[^"'\s<>]*"""

    def __init__(self, user, password):
        import base64
        import requests
        self.user = user
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0 (psdash patch downloader)"
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def get(self, url, stream=False, timeout=60):
        from urllib.parse import urljoin, urlparse
        for _ in range(20):
            headers = {"Authorization": self.auth} if self.sends_auth_to(urlparse(url).hostname or "") else {}
            r = self.s.get(url, headers=headers, allow_redirects=False, stream=stream, timeout=timeout)
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                url = urljoin(url, r.headers["Location"])
                r.close()
                continue
            return r
        raise MOSError("Oracle Support kept redirecting; the sign-in flow may have changed.")

    @staticmethod
    def sends_auth_to(host):
        # credentials only ever go to Oracle's own hosts, never to a CDN the download redirects to
        return host == "oracle.com" or host.endswith(".oracle.com")

    def has_auth_cookie(self):
        return any(c.name == "Oracle_updates_auth" for c in self.s.cookies)

    def login(self):
        r = self.get(self.BASE + "/Orion/Services/download")
        r.close()
        if r.status_code == 401:
            raise MOSError("Oracle Support rejected the user name or password.")
        if not self.has_auth_cookie():
            r = self.get(self.BASE + "/Orion/SavedSearches/switch_to_simple")
            r.close()
        if not self.has_auth_cookie():
            raise MOSError("Signed in, but Oracle Support didn't issue a download session. Check that the account "
                           "has a support identifier (CSI) with download rights, or sign in to updates.oracle.com in "
                           "a browser once to accept any pending terms.")

    def find_files(self, patch, platform, file_filter=""):
        import html as htmlmod
        url = (f"{self.BASE}/Orion/SimpleSearch/process_form?search_type=patch"
               f"&patch_number={patch}&plat_lang={platform}")
        r = self.get(url)
        page = r.text
        if r.status_code == 401 or "login.oracle.com" in r.url:
            raise MOSError("The Oracle Support session expired. Sign in again.")
        links = re.findall(self.LINK_RE, page)
        if not links:   # multi-part patches list their files on a details page
            for d in re.findall(r"/Orion/PatchDetails/process_form[^\"'\s]+", page):
                links += re.findall(self.LINK_RE, self.get(self.BASE + htmlmod.unescape(d)).text)
        files = {}
        for link in links:
            link = htmlmod.unescape(link)
            name = link.split("process_form/")[1].split("?")[0]
            if file_filter and not re.search(file_filter, name):
                continue
            files[name] = link
        return sorted(files.items())

    def download(self, url, dest, log):
        part = Path(str(dest) + ".part")
        r = self.get(url, stream=True, timeout=120)
        if r.status_code != 200:
            raise MOSError(f"Download returned HTTP {r.status_code}.")
        if "text/html" in (r.headers.get("Content-Type") or ""):
            raise MOSError("Oracle Support returned a web page instead of the file. The session may have expired, "
                           "or the license agreement for this patch hasn't been accepted.")
        total = int(r.headers.get("Content-Length") or 0)
        done, next_mark = 0, 0
        with open(part, "wb") as f:
            for chunk in r.iter_content(1024 * 1024):
                f.write(chunk)
                done += len(chunk)
                if total and done * 100 // total >= next_mark:
                    log(f"    {dest.name}: {done * 100 // total}% of {total // 1048576} MB\n")
                    next_mark += 20
        import zipfile
        if not zipfile.is_zipfile(part):
            part.unlink()
            raise MOSError(f"{dest.name} isn't a valid zip file. The download was probably an error page.")
        os.replace(part, dest)


@app.post("/api/mos-login")
def mos_login():
    body = request.get_json(silent=True) or {}
    user, pw = (body.get("user") or "").strip(), body.get("password") or ""
    if not user or not pw:
        return jsonify(error="Enter your Oracle Support user name and password."), 400
    try:
        c = MOSClient(user, pw)
        c.login()
    except MOSError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=f"Couldn't reach Oracle Support from this machine: {e}"), 502
    mos_sessions[session["token"]] = c
    session["mos_user"] = user
    note = ""
    if body.get("remember"):
        if secret_set(f"mos_password:{user}", pw):
            sv = saved()
            old_user = sv.get("mos_user")
            if old_user and old_user != user:
                secret_set(f"mos_password:{old_user}", "")
            sv["mos_user"] = user
            save_saved(sv)
        else:
            note = "Signed in, but the password wasn't saved: no secure credential store is available on this machine."
    audit({"time": now(), "who": session.get("who"), "event": "mos_sign_in", "target": user})
    return jsonify(ok=True, user=user, note=note)


MOS_IDS = {   # from Oracle's ARU product/release lists
    "peopletools": {"product": "21918", "release_862": "600000000214961", "platform": "226P"},
    "weblogic": {"product": "15991", "release": "600000000159803", "platform": "2000P"},
    "tuxedo": {"product": "16021", "release": "600000000183513", "platform": "226P"},
}


def strip_bulk(html_text):
    """Drop the multi-megabyte product/release dictionaries and long option lists from an ARU page.
    Linear-time: splits on tags instead of using backtracking regexes."""
    out, pos, low = [], 0, html_text.lower()
    while True:
        i = low.find("<script", pos)
        if i < 0:
            out.append(html_text[pos:])
            break
        j = low.find("</script>", i)
        j = len(html_text) if j < 0 else j + 9
        out.append(html_text[pos:i])
        block = html_text[i:j]
        out.append(block if len(block) < 20000 else "<script>/* %d bytes of lists removed */</script>" % len(block))
        pos = j
    t = "".join(out)
    out, pos, low = [], 0, t.lower()
    while True:
        i = low.find("<select", pos)
        if i < 0:
            out.append(t[pos:])
            break
        j = low.find("</select>", i)
        j = len(t) if j < 0 else j + 9
        out.append(t[pos:i])
        block = t[i:j]
        n = block.lower().count("<option")
        if n > 150:
            head = block[:block.find(">") + 1]
            block = head + "<!-- %d options removed -->" % n + "</select>"
        out.append(block)
        pos = j
    return "".join(out)


@app.post("/api/mos-capture")
def mos_capture():
    """Save Oracle Support search pages (bulk lists stripped) and trial product searches, so the
    latest-patch search can be built against Oracle's real form fields. Read-only."""
    import zipfile
    from urllib.parse import urlencode
    try:
        mos = get_mos()
    except Exception as e:
        return jsonify(error=f"The saved Oracle Support sign-in didn't work: {e}", need_mos=True), 409
    if not mos:
        return jsonify(error="Sign in to Oracle Support first.", need_mos=True), 409
    out_dir = DATA_DIR / "mos_capture"
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True)
    saved_files, notes = [], []

    def grab(name, url):
        try:
            r = mos.get(url, timeout=120)
            text = strip_bulk(r.text)
            (out_dir / name).write_text(text, encoding="utf-8")
            saved_files.append(name)
            dl = len(re.findall(r"Download/process_form/", text))
            pd = len(set(re.findall(r"patch_num(?:ber)?=(\d{6,9})", text)))
            notes.append(f"{name}: HTTP {r.status_code}, {len(r.content)} bytes raw, {len(text)} kept, "
                         f"{dl} download links, {pd} patch numbers, from {r.url[:160]}")
        except Exception as e:
            notes.append(f"{name}: failed ({e})")

    B = mos.BASE
    pt, wl, tx = MOS_IDS["peopletools"], MOS_IDS["weblogic"], MOS_IDS["tuxedo"]
    grab("01_simple_form.html", B + "/Orion/SavedSearches/switch_to_simple")
    grab("02_simple_prod_form.html", B + "/Orion/SimpleSearch/get_form?search_type=prod")
    grab("03_advanced_form.html", B + "/Orion/SavedSearches/switch_to_advanced")
    trials = [
        ("10_pt862_simple.html", "/Orion/SimpleSearch/process_form",
         {"search_type": "prod", "product": pt["product"], "release": pt["release_862"], "plat_lang": pt["platform"]}),
        ("11_wls1412_simple.html", "/Orion/SimpleSearch/process_form",
         {"search_type": "prod", "product": wl["product"], "release": wl["release"], "plat_lang": wl["platform"]}),
        ("12_tux221_simple.html", "/Orion/SimpleSearch/process_form",
         {"search_type": "prod", "product": tx["product"], "release": tx["release"], "plat_lang": tx["platform"]}),
        ("13_pt862_advanced.html", "/Orion/AdvancedSearch/process_form",
         {"product": pt["product"], "release": pt["release_862"], "plat_lang": pt["platform"], "description": "INFRA"}),
        ("14_wls1412_advanced.html", "/Orion/AdvancedSearch/process_form",
         {"product": wl["product"], "release": wl["release"], "plat_lang": wl["platform"]}),
    ]
    for name, path, params in trials:
        grab(name, B + path + "?" + urlencode(params))
    (out_dir / "00_notes.txt").write_text("\n".join(notes) + "\n", encoding="utf-8")
    zpath = DATA_DIR / "mos_capture.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in ["00_notes.txt"] + saved_files:
            z.write(out_dir / f, f)
    audit({"time": now(), "who": session.get("who"), "event": "mos_capture", "target": str(zpath)})
    return jsonify(ok=True, path=str(zpath), notes=notes)


@app.get("/api/mos-status")
def mos_status():
    sv = saved()
    return jsonify(signed_in=session.get("token") in mos_sessions or bool(sv.get("mos_user")),
                   user=session.get("mos_user") or sv.get("mos_user"), remembered=bool(sv.get("mos_user")))


# ---------------------------------------------------------------- patching: download and stage
def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def cached_files(patch, file_filter):
    d = PATCH_CACHE / patch
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and not p.name.endswith(".part")
                  and (not file_filter or re.search(file_filter, p.name)))


def stage_file(client, ssh_user, os_user, local, stage_dir, log):
    name = local.name
    dest = f"{stage_dir}/{name}"
    size = local.stat().st_size
    digest = sha256_file(local)
    # already there?
    code, out = run_remote(client, as_owner(os_user, ssh_user,
                           f"mkdir -p {shlex.quote(stage_dir)} && (sha256sum {shlex.quote(dest)} 2>/dev/null || true) && df -Pk {shlex.quote(stage_dir)} | tail -1"))
    if code != 0:
        raise RuntimeError(f"Couldn't create {stage_dir} as {os_user or ssh_user}: {out.strip()}")
    if digest in out:
        log(f"    {name}: already staged (checksum matches), skipped\n")
        return
    m = re.search(r"\s(\d+)\s+\d+%\s", out)
    if m and int(m.group(1)) * 1024 < size + 50 * 1048576:
        raise RuntimeError(f"Not enough space in {stage_dir}: {int(m.group(1)) // 1024} MB free, {size // 1048576} MB needed.")
    tmp = f"{dest}.part"
    cmd = as_owner(os_user, ssh_user,
                   f"cat > {shlex.quote(tmp)} && mv -f {shlex.quote(tmp)} {shlex.quote(dest)} && sha256sum {shlex.quote(dest)}")
    chan = client.get_transport().open_session()
    chan.set_combine_stderr(True)
    chan.exec_command(cmd)
    sent, next_mark = 0, 25
    with open(local, "rb") as f:
        for chunk in iter(lambda: f.read(256 * 1024), b""):
            chan.sendall(chunk)
            sent += len(chunk)
            if size and sent * 100 // size >= next_mark:
                log(f"    {name}: sent {sent * 100 // size}%\n")
                next_mark += 25
    chan.shutdown_write()
    out = b""
    while True:
        data = chan.recv(65536)
        if not data:
            break
        out += data
    code = chan.recv_exit_status()
    text = out.decode("utf-8", "replace")
    if code != 0 or digest not in text:
        raise RuntimeError(f"Copy of {name} failed or its checksum didn't match: {text.strip()[:300]}")
    log(f"    {name}: staged and verified (sha256 {digest[:12]}…)\n")


def download_jdk(version, log):
    """Download the Linux x64 JDK tarball for an exact release from Oracle's Java download service,
    verifying it against Oracle's published SHA-256."""
    import requests
    dest_dir = PATCH_CACHE / f"jdk-{version}"
    have = cached_files(f"jdk-{version}", "")
    if have:
        log(f"\n=== JDK {version}: using {have[0].name} already in {dest_dir}\n")
        return have
    log(f"\n=== JDK {version}: looking it up on Oracle's Java download service — {now()}\n")
    r = requests.get(f"{JAVA_API}/javaReleases/{version}", timeout=30,
                     params={"osFamily": "linux", "architecture": "x64", "packageType": "tar.gz", "artifactType": "JDK"})
    info = r.json() if r.ok else {}
    arts = [a for a in (info.get("artifacts") or []) if a.get("downloadUrl")]
    if not arts:
        raise RuntimeError(f"Oracle's Java download service has no Linux x64 tarball for JDK {version}. "
                           f"Download it from MOS or oracle.com and put it in {dest_dir}.")
    a = arts[0]
    license_type = (info.get("licenseDetails") or {}).get("licenseType", "")
    token = settings().get("jms_token", "")
    if license_type == "OTN" and not token:
        raise RuntimeError(f"JDK {version} is under the OTN license, so Oracle's download service needs a Java "
                           "Management Service token. Create one in the OCI Console (Java Management > Java "
                           "Download > Tokens) and add it on the Patching tab, or put the tarball in " + str(dest_dir) + ".")
    headers = {"token": token} if token else {}
    name = a["downloadUrl"].rsplit("/", 1)[-1].split("?")[0] or f"jdk-{version}_linux-x64_bin.tar.gz"
    dest_dir.mkdir(parents=True, exist_ok=True)
    part = dest_dir / (name + ".part")
    log(f"  Downloading {name}\n")
    with requests.get(a["downloadUrl"], headers=headers, stream=True, timeout=120) as resp:
        if resp.status_code != 200:
            raise RuntimeError(f"Java download returned HTTP {resp.status_code}." +
                               (" The token may be invalid or expired." if resp.status_code in (401, 403) else ""))
        total = int(resp.headers.get("Content-Length") or a.get("downloadFileSizeInBytes") or 0)
        done, mark = 0, 0
        with open(part, "wb") as f:
            for chunk in resp.iter_content(1024 * 1024):
                f.write(chunk)
                done += len(chunk)
                if total and done * 100 // total >= mark:
                    log(f"    {name}: {done * 100 // total}% of {total // 1048576} MB\n")
                    mark += 20
    if a.get("checksumUrl"):
        expected = requests.get(a["checksumUrl"], headers=headers, timeout=30).text.split()[0].strip().lower()
        actual = sha256_file(part)
        if actual != expected:
            part.unlink()
            raise RuntimeError(f"{name} failed its SHA-256 check against Oracle's published checksum.")
        log(f"    {name}: SHA-256 matches Oracle's checksum\n")
    os.replace(part, dest_dir / name)
    return [dest_dir / name]


STAGED_PATH = DATA_DIR / "staged.json"


def record_staged(env_name, ip, key, files, stage_dir):
    data = read_json(STAGED_PATH, {})
    data.setdefault(env_key(env_name), {}).setdefault(ip, {})["|".join(key)] = {
        "dir": stage_dir, "files": [f.name for f in files], "time": now()}
    write_json(STAGED_PATH, data)


PROTECTED_DIRS = {"/", "/u01", "/u01/app", "/u01/app/oracle", "/u01/app/oracle/product", "/home", "/root", "/etc",
                  "/usr", "/var", "/opt", "/tmp", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys"}


def prepare_stage_root(client, ssh_user, os_user, stage_root, log):
    """Make sure the PeopleSoft owner can write to the staging folder. If it can't, create the folder as root
    (sudo as the SSH user, e.g. opc) and give it to the owner, readable by everyone so psadm1/oracle2 can
    apply from it. Only ever touches the staging folder itself, never its parents."""
    owner = os_user or ssh_user
    probe = as_owner(os_user, ssh_user, f"mkdir -p {q(stage_root)} 2>&1 && test -w {q(stage_root)} && echo PSOK")
    code, out = run_remote(client, probe, timeout=60)
    if "PSOK" in out:
        return
    root = stage_root.rstrip("/")
    if root in PROTECTED_DIRS or root.count("/") < 3 or not SAFE_ABS_PATH.match(root) or ".." in root:
        raise RuntimeError(f"{owner} can't write to {root}, and it's too general a folder for Pegasus to change. "
                           "Pick a dedicated staging folder such as /u01/app/oracle/staging/cpu.")
    log(f"    {owner} can't write to {root}; creating it as root with sudo and giving it to {owner}\n")
    fix = (f"sudo -n mkdir -p {q(root)} && "
           f"sudo -n chown -R {q(owner)}:\"$(id -gn {q(owner)})\" {q(root)} && "
           f"sudo -n chmod 755 {q(root)} && "
           f"sudo -n find {q(root)} -type d -exec chmod 755 {{}} + && "
           f"sudo -n find {q(root)} -type f -exec chmod 644 {{}} + && echo PSFIXED")
    code, out = run_remote(client, fix, timeout=120)
    if "PSFIXED" not in out:
        raise RuntimeError(f"{owner} can't write to {root}, and sudo as {ssh_user} didn't work either "
                           f"({out.strip()[-200:] or 'no output'}). On the server, run:  sudo mkdir -p {root} && "
                           f"sudo chown -R {owner}: {root} && sudo chmod 755 {root}")
    code, out = run_remote(client, probe, timeout=60)
    if "PSOK" not in out:
        raise RuntimeError(f"Created {root}, but {owner} still can't write to it: {out.strip()[-200:]}")
    log(f"    {root} is now owned by {owner} and readable by the patch owners\n")


def run_stage_job(job_id, env, plan, stage_root, creds, passphrase, mos):
    log = JobLog(job_id)
    ok = True
    staged = []
    try:
        # 1) make sure every patch is in the local cache, downloading from MOS if needed
        files_for = {}
        for key, t in plan["patches"].items():
            patch, platform, filt = key
            if platform == "java":
                files_for[key] = download_jdk(patch, log)
                continue
            have = cached_files(patch, filt)
            if have:
                log(f"\n=== Patch {patch}: using {len(have)} file(s) already in {PATCH_CACHE / patch}\n")
                files_for[key] = have
                continue
            log(f"\n=== Patch {patch}: looking it up on Oracle Support (platform {platform}) — {now()}\n")
            if not mos:
                raise MOSError("Sign in to Oracle Support first, or put the patch zip in "
                               f"{PATCH_CACHE / patch} and try again.")
            found = mos.find_files(patch, platform, filt)
            if not found:
                raise MOSError(f"Oracle Support has no files for patch {patch} on platform {platform}"
                               f"{' matching ' + filt if filt else ''}. Check the patch number, platform and file filter.")
            (PATCH_CACHE / patch).mkdir(parents=True, exist_ok=True)
            for name, url in found:
                log(f"  Downloading {name}\n")
                mos.download(url, PATCH_CACHE / patch / name, log)
            files_for[key] = cached_files(patch, filt)
        # 2) copy each host's patches into its staging folder
        for h in plan["hosts"]:
            log(f"\n=== Staging on {h['host']} ({h['ip'] or h['host']}) — {now()}\n")
            try:
                client, user = ssh_client(h, creds, passphrase)
                try:
                    prepare_stage_root(client, user, h.get("os_user") or "", stage_root, log)
                    for key in h["patch_keys"]:
                        sub = plan["patches"][key]["label"] or (f"jdk-{key[0]}" if key[1] == "java" else f"p{key[0]}")
                        stage_dir = f"{stage_root}/{sub}"
                        for local in files_for[key]:
                            stage_file(client, user, h.get("os_user") or "", local, stage_dir, log)
                            staged.append(f"{h['host']}:{stage_dir}/{local.name}")
                        record_staged(env["name"], h["ip"] or h["host"], key, files_for[key], stage_dir)
                finally:
                    client.close()
            except Exception as e:
                ok = False
                log(f"Error on {h['host']}: {e}\n")
    except Exception as e:
        ok = False
        log(f"\nError: {e}\n")
    log.finish(ok, {"staged": staged})


@app.post("/api/patch-stage")
def patch_stage():
    body = request.get_json(silent=True) or {}
    env = {env_key(e["name"]): e for e in group(read_rows())}.get(env_key(body.get("environment")))
    if not env:
        return jsonify(error="Environment not found."), 404
    creds = session.get("ssh")
    if not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    stage_root = settings()["staging_root"]
    targets = read_targets()
    hosts = {(h["ip"] or h["host"]): h for h in env_hosts(env)}
    plan_hosts, patches = {}, {}
    for item in body.get("items") or []:
        h = hosts.get(item.get("ip") or item.get("host"))
        if item.get("auto") == "mos":
            pn, plat = str(item.get("patch_number") or ""), str(item.get("platform") or "")
            if not h or not re.match(r"^\d{5,12}$", pn) or not re.match(r"^\d{1,5}[PL]$", plat):
                return jsonify(error="A selected item is invalid. Check patch levels again."), 400
            key = (pn, plat, "")
            patches[key] = {"label": f"p{pn}", "component": item.get("component", "")}
            ph = plan_hosts.setdefault(h["ip"] or h["host"], {**h, "patch_keys": []})
            if key not in ph["patch_keys"]:
                ph["patch_keys"].append(key)
            if item.get("component") == "dbclient":
                patches[OPATCH_19_KEY] = {"label": "p6880880", "component": "opatch"}
                if OPATCH_19_KEY not in ph["patch_keys"]:
                    ph["patch_keys"].append(OPATCH_19_KEY)
            continue
        if item.get("auto") == "jdk":
            ver = str(item.get("version") or "")
            if not h or not re.match(r"^[0-9][0-9._]{0,30}$", ver):
                return jsonify(error="A selected JDK item is invalid. Check patch levels again."), 400
            key = (ver, "java", "")
            patches[key] = {"label": "", "component": "jdk"}
            ph = plan_hosts.setdefault(h["ip"] or h["host"], {**h, "patch_keys": []})
            if key not in ph["patch_keys"]:
                ph["patch_keys"].append(key)
            continue
        try:
            t = targets[int(item.get("target_index"))]
        except (TypeError, ValueError, IndexError):
            return jsonify(error="A selected item no longer matches a CPU target. Check patch levels again."), 400
        if not h:
            return jsonify(error=f"Server {item.get('host')} isn't in {env['name']} any more."), 400
        if not t["patch_number"]:
            return jsonify(error=f"The {t['component']} target {t['target']} has no MOS patch number."), 400
        key = (t["patch_number"], t["platform"] or DEFAULT_PLATFORM[t["component"]], t["file_filter"])
        patches[key] = {"label": t["label"], "component": t["component"]}
        ph = plan_hosts.setdefault(h["ip"] or h["host"], {**h, "patch_keys": []})
        if key not in ph["patch_keys"]:
            ph["patch_keys"].append(key)
    if not plan_hosts:
        return jsonify(error="Select at least one patch to stage."), 400
    try:
        mos = get_mos()
    except MOSError as e:
        return jsonify(error=f"The saved Oracle Support sign-in didn't work: {e} Sign in again.", need_mos=True), 409
    except Exception as e:
        return jsonify(error=f"Couldn't reach Oracle Support from this machine: {e}"), 502
    if not mos and any(k[1] != "java" and not cached_files(k[0], k[2]) for k in patches):
        return jsonify(error="Sign in to Oracle Support so the dashboard can download the patches.", need_mos=True), 409
    job_id = new_job("patch_stage", env["name"], "download and stage CPU patches",
                     ", ".join(sorted(plan_hosts)))
    plan = {"patches": patches, "hosts": list(plan_hosts.values())}
    threading.Thread(target=run_stage_job,
                     args=(job_id, env, plan, stage_root, creds, passphrases.get(session.get("token")), mos),
                     daemon=True).start()
    return jsonify(job=job_id)


# ---------------------------------------------------------------- patching: apply
# Each script runs on the server as the software owner (e.g. psadm1), detached with nohup/setsid,
# so a dropped SSH session or a closed browser can't interrupt an opatch run halfway.
APPLY_COMMON = r'''
set -u
unset _JAVA_OPTIONS JDK_JAVA_OPTIONS JAVA_TOOL_OPTIONS   # their "Picked up ..." line would hide the version line
fail() { echo "APPLY FAILED: $*"; exit 1; }
TS=$(date +%Y%m%d%H%M%S)
backup_home() {   # tar.gz backup of a home next to it, after a free-space check
  local H="$1" P; P=$(dirname "$H")
  local need free; need=$(du -sk "$H" 2>/dev/null | cut -f1); free=$(df -Pk "$P" | tail -1 | awk '{print $4}')
  [ "$free" -gt $(( need / 2 + 1048576 )) ] || fail "not enough free space in $P to back up $H (${need} KB to copy, ${free} KB free)"
  BK="$P/$(basename "$H").bak.$TS.tar.gz"
  echo "Backing up $H to $BK"
  tar -czf "$BK" -C "$P" "$(basename "$H")" || fail "backup of $H failed"
  echo "Backup done ($(du -sh "$BK" | cut -f1))"
}
unpack() {   # unzip every staged file into $WORK
  mkdir -p "$WORK" || fail "can't create $WORK"
  for z in "$@"; do echo "Unpacking $(basename "$z")"; unzip -oq "$z" -d "$WORK" || fail "couldn't unzip $z"; done
}
'''

APPLY_JDK = r'''
JH=__JH__; TAR=__TAR__; NEWVER=__VER__
P=$(dirname "$JH"); BKD="$JH.bak.$TS"; T="$P/.psdash_jdk_$TS"
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
if [ -n "$OPZ" ]; then   # bring OPatch up to the latest release first (Release Updates require a minimum OPatch)
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

SAFE_FILE = re.compile(r"^[A-Za-z0-9_.+\-]{1,200}$")
apply_running = set()


def q(v):
    return shlex.quote(v or "")


def build_apply_script(component, home, jdk_home, wl_home, staged, version, ids, level, work, opatch_zip=""):
    for pth in (home, jdk_home, wl_home, staged["dir"], work):
        if pth and not SAFE_ABS_PATH.match(pth):
            raise ValueError(f"Path '{pth}' has unexpected characters.")
    files = [f for f in staged["files"] if SAFE_FILE.match(f)]
    if not files:
        raise ValueError("No downloaded files recorded for this patch. Download it again.")
    paths = [f"{staged['dir']}/{f}" for f in files]
    if component == "jdk":
        body = (APPLY_JDK.replace("__JH__", q(home)).replace("__TAR__", q(paths[0]))
                .replace("__VER__", q(version)))
    elif component in ("weblogic", "dbclient"):
        body = (APPLY_WEBLOGIC.replace("__W__", q(home)).replace("__JH__", q(jdk_home if component == "weblogic" else "")).replace("__WORK__", q(work))
                .replace("__IDS__", q(" ".join(i for i in ids if i.isdigit()))).replace("__FILES__", " ".join(q(p) for p in paths))
                .replace("__OPATCHZIP__", q(opatch_zip)))
    else:
        body = (APPLY_TUXEDO.replace("__TD__", q(home)).replace("__JH__", q(jdk_home)).replace("__WORK__", q(work))
                .replace("__LEVEL__", q(re.sub(r"\D", "", level) or "0")).replace("__W__", q(wl_home))
                .replace("__FILES__", " ".join(q(p) for p in paths)))
    return APPLY_COMMON + body


def domain_steps(env, log, creds, passphrase, action):
    """Run start/stop/status for every domain in the environment. Returns per-step exit codes."""
    results = []
    try:
        steps = plan_steps(env, action)
    except ValueError:
        return results
    clients = {}
    try:
        for server, act in steps:
            label = f"{server['host']} [{server['role']} {server['domain']}]"
            try:
                key = (server["ip"] or server["host"], server.get("ssh_user"), server.get("ssh_key"))
                if key not in clients:
                    clients[key] = ssh_client(server, creds, passphrase)
                client, user = clients[key]
                code, out = run_remote(client, build_command(server, act, user), timeout=ACTION_TIMEOUT)
                state = domain_state(server["role"], act, out, code)
                log(f"--- {act} {label}: exit {code}" + (f", {state}" if act == "status" else "") + "\n")
                tail = "\n".join(l for l in out.splitlines() if l.strip() and "psconfig.sh" not in l)[-1500:]
                if tail:
                    log(tail + "\n")
                results.append((server, act, code, state))
            except Exception as e:
                log(f"--- {act} {label}: {e}\n")
                results.append((server, act, None, "unreachable"))
    finally:
        for c, _ in clients.values():
            c.close()
    try:
        record_states(env["name"], results)
    except Exception:
        pass
    return results


def processes_running(client, ssh_user, os_user):
    # bracketed first letters stop the pattern from matching this command's own process line
    cmd = as_owner(os_user, ssh_user, "ps -u " + q(os_user or ssh_user) + " -o pid=,args= | grep -E "
                   "'[w]eblogic[.]Server|[B]BL -|[P]SAPPSRV|[P]SPRCSRV|[P]SMSTPRC|[P]SDSTSRV' || true")
    code, out = run_remote(client, cmd, timeout=60)
    return [l.strip() for l in out.splitlines() if re.match(r"^\s*\d+\s", l)]


def apply_on_host(h, owner, script, job_id, creds, passphrase, log):
    """Launch the apply script detached on the server as `owner`, then follow its log until it finishes."""
    tag = f"psdash_apply/{job_id}"
    launcher = (f'D="$HOME/{tag}"; mkdir -p "$D" || exit 1\n'
                f'cat > "$D/apply.sh" <<\'PSDASH_APPLY_EOF\'\n{script}\nPSDASH_APPLY_EOF\n'
                f'( nohup setsid bash -c \'bash "$0/apply.sh"; echo $? > "$0/apply.rc"\' "$D" > "$D/apply.log" 2>&1 < /dev/null & )\n'
                f'echo "PSA|started|$D"\n')
    poll = (f'D="$HOME/{tag}"; echo "RC=$(cat "$D/apply.rc" 2>/dev/null)"; '
            f'echo "SIZE=$(stat -c %s "$D/apply.log" 2>/dev/null || echo 0)"; tail -c +$((OFFSET+1)) "$D/apply.log" 2>/dev/null | head -c 200000\n')
    client, user = ssh_client(h, creds, passphrase)
    try:
        cmd = f"sudo -n -iu {q(owner)} bash -l -s" if owner != user else "bash -l -s"
        code, out = run_remote(client, cmd, stdin_text=launcher, timeout=120)
        m = re.search(r"PSA\|started\|(\S+)", out)
        if not m:
            raise RuntimeError(f"Couldn't start the apply as {owner}: {out.strip()[-400:]}")
        log(f"Running as {owner} in the background; log on the server: {m.group(1)}/apply.log\n")
    finally:
        client.close()
    offset, deadline, failures = 0, time.time() + 4 * 3600, 0
    while time.time() < deadline:
        time.sleep(5)
        try:
            client, user = ssh_client(h, creds, passphrase)
            try:
                code, out = run_remote(client, cmd, stdin_text=f"OFFSET={offset}\n" + poll, timeout=120)
            finally:
                client.close()
            failures = 0
        except Exception as e:
            failures += 1
            log(f"(lost contact with {h['host']}: {e}; the apply keeps running there, retrying)\n")
            if failures > 30:
                raise RuntimeError("Lost contact with the server for too long. Check apply.log on the server.")
            continue
        i = out.find("RC=")   # skip anything the owner's login profile printed first
        lines = out[i:].split("\n", 2) if i >= 0 else ["", "", ""]
        rc = re.sub(r"\D", "", lines[0])
        chunk = lines[2] if len(lines) > 2 else ""
        if chunk:
            offset += len(chunk.encode("utf-8"))
            log(chunk if chunk.endswith("\n") else chunk + "\n")
        if rc != "":
            if chunk == "" or len(chunk.encode("utf-8")) < 200000:
                return int(rc) == 0
    raise RuntimeError("The apply didn't finish within 4 hours. Check apply.log on the server.")


APPLY_ORDER = ["jdk", "weblogic", "dbclient", "tuxedo"]   # JDK first: OPatch for WebLogic runs on it
COMP_TITLE = {"jdk": "JDK", "weblogic": "WebLogic", "dbclient": "Oracle Database Client", "tuxedo": "Tuxedo"}


def run_apply_job(job_id, env, plan, creds, passphrase):
    """One maintenance window: stop every domain once, apply each planned step (component by component, server by
    server), then start everything once. Stops at the first failure; domains are started again regardless."""
    log = JobLog(job_id)
    ok, applied, skipped = True, [], []
    try:
        log(f"=== Plan for {env['name']}\n")
        for comp in dict.fromkeys(p["component"] for p in plan):
            hosts = [p["server"]["host"] for p in plan if p["component"] == comp]
            log(f"    {COMP_TITLE[comp]} {next(p['label'] for p in plan if p['component'] == comp)} on {', '.join(hosts)}\n")
        log(f"\n=== Stopping all domains in {env['name']} — {now()}\n")
        domain_steps(env, log, creds, passphrase, "stop")
        checked = set()
        for h in plan:   # nothing may be running before we touch the binaries
            ip = h["server"]["ip"] or h["server"]["host"]
            if ip in checked:
                continue
            checked.add(ip)
            client, user = ssh_client(h["server"], creds, passphrase)
            try:
                left = processes_running(client, user, h["server"].get("os_user") or "")
            finally:
                client.close()
            if left:
                raise RuntimeError(f"PeopleSoft processes are still running on {h['server']['host']} after the stop, "
                                   "so nothing was patched:\n  " + "\n  ".join(left[:10]))
        for n, h in enumerate(plan):
            log(f"\n=== [{n + 1}/{len(plan)}] Applying {COMP_TITLE[h['component']]} {h['label']} on {h['server']['host']} "
                f"as {h['owner']} — {now()}\n")
            if not apply_on_host(h["server"], h["owner"], h["script"], f"{job_id}-{n + 1}", creds, passphrase, log):
                ok = False
                skipped = [f"{COMP_TITLE[x['component']]} on {x['server']['host']}" for x in plan[n + 1:]]
                log(f"\n{COMP_TITLE[h['component']]} failed on {h['server']['host']}. Stopping here; not applied: "
                    + (", ".join(skipped) or "nothing else was planned") + ".\n")
                break
            applied.append(f"{h['component']}@{h['server']['host']}")
    except Exception as e:
        ok = False
        log(f"\nError: {e}\n")
    log(f"\n=== Starting all domains in {env['name']} — {now()}\n")
    started = domain_steps(env, log, creds, passphrase, "start")
    if any(r[2] != 0 for r in started):
        ok = False
        log("Some domains didn't start. Check the output above.\n")
    log(f"\n=== Status — {now()}\n")
    domain_steps(env, log, creds, passphrase, "status")
    log(f"\n=== Re-checking patch levels — {now()}\n")
    try:
        results, _ = collect_levels(env, creds, passphrase, log)
        data = read_json(LEVELS_PATH, {})
        data[env_key(env["name"])] = {"checked": now(), "hosts": results}
        write_json(LEVELS_PATH, data)
    except Exception as e:
        log(f"Couldn't re-check: {e}\n")
    if applied:
        log(f"\nApplied: {', '.join(applied)}\n")
    apply_running.discard(env_key(env["name"]))
    log.finish(ok, {"applied": applied, "not_applied": skipped})


def build_apply_plan(env, groups):
    """groups: [(component, key)]. Returns (plan, missing, error)."""
    rec = read_json(LEVELS_PATH, {}).get(env_key(env["name"]))
    if not rec:
        return None, [], "Check patch levels first."
    targets = read_targets()
    majors = {jdk_major(h["jdk"]["version"]) for h in rec["hosts"] if h.get("jdk")}
    java = {m: java_latest(m) for m in majors}
    mosrel, latest = read_json(MOS_REL_PATH, {}), read_json(MOS_LATEST_PATH, {})
    staged = read_json(STAGED_PATH, {}).get(env_key(env["name"]), {})
    servers = {(h["ip"] or h["host"]): h for h in env_hosts(env)}
    plan, missing = [], []
    for component, key in sorted(groups, key=lambda g: APPLY_ORDER.index(g[0])):
        for h in rec["hosts"]:
            if h.get("error"):
                continue
            ip = h["ip"] or h["host"]
            item = next((it for it in evaluate(h, targets, java, mosrel, latest)
                         if it["component"] == component and it.get("key") == key and it["status"] == "needed"), None)
            if not item:
                continue
            st = staged.get(ip, {}).get(key)
            if not st:
                missing.append(f"{COMP_TITLE[component]} on {h['host']}")
                continue
            inst = h.get(component) or {}
            home = inst.get("home", "")
            owner = (h.get("owners") or {}).get(home) or "psadm1"
            if not SAFE_NAME.match(owner):
                return None, [], f"Unexpected owner '{owner}' for {home}."
            opz = ""
            if component == "dbclient" and item.get("auto") == "mos":
                sto = staged.get(ip, {}).get("|".join(OPATCH_19_KEY))
                if not sto or not sto.get("files"):
                    missing.append(f"OPatch on {h['host']}")
                    continue
                opz = f"{sto['dir']}/{sto['files'][0]}"
                if not SAFE_ABS_PATH.match(opz):
                    return None, [], f"Unexpected OPatch path {opz}."
            if ip not in servers:
                return None, [], f"{h['host']} isn't in the inventory any more."
            try:
                script = build_apply_script(
                    component, home, (h.get("jdk") or {}).get("home", ""), (h.get("weblogic") or {}).get("home", ""),
                    st, item["target"], item.get("verify_ids") or re.split(r"[\s,;]+", item["target"]),
                    item.get("level") or item["target"],
                    f"{os.path.dirname(home.rstrip('/')) or '/tmp'}/.psdash_work_{uuid.uuid4().hex[:6]}", opz)
            except ValueError as e:
                return None, [], f"{h['host']}: {e}"
            plan.append({"component": component, "key": key, "label": item.get("latest_label") or item["target"],
                         "server": servers[ip], "owner": owner, "script": script})
    return plan, missing, None


def start_apply(env, groups, body, title):
    creds = session.get("ssh")
    if not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    if env_key(env["name"]) in apply_running:
        return jsonify(error=f"An apply is already running for {env['name']}."), 409
    if is_prd(env["tier"]) and env_key(body.get("confirm")) != env_key(env["name"]):
        return jsonify(error=f"Type {env['name']} to confirm.", need_confirm=True), 409
    plan, missing, err = build_apply_plan(env, groups)
    if err:
        return jsonify(error=err), 400
    if missing:
        return jsonify(error="Download these first: " + ", ".join(missing)), 409
    if not plan:
        return jsonify(error="Nothing needs applying. Check patch levels again."), 400
    cr_id = None
    if approval_required(env):
        cr, err = claim_approval(env, body.get("change_request"), plan)
        if err:
            return jsonify(error=err, need_approval=True), 409
        cr_id = cr["id"]
    apply_running.add(env_key(env["name"]))
    job_id = new_job("patch_apply", env["name"], title, ", ".join(dict.fromkeys(p["server"]["host"] for p in plan)))
    if cr_id:
        update_cr(cr_id, job=job_id)
        jobs[job_id]["change_request"] = cr["jira_key"]
    threading.Thread(target=run_apply_with_approval,
                     args=(job_id, env, plan, creds, passphrases.get(session.get("token")), cr_id),
                     daemon=True).start()
    return jsonify(job=job_id, steps=len(plan), change_request=cr["jira_key"] if cr_id else None)


@app.post("/api/patch-apply")
def patch_apply():
    body = request.get_json(silent=True) or {}
    env = {env_key(e["name"]): e for e in group(read_rows())}.get(env_key(body.get("environment")))
    if not env:
        return jsonify(error="Environment not found."), 404
    component, key = body.get("component"), body.get("key") or ""
    if component not in COMPONENTS or not key:
        return jsonify(error="Choose a component and update to apply."), 400
    return start_apply(env, [(component, key)], body, f"apply {component} {key.split('|')[0]}")


@app.post("/api/patch-apply-all")
def patch_apply_all():
    """Every outstanding update in the environment, in one stop/start window."""
    body = request.get_json(silent=True) or {}
    env = {env_key(e["name"]): e for e in group(read_rows())}.get(env_key(body.get("environment")))
    if not env:
        return jsonify(error="Environment not found."), 404
    groups, err = outstanding_groups(env)
    if err:
        return jsonify(error=err), 400
    return start_apply(env, groups, body, "apply all outstanding updates")


def outstanding_groups(env):
    """Every (component, update key) still needed somewhere in the environment. Returns (groups, error)."""
    rec = read_json(LEVELS_PATH, {}).get(env_key(env["name"]))
    if not rec:
        return None, "Check patch levels first."
    targets = read_targets()
    java = {m: java_latest(m) for m in {jdk_major(h["jdk"]["version"]) for h in rec["hosts"] if h.get("jdk")}}
    mosrel, latest = read_json(MOS_REL_PATH, {}), read_json(MOS_LATEST_PATH, {})
    groups = []
    for h in rec["hosts"]:
        if h.get("error"):
            continue
        for it in evaluate(h, targets, java, mosrel, latest):
            if it["status"] == "needed" and it.get("key") and (it["component"], it["key"]) not in groups:
                groups.append((it["component"], it["key"]))
    if not groups:
        return None, "Nothing outstanding. Check patch levels again."
    return groups, None


# ---------------------------------------------------------------- change approval (Jira)
# With approval switched on, an Apply button no longer patches anything by itself. It first raises a Jira ticket that
# describes exactly what will change (components, versions, servers, outage, backout). The Apply button only unlocks
# once that ticket is in an approved status, and the server checks Jira again at the moment you click it, so the
# browser can't skip the step. Each approval covers one exact plan and can be used once: if patch levels change after
# the ticket was raised, Pegasus asks for a new one. When the apply finishes, the result goes back to the ticket.
CR_PATH = DATA_DIR / "change_requests.json"
JIRA_TOKEN_NAME = "jira_token"
CR_OPEN = ("pending", "approved", "applying")
cr_lock = threading.Lock()
jira_token_mem = {}   # used only when there's no OS credential store; cleared on restart

JIRA_DEFAULTS = {
    "enabled": False,
    "require": "all",                 # "all" environments, or "prd" only
    "url": "",                        # https://yourcompany.atlassian.net  or  https://jira.yourcompany.com
    "deployment": "cloud",            # "cloud" (email + API token) or "datacenter" (personal access token)
    "user": "",                       # Jira Cloud account email
    "project": "",                    # project key, e.g. CHG
    "issue_type": "Change",
    "change_type": "Normal",          # Jira Service Management "Change type" (Standard, Normal, Emergency)
    "change_risk": "",                # "Change risk" (Low, Medium, High, Critical); blank leaves it to Jira
    "impact": "",                     # "Impact"; blank leaves it to Jira
    "urgency": "",                    # "Urgency"; blank leaves it to Jira
    "submit_transition": "",          # optional transition right after creating, to send it for approval
    "approved_statuses": ["Approved", "Awaiting implementation", "Scheduled"],
    "rejected_statuses": ["Rejected", "Declined", "Canceled", "Cancelled", "Won't Do"],
    "start_transition": "",           # optional transition when the apply starts, e.g. "Implement"
    "done_transition": "",            # optional transition when it succeeds, e.g. "Done"
    "extra_fields": {"labels": ["pegasus", "cpu-patching"]},
    "block_self_approval": True,
}


class JiraError(Exception):
    pass


def jira_cfg():
    c = dict(JIRA_DEFAULTS)
    c.update(settings().get("jira") or {})
    return c


def jira_token():
    return os.environ.get("PSDASH_JIRA_TOKEN") or secret_get(JIRA_TOKEN_NAME) or jira_token_mem.get("token") or ""


def approval_required(env):
    c = jira_cfg()
    return bool(c["enabled"]) and (c["require"] == "all" or is_prd(env["tier"]))


def _jira_error_text(r):
    try:
        j = r.json()
        parts = list(j.get("errorMessages") or []) + [f"{k}: {v}" for k, v in (j.get("errors") or {}).items()]
        if parts:
            return "; ".join(parts)[:500]
    except ValueError:
        pass
    return (r.text or r.reason or "")[:300]


def _who(u):
    """A Jira user's stable identity: accountId on Cloud, key or name on Data Center."""
    u = u or {}
    return u.get("accountId") or u.get("key") or u.get("name") or ""


class Jira:
    def __init__(self, cfg=None, token=None):
        import requests
        cfg = cfg or jira_cfg()
        token = token if token is not None else jira_token()
        if not cfg["url"] or not cfg["project"]:
            raise JiraError("Jira isn't set up yet. Fill in the Jira URL and project on the Patching tab.")
        if not token:
            raise JiraError("No Jira API token is saved. Add it under Change approval on the Patching tab.")
        if cfg["deployment"] == "cloud" and not cfg["user"]:
            raise JiraError("Jira Cloud signs in with an account email and API token. Enter the email.")
        self.cfg = cfg
        self.base = cfg["url"].rstrip("/")
        self.req = requests
        self.s = requests.Session()
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if cfg["deployment"] == "cloud":
            self.s.auth = (cfg["user"], token)
        else:
            self.s.headers["Authorization"] = f"Bearer {token}"

    def call(self, method, path, body=None, params=None):
        try:
            r = self.s.request(method, f"{self.base}/rest/api/2/{path}", json=body, params=params, timeout=20)
        except self.req.RequestException as e:
            raise JiraError(f"Couldn't reach Jira at {self.base}: {e}")
        if r.status_code in (401, 403):
            raise JiraError(f"Jira refused the sign-in ({r.status_code}). Check the account and API token. "
                            + _jira_error_text(r))
        if r.status_code >= 300:
            raise JiraError(f"Jira returned {r.status_code}: {_jira_error_text(r)}")
        return r.json() if r.content else {}

    def browse(self, key):
        return f"{self.base}/browse/{key}"

    def myself(self):
        return self.call("GET", "myself")

    def project(self):
        return self.call("GET", f"project/{self.cfg['project']}")

    def create_meta(self):
        """The fields Jira offers when creating the configured issue type in the project: {lower name: field}."""
        proj, want = self.cfg["project"], self.cfg["issue_type"].strip().lower()
        try:   # Jira Cloud and Data Center 8.4+
            types = self.call("GET", f"issue/createmeta/{proj}/issuetypes", params={"maxResults": 100})
            types = types.get("values") or types.get("issueTypes") or []
            it = next((t for t in types if t.get("name", "").lower() == want), None)
            if not it:
                raise JiraError(f"Project {proj} has no '{self.cfg['issue_type']}' issue type. "
                                f"Available: {', '.join(t.get('name', '') for t in types) or 'none'}.")
            fields, start = [], 0
            while True:
                page = self.call("GET", f"issue/createmeta/{proj}/issuetypes/{it['id']}",
                                 params={"startAt": start, "maxResults": 100})
                vals = page.get("values") or page.get("fields") or []
                fields += vals
                start += len(vals)
                if not vals or page.get("isLast", True) or start >= page.get("total", start):
                    break
        except JiraError as e:
            if "returned 404" not in str(e):
                raise
            # older Jira Server: the expanded createmeta call
            meta = self.call("GET", "issue/createmeta", params={"projectKeys": proj,
                                                                 "expand": "projects.issuetypes.fields"})
            types = [t for p in meta.get("projects") or [] for t in p.get("issuetypes") or []]
            it = next((t for t in types if t.get("name", "").lower() == want), None)
            if not it:
                raise JiraError(f"Project {proj} has no '{self.cfg['issue_type']}' issue type. "
                                f"Available: {', '.join(t.get('name', '') for t in types) or 'none'}.")
            fields = [dict(f, fieldId=fid) for fid, f in (it.get("fields") or {}).items()]
        return {(f.get("name") or "").strip().lower(): dict(f, fieldId=f.get("fieldId") or f.get("key")) for f in fields}

    def change_fields(self, meta, window):
        """Fill the Change fields this project has (by their names, since their IDs differ between Jira sites)."""
        out, problems = {}, []

        def put(name, value):
            f = meta.get(name)
            if not f or value in (None, ""):
                return
            kind = (f.get("schema") or {}).get("type", "")
            if kind == "option":
                allowed = [a.get("value") or a.get("name") for a in f.get("allowedValues") or []]
                match = next((a for a in allowed if a and a.lower() == str(value).lower()), None)
                if allowed and not match:
                    problems.append(f"'{value}' isn't a valid {f['name']} in Jira. Choose one of: {', '.join(allowed)}.")
                    return
                out[f["fieldId"]] = {"value": match or value}
            elif kind == "priority":
                out[f["fieldId"]] = {"name": value}
            elif kind == "date":
                out[f["fieldId"]] = str(value)[:10]
            else:
                out[f["fieldId"]] = value

        put("change type", self.cfg.get("change_type"))
        put("change risk", self.cfg.get("change_risk"))
        put("impact", self.cfg.get("impact"))
        put("urgency", self.cfg.get("urgency"))
        put("planned start", (window or {}).get("start"))
        put("planned end", (window or {}).get("end"))
        if problems:
            raise JiraError(" ".join(problems))
        return out

    def create(self, summary, description, window=None):
        meta = self.create_meta()
        fields = self.change_fields(meta, window)
        fields.update(self.cfg.get("extra_fields") or {})
        fields.update({"project": {"key": self.cfg["project"]}, "summary": summary[:250], "description": description,
                       "issuetype": {"name": self.cfg["issue_type"]}})
        missing = missing_required(meta, fields)
        if missing:
            raise JiraError(f"Jira needs these fields on a {self.cfg['issue_type']}, which Pegasus doesn't fill in: "
                            f"{'; '.join(missing)}. Add them under Additional fields in Change approval.")
        return self.call("POST", "issue", {"fields": fields})["key"]

    def issue(self, key):
        return self.call("GET", f"issue/{key}", params={"fields": "status,creator,reporter", "expand": "changelog"})

    def approvals(self, key):
        """Jira Service Management approvals on the ticket, or None if the project isn't a service project."""
        try:
            r = self.s.get(f"{self.base}/rest/servicedeskapi/request/{key}/approval", timeout=20)
        except self.req.RequestException:
            return None
        if r.status_code != 200:
            return None
        try:
            return r.json().get("values") or []
        except ValueError:
            return None

    def approval_state(self, key):
        return jira_status(self.cfg, self.issue(key), self.approvals(key))

    def comment(self, key, text):
        self.call("POST", f"issue/{key}/comment", {"body": text})

    def transition(self, key, name):
        if not name:
            return None
        ts = self.call("GET", f"issue/{key}/transitions").get("transitions") or []
        want = name.strip().lower()
        t = next((t for t in ts if t["name"].lower() == want or (t.get("to") or {}).get("name", "").lower() == want), None)
        if not t:
            raise JiraError(f"No '{name}' transition is available on {key} from its current status. "
                            f"Available: {', '.join(x['name'] for x in ts) or 'none'}.")
        self.call("POST", f"issue/{key}/transitions", {"transition": {"id": t["id"]}})
        return t["name"]


def missing_required(meta, fields):
    """Required create fields that are still empty, each with its allowed values when Jira lists them."""
    out = []
    for f in meta.values():
        fid = f.get("fieldId")
        if not f.get("required") or f.get("hasDefaultValue") or fid in fields or fid in ("reporter", "attachment"):
            continue
        allowed = [a.get("value") or a.get("name") for a in f.get("allowedValues") or []][:12]
        out.append(f"{f.get('name')} ({fid}" + (f"; one of {', '.join(a for a in allowed if a)}" if allowed else "") + ")")
    return out


def jira_status(cfg, issue, jsm=None):
    """(state, jira status name, approver name). state: approved, rejected, pending or self_approved.
    jsm: Jira Service Management approvals on the ticket, if it's a service project request."""
    f = issue.get("fields") or {}
    name = (f.get("status") or {}).get("name", "")
    low = name.lower()
    if low in {s.lower() for s in cfg["rejected_statuses"]}:
        return "rejected", name, ""
    raiser = {_who(f.get("creator")), _who(f.get("reporter"))} - {""}
    if jsm:
        # Service Management approval steps decide it: any step still open means pending; the latest
        # completed step's decision counts, and it must have been made by someone other than Pegasus's account.
        if any((a.get("finalDecision") or "pending").lower() == "pending" for a in jsm):
            return "pending", name, ""
        done = sorted(jsm, key=lambda a: ((a.get("completedDate") or {}).get("epochMillis") or 0))
        last = done[-1]
        if (last.get("finalDecision") or "").lower() != "approved":
            return "rejected", name, ""
        yes = [a.get("approver") or {} for a in last.get("approvers") or []
               if (a.get("approverDecision") or "").lower() == "approved"]
        approver = ", ".join(u.get("displayName", "") for u in yes if u.get("displayName"))
        if cfg.get("block_self_approval", True) and (not yes or all(_who(u) in raiser for u in yes)):
            return "self_approved", name, approver
        return "approved", name, approver
    if low not in {s.lower() for s in cfg["approved_statuses"]}:
        return "pending", name, ""
    # Who moved it into the approved status? Newest history entry that set the status to this one.
    approver, approver_id = "", ""
    for hist in reversed((issue.get("changelog") or {}).get("histories") or []):
        if any(it.get("field") == "status" and (it.get("toString") or "").lower() == low for it in hist.get("items") or []):
            approver, approver_id = (hist.get("author") or {}).get("displayName", ""), _who(hist.get("author"))
            break
    if cfg.get("block_self_approval", True):
        if not approver_id or approver_id in raiser:
            return "self_approved", name, approver
    return "approved", name, approver


# ---- stored change requests
def read_crs():
    return read_json(CR_PATH, {})


def update_cr(cr_id, **changes):
    with cr_lock:
        crs = read_crs()
        if cr_id in crs:
            crs[cr_id].update(changes)
            write_json(CR_PATH, crs)
            return crs[cr_id]
    return None


def plan_signature(plan):
    """What an approval covers: every component, update and server in the plan."""
    return sorted(f"{p['component']}|{p['key']}|{p['server']['host']}" for p in plan)


def scope_of(groups, all_mode):
    return "all" if all_mode else f"{groups[0][0]}~{groups[0][1]}"


def refresh_cr(cr, jira=None):
    """Ask Jira for the ticket's current state and store it. Only pending/approved tickets change."""
    if cr["status"] not in ("pending", "approved", "self_approved"):
        return cr
    jira = jira or Jira()
    state, name, approver = jira.approval_state(cr["jira_key"])
    return update_cr(cr["id"], status="pending" if state == "self_approved" else state, approval=state,
                     jira_status=name, approver=approver, checked_at=now()) or cr


def wiki(text):
    return re.sub(r"([{}\[\]|*_^~+\-!#])", r"\\\1", str(text or ""))


def describe_plan(env, plan, notes, who, window=None):
    comps = []
    for comp in dict.fromkeys(p["component"] for p in plan):
        steps = [p for p in plan if p["component"] == comp]
        comps.append((COMP_TITLE[comp], steps[0]["label"], [p["server"]["host"] for p in steps]))
    hosts = list(dict.fromkeys(p["server"]["host"] for p in plan))
    rows = "\n".join(f"|{wiki(c)}|{wiki(v)}|{wiki(', '.join(h))}|" for c, v, h in comps)
    backups = []
    if any(p["component"] == "jdk" for p in plan):
        backups.append("JDK: the old JDK is kept as jdk.bak.<timestamp> next to the new one, and put back automatically if "
                       "the new JDK fails verification.")
    if any(p["component"] == "weblogic" for p in plan):
        backups.append("WebLogic: the WebLogic home is archived to bea.bak.<timestamp>.tar.gz before patching.")
    if any(p["component"] == "dbclient" for p in plan):
        backups.append("Oracle Database Client: the client home is backed up first, and the previous OPatch is kept "
                       "as OPatch.bak.<timestamp>.")
    if any(p["component"] == "tuxedo" for p in plan):
        backups.append("Tuxedo: the Tuxedo home is backed up before the rolling patch.")
    return "\n".join([
        "h3. What will change",
        "||Component||Update||Servers||",
        rows,
        "",
        "h3. Impact",
        f"{wiki(env['name'])} is unavailable for the whole window. Pegasus stops every domain (web, process scheduler, "
        f"app server), confirms no WebLogic or Tuxedo processes are left, patches the servers one at a time, then "
        f"starts every domain again and checks status. Servers affected: {wiki(', '.join(hosts))}.",
        "",
        "h3. Backout",
        *[f"* {wiki(b)}" for b in backups],
        "* If a server fails, the remaining servers are left alone and all domains are started again. The failing "
        "step and backup location are reported back on this ticket.",
        "",
        "h3. Request",
        f"* Environment: {wiki(env['name'])} ({wiki(env.get('client') or 'no client set')}, tier "
        f"{wiki(env.get('tier') or 'not set')})",
        f"* Requested in Pegasus by {wiki(who)} on {now()}",
        *([f"* Planned window: {wiki((window or {}).get('start') or 'not set')} to {wiki((window or {}).get('end') or 'not set')}"]
          if (window or {}).get("start") or (window or {}).get("end") else []),
        *([f"* Notes: {wiki(notes)}"] if notes else []),
        "",
        "{panel}Pegasus applies exactly this plan once, and only after this ticket is approved by someone other than "
        "the account that raised it. If the plan changes before then, Pegasus asks for a new ticket.{panel}",
    ])


def find_env(name):
    return {env_key(e["name"]): e for e in group(read_rows())}.get(env_key(name))


@app.get("/api/jira")
def get_jira():
    c = jira_cfg()
    return jsonify(config=c, has_token=bool(jira_token()), token_from_env=bool(os.environ.get("PSDASH_JIRA_TOKEN")),
                   secure_store=_keyring() is not None)


@app.put("/api/jira")
def put_jira():
    body = request.get_json(silent=True) or {}
    c = jira_cfg()
    problems = []
    url = str(body.get("url", c["url"]) or "").strip().rstrip("/")
    if url and not re.match(r"^https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?$", url):
        problems.append("The Jira URL should look like https://yourcompany.atlassian.net.")
    project = str(body.get("project", c["project"]) or "").strip().upper()
    if project and not re.match(r"^[A-Z][A-Z0-9_]{1,19}$", project):
        problems.append("The project key should look like CHG or PSOPS.")
    deployment = body.get("deployment", c["deployment"])
    if deployment not in ("cloud", "datacenter"):
        problems.append("Choose Jira Cloud or Jira Data Center.")
    require = body.get("require", c["require"])
    if require not in ("all", "prd"):
        problems.append("Choose whether approval is needed for every environment or production only.")

    def names(key):
        v = body.get(key, c[key])
        v = v if isinstance(v, list) else re.split(r"\s*,\s*", str(v or ""))
        return [x.strip()[:60] for x in v if x and x.strip()]

    extra = body.get("extra_fields", c["extra_fields"])
    if isinstance(extra, str):
        try:
            extra = json.loads(extra) if extra.strip() else {}
        except ValueError:
            problems.append("Additional fields must be JSON, e.g. {\"labels\": [\"pegasus\"]}.")
            extra = c["extra_fields"]
    if not isinstance(extra, dict):
        problems.append("Additional fields must be a JSON object.")
        extra = c["extra_fields"]
    approved = names("approved_statuses")
    enabled = bool(body.get("enabled", c["enabled"]))
    if enabled and not approved:
        problems.append("List at least one status that means approved.")
    new = {"enabled": enabled, "require": require, "url": url, "deployment": deployment,
           "user": str(body.get("user", c["user"]) or "").strip()[:120], "project": project,
           "issue_type": str(body.get("issue_type", c["issue_type"]) or "Change").strip()[:60],
           "change_type": str(body.get("change_type", c["change_type"]) or "").strip()[:40],
           "change_risk": str(body.get("change_risk", c["change_risk"]) or "").strip()[:40],
           "impact": str(body.get("impact", c["impact"]) or "").strip()[:40],
           "urgency": str(body.get("urgency", c["urgency"]) or "").strip()[:40],
           "submit_transition": str(body.get("submit_transition", c["submit_transition"]) or "").strip()[:60],
           "approved_statuses": approved, "rejected_statuses": names("rejected_statuses"),
           "start_transition": str(body.get("start_transition", c["start_transition"]) or "").strip()[:60],
           "done_transition": str(body.get("done_transition", c["done_transition"]) or "").strip()[:60],
           "extra_fields": extra, "block_self_approval": bool(body.get("block_self_approval", c["block_self_approval"]))}
    if enabled and not (new["url"] and new["project"] and (deployment == "datacenter" or new["user"])):
        problems.append("Fill in the Jira URL, project key and (for Jira Cloud) the account email before switching "
                        "approval on.")
    note = None
    token = (body.get("token") or "").strip()
    if enabled and not (token or jira_token()):
        problems.append("Add the Jira API token before switching approval on.")
    if problems:
        return jsonify(error=" ".join(problems)), 400
    if token:
        if secret_set(JIRA_TOKEN_NAME, token):
            jira_token_mem.pop("token", None)
        else:
            jira_token_mem["token"] = token
            note = "No secure credential store on this machine, so the token is kept in memory until Pegasus restarts."
    s = settings()
    s["jira"] = new
    write_json(SETTINGS_PATH, s)
    audit({"time": now(), "who": session.get("who"), "event": "update_jira_settings", "enabled": enabled,
           "require": require, "project": project})
    return jsonify(config=new, has_token=bool(jira_token()), note=note)


@app.delete("/api/jira/token")
def forget_jira_token():
    secret_set(JIRA_TOKEN_NAME, "")
    jira_token_mem.pop("token", None)
    audit({"time": now(), "who": session.get("who"), "event": "forget_jira_token"})
    return jsonify(ok=True, has_token=bool(jira_token()))


@app.post("/api/jira/test")
def test_jira():
    try:
        j = Jira()
        me = j.myself()
        proj = j.project()
    except JiraError as e:
        return jsonify(error=str(e)), 400
    types = [t["name"] for t in proj.get("issueTypes") or []]
    warn, filled = None, []
    try:
        meta = j.create_meta()
        test_window = {"start": "2030-01-01T20:00:00.000+0000", "end": "2030-01-01T23:00:00.000+0000"}
        fields = j.change_fields(meta, test_window)
        filled = [f["name"] for f in meta.values() if f.get("fieldId") in fields]
        fields.update(j.cfg.get("extra_fields") or {})
        fields.update({"project": 1, "summary": 1, "description": 1, "issuetype": 1})
        missing = missing_required(meta, fields)
        if missing:
            warn = (f"A {j.cfg['issue_type']} in this project also needs: {'; '.join(missing)}. "
                    "Add them under Additional fields, or Request approval will fail.")
    except JiraError as e:
        warn = str(e)
    return jsonify(ok=True, user=me.get("displayName") or me.get("name"), project=proj.get("name"),
                   issue_types=types, filled=filled, warning=warn)


@app.get("/api/change-requests")
def list_crs():
    env = find_env(request.args.get("environment"))
    if not env:
        return jsonify(error="Environment not found."), 404
    with cr_lock:
        mine = [c for c in read_crs().values() if env_key(c["environment"]) == env_key(env["name"])]
    mine.sort(key=lambda c: c["requested_at"], reverse=True)
    latest = {}
    for c in mine:                      # newest ticket per scope
        latest.setdefault(c["scope"], c)
    error = None
    if request.args.get("refresh") and jira_cfg()["enabled"]:
        try:
            jira = None
            for scope, c in latest.items():
                if c["status"] in ("pending", "approved"):
                    jira = jira or Jira()
                    latest[scope] = refresh_cr(c, jira)
        except JiraError as e:
            error = str(e)
    return jsonify(required=approval_required(env), enabled=jira_cfg()["enabled"], requests=list(latest.values()),
                   error=error)


@app.post("/api/change-requests")
def create_cr():
    body = request.get_json(silent=True) or {}
    env = find_env(body.get("environment"))
    if not env:
        return jsonify(error="Environment not found."), 404
    if not jira_cfg()["enabled"]:
        return jsonify(error="Change approval isn't switched on."), 400
    scope = body.get("scope") or ""
    if scope == "all":
        groups, err = outstanding_groups(env)
        if err:
            return jsonify(error=err), 400
    else:
        comp, _, key = scope.partition("~")
        if comp not in COMPONENTS or not key:
            return jsonify(error="Choose an update to request approval for."), 400
        groups = [(comp, key)]
    plan, missing, err = build_apply_plan(env, groups)
    if err:
        return jsonify(error=err), 400
    if missing:
        return jsonify(error="Download these first, so the ticket shows exactly what will be applied: "
                       + ", ".join(missing)), 409
    if not plan:
        return jsonify(error="Nothing needs applying. Check patch levels again."), 400
    sig = plan_signature(plan)
    scope = scope_of(groups, scope == "all")
    with cr_lock:
        for c in read_crs().values():
            if (env_key(c["environment"]) == env_key(env["name"]) and c["scope"] == scope and c["status"] in CR_OPEN
                    and c["signature"] == sig):
                return jsonify(error=f"{c['jira_key']} already covers this update.", request=c), 409
    notes = str(body.get("notes") or "").strip()[:2000]
    who = session.get("who") or "admin"
    window = {}
    for k in ("start", "end"):
        v = str((body.get("window") or {}).get(k) or "").strip()
        if v and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{3})?)?[+-]\d{4}$", v):
            return jsonify(error="The planned window dates aren't in a format Jira accepts."), 400
        window[k] = v
    if window.get("start") and window.get("end") and window["end"] <= window["start"]:
        return jsonify(error="The planned end must be after the planned start."), 400
    change_type = str(body.get("change_type") or "").strip()[:40]
    comps = []
    for comp in dict.fromkeys(p["component"] for p in plan):
        comps.append(f"{COMP_TITLE[comp]} {next(p['label'] for p in plan if p['component'] == comp)}")
    summary = f"[Pegasus] {env['name']}: apply {', '.join(comps)}"
    try:
        cfg = jira_cfg()
        if change_type:
            cfg["change_type"] = change_type
        jira = Jira(cfg)
        key = jira.create(summary, describe_plan(env, plan, notes, who, window), window)
    except JiraError as e:
        return jsonify(error=str(e)), 502
    submit_note = None
    try:
        jira.transition(key, jira.cfg["submit_transition"])
    except JiraError as e:
        submit_note = f"{key} was created, but Pegasus couldn't send it for approval: {e}"
    cr = {"id": uuid.uuid4().hex[:12], "jira_key": key, "url": jira.browse(key), "environment": env["name"],
          "scope": scope, "groups": [list(g) for g in groups], "signature": sig, "summary": summary,
          "hosts": list(dict.fromkeys(p["server"]["host"] for p in plan)), "notes": notes, "requested_by": who,
          "window": window, "change_type": jira.cfg.get("change_type") or "",
          "requested_at": now(), "status": "pending", "approval": "pending", "jira_status": "", "approver": "",
          "checked_at": None, "job": None, "finished_at": None}
    with cr_lock:
        crs = read_crs()
        # anything older for the same scope that hasn't been used is superseded by this ticket
        for c in crs.values():
            if env_key(c["environment"]) == env_key(env["name"]) and c["scope"] == scope and c["status"] in ("pending", "approved"):
                c["status"] = "superseded"
        crs[cr["id"]] = cr
        write_json(CR_PATH, crs)
    try:
        refresh_cr(cr, jira)
    except JiraError:
        pass
    audit({"time": now(), "who": who, "event": "change_request", "environment": env["name"], "target": key,
           "action": summary})
    return jsonify(request=read_crs().get(cr["id"], cr), note=submit_note)


@app.post("/api/change-requests/<cr_id>/withdraw")
def withdraw_cr(cr_id):
    c = read_crs().get(cr_id)
    if not c:
        return jsonify(error="That change request doesn't exist."), 404
    if c["status"] not in ("pending", "approved"):
        return jsonify(error=f"{c['jira_key']} can't be withdrawn now ({c['status']})."), 409
    update_cr(cr_id, status="withdrawn", finished_at=now())
    try:
        Jira().comment(c["jira_key"], f"Withdrawn in Pegasus by {session.get('who') or 'admin'} on {now()}. "
                                      "Pegasus won't apply this plan under this ticket.")
    except JiraError:
        pass
    audit({"time": now(), "who": session.get("who"), "event": "withdraw_change_request",
           "environment": c["environment"], "target": c["jira_key"]})
    return jsonify(ok=True)


def claim_approval(env, cr_id, plan):
    """Check, at the moment of applying, that an approved ticket covers exactly this plan, then mark it used.
    Returns (change request, None) or (None, error message)."""
    if not cr_id:
        return None, (f"{env['name']} needs an approved Jira ticket before it can be patched. "
                      "Use Request approval first.")
    with cr_lock:
        c = read_crs().get(str(cr_id))
        if not c or env_key(c["environment"]) != env_key(env["name"]):
            return None, "That change request isn't for this environment."
        if c["status"] in ("applying", "applied", "failed"):
            return None, f"{c['jira_key']} has already been used for an apply. Request approval again."
        if c["status"] not in ("pending", "approved"):
            return None, f"{c['jira_key']} is {c['status'].replace('_', ' ')}. Request approval again."
        if c["signature"] != plan_signature(plan):
            c["status"] = "stale"
            crs = read_crs()
            crs[c["id"]] = c
            write_json(CR_PATH, crs)
            return None, (f"The patch plan has changed since {c['jira_key']} was raised (different updates or servers), "
                          "so that approval doesn't cover it. Request approval again.")
        try:
            jira = Jira()
            state, name, approver = jira.approval_state(c["jira_key"])
        except JiraError as e:
            return None, f"Couldn't confirm the approval of {c['jira_key']} with Jira: {e}"
        c.update(jira_status=name, approver=approver, checked_at=now(), approval=state)
        if state == "approved":
            c["status"] = "applying"
        elif state == "rejected":
            c["status"] = "rejected"
        crs = read_crs()
        crs[c["id"]] = c
        write_json(CR_PATH, crs)
    if state == "approved":
        return c, None
    if state == "self_approved":
        return None, (f"{c['jira_key']} was approved by the account Pegasus uses to raise tickets, or Pegasus can't "
                      "tell who approved it. It needs approval from someone else.")
    if state == "rejected":
        return None, f"{c['jira_key']} was declined in Jira (status: {name or 'unknown'}). Nothing was applied."
    return None, f"{c['jira_key']} isn't approved yet (status: {name or 'unknown'})."


def run_apply_with_approval(job_id, env, plan, creds, passphrase, cr_id):
    c = read_crs().get(cr_id) if cr_id else None
    if c:
        try:
            jira = Jira()
            jira.comment(c["jira_key"], f"Pegasus started applying this change on {now()} "
                                        f"(job {job_id}, by {jobs[job_id].get('who') or 'admin'}). "
                                        f"Approved by {c.get('approver') or 'unknown'}.")
            jira.transition(c["jira_key"], jira.cfg["start_transition"])
        except JiraError as e:
            audit({"time": now(), "event": "jira_update_failed", "target": c["jira_key"], "error": str(e)})
    try:
        run_apply_job(job_id, env, plan, creds, passphrase)
    finally:
        if c:
            report_to_jira(c, job_id)


def report_to_jira(c, job_id):
    job = jobs.get(job_id) or {}
    ok = job.get("status") == "succeeded"
    update_cr(c["id"], status="applied" if ok else "failed", finished_at=now())
    lines = "".join(job.get("output") or []).splitlines()
    tail = "\n".join(lines[-40:])
    text = (f"Pegasus finished applying on {now()}: *{'SUCCEEDED' if ok else 'FAILED'}*.\n"
            f"Job {job_id}. The full log is in Pegasus under Activity.\n\n"
            "{noformat}\n" + tail.replace("{noformat}", "{ noformat}") + "\n{noformat}")
    try:
        jira = Jira()
        jira.comment(c["jira_key"], text)
        if ok:
            jira.transition(c["jira_key"], jira.cfg["done_transition"])
    except JiraError as e:
        audit({"time": now(), "event": "jira_update_failed", "target": c["jira_key"], "error": str(e)})


# ---------------------------------------------------------------- SSH access (users' public keys)
# Adds, checks or removes a person's SSH public key in an account's authorized_keys on every server of the chosen
# environments, over the same SSH connection Pegasus uses for everything else. By default the account is the SSH user
# itself (opc on OCI); another account (e.g. psadm1) is reached with `sudo -n -iu`, like the PeopleSoft commands.
# Keys added here are kept in data/access_keys.json, so they can be checked or removed later in one click.
ACCESS_PATH = DATA_DIR / "access_keys.json"
access_lock = threading.Lock()
access_running = set()
KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
PUBKEY_RE = re.compile(r"^(\S+) ([A-Za-z0-9+/]+={0,3})(?: (.*))?$")


def parse_pubkey(text):
    """Validate one OpenSSH public key line. Returns (key dict, None) or (None, error)."""
    text = (text or "").replace("\r", "").strip()
    if "PRIVATE KEY" in text:
        return None, "That's a private key. Never share it. Ask the person for their public key (the .pub file)."
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return None, "Paste the public key, or choose the .pub file."
    if lines[0].startswith("---- BEGIN SSH2 PUBLIC KEY"):
        return None, ("That's a PuTTY/SSH2-format key. Convert it to OpenSSH format first: in PuTTYgen, load the key and "
                      "copy the box 'Public key for pasting into OpenSSH authorized_keys file'.")
    if len(lines) > 1:
        joined = "".join(lines)
        if PUBKEY_RE.match(lines[0]) and not PUBKEY_RE.match(joined):
            return None, "Paste one key at a time."
        lines = [joined]          # a single key that was wrapped across lines when it was pasted
    if re.match(r"^(from|command|environment|permitopen|permitlisten|principals|tunnel|no-|restrict|cert-authority)", lines[0]):
        return None, "Paste the key without authorized_keys options (from=, command= and so on)."
    m = PUBKEY_RE.match(re.sub(r"\s+", " ", lines[0]))
    if not m:
        return None, "That doesn't look like an OpenSSH public key (it should start with ssh-ed25519, ssh-rsa or ecdsa-)."
    kind, b64, comment = m.group(1), m.group(2), (m.group(3) or "").strip()
    if kind not in KEY_TYPES:
        return None, f"'{kind[:40]}' isn't a supported key type. Use ssh-ed25519, ssh-rsa or ecdsa."
    try:
        blob = base64.b64decode(b64, validate=True)
        parts, i = [], 0               # the key is a run of length-prefixed fields that must use up every byte
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
  awk -v b="$BODY" '{k=1; for(i=1;i<=NF;i++) if($i==b) k=0} k' "$AK" > "$AK.psdash.tmp" && cat "$AK.psdash.tmp" > "$AK"
  rm -f "$AK.psdash.tmp"
  if has_key; then echo "RESULT:FAILED the key is still in the file"; else echo "RESULT:REMOVED"; fi ;;
esac
'''


def access_command(account, ssh_user):
    if account and account != ssh_user:
        return f"sudo -n -iu {shlex.quote(account)} bash -s"
    return "bash -s"


def read_access():
    return read_json(ACCESS_PATH, {})


def access_record_id(fp, account):
    return f"{fp}|{account or ''}"


def access_targets(env_names, hosts=None):
    """Unique servers across the chosen environments: [(environment name, server)]."""
    envs = {env_key(e["name"]): e for e in group(read_rows())}
    out, seen, unknown = [], set(), []
    for n in env_names:
        e = envs.get(env_key(n))
        if not e:
            unknown.append(str(n))
            continue
        for s in env_hosts(e):
            target = s["ip"] or s["host"]
            if hosts and target not in hosts and s["host"] not in hosts:
                continue
            k = (target, s.get("ssh_user"), s.get("ssh_key"), s.get("ssh_port"))
            if k in seen:
                continue
            seen.add(k)
            out.append((e, s))
    return out, unknown


def run_access_job(job_id, mode, key, account, targets, creds, passphrase, note):
    log = JobLog(job_id)
    word = {"add": "Adding", "remove": "Removing", "check": "Checking for"}[mode]
    log(f"=== {word} {key['type']} key {key['fingerprint']}"
        + (f" ({key['comment']})" if key["comment"] else "") + "\n")
    log(f"    Account: {account or 'the SSH user on each server'}\n")
    if note:
        log(f"    Note: {note}\n")
    log(f"    Servers: {len(targets)}\n\n")
    script = (f"MODE={shlex.quote(mode)}\nKEY={shlex.quote(key['line'])}\nBODY={shlex.quote(key['body'])}\n"
              + ACCESS_SCRIPT)
    results, ok = [], True
    for env, s in targets:
        target = s["ip"] or s["host"]
        label = f"{s['host'] or target} ({target})" if s["host"] and s["host"] != target else target
        try:
            client, user = ssh_client(s, creds, passphrase)
            try:
                code, out = run_remote(client, access_command(account, user), stdin_text=script, timeout=60)
            finally:
                client.close()
            m = re.findall(r"RESULT:([A-Z_]+)(.*)", out)
            acct = (re.findall(r"ACCOUNT:(\S+)", out) or [account or user])[-1]
            if not m:
                hint = ""
                if "sudo" in out and ("password" in out or "not allowed" in out or "a terminal" in out):
                    hint = f" (needs a passwordless sudo rule: {user} ALL=({account}) NOPASSWD: ALL)"
                raise RuntimeError((out.strip().splitlines() or ["no output"])[-1][:200] + hint)
            result, detail = m[-1][0], m[-1][1].strip()
            if result == "FAILED":
                ok = False
            results.append({"environment": env["name"], "host": s["host"], "ip": target, "account": acct,
                            "result": result})
            log(f"{label:<44} {acct:<10} {result.replace('_', ' ').lower()}{(': ' + detail) if detail else ''}\n")
        except Exception as e:
            ok = False
            results.append({"environment": env["name"], "host": s["host"], "ip": target, "account": account,
                            "result": "ERROR", "error": str(e)[:200]})
            log(f"{label:<44} {'':<10} couldn't connect or run: {e}\n")
    record_access(mode, key, account, results, note, jobs[job_id].get("who") or "admin")
    counts = {}
    for r in results:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    log("\n=== " + ", ".join(f"{v} {k.replace('_', ' ').lower()}" for k, v in sorted(counts.items())) + "\n")
    with access_lock:
        access_running.discard(key["fingerprint"])
    log.finish(ok, {"fingerprint": key["fingerprint"], "comment": key["comment"], "account": account or "",
                    "results": counts})


def record_access(mode, key, account, results, note, who):
    """Keep the register of keys Pegasus has put on servers in step with what was found. A check only updates keys
    that are already in the register; it never adds one."""
    with access_lock:
        data = read_access()
        rid = access_record_id(key["fingerprint"], account)
        if mode == "check" and rid not in data:
            return
        rec = data.get(rid) or {"fingerprint": key["fingerprint"], "type": key["type"], "comment": key["comment"],
                                "line": key["line"], "account": account or "", "added_by": who,
                                "added_at": now(), "note": note, "servers": {}}
        for r in results:
            if r["result"] in ("ADDED", "EXISTS", "PRESENT"):
                prev = rec["servers"].get(r["ip"], {})
                rec["servers"][r["ip"]] = {"host": r["host"], "environment": r["environment"], "account": r["account"],
                                           "since": prev.get("since") or now()}
            elif r["result"] in ("REMOVED", "NOT_PRESENT", "ABSENT"):
                rec["servers"].pop(r["ip"], None)
        if rec["servers"]:
            rec["updated_at"] = now()
            if mode == "add" and note:
                rec["note"] = note
            data[rid] = rec
        else:
            data.pop(rid, None)
        write_json(ACCESS_PATH, data)


@app.post("/api/access/parse")
def access_parse():
    key, err = parse_pubkey((request.get_json(silent=True) or {}).get("key"))
    if err:
        return jsonify(error=err), 400
    rec = [r for r in read_access().values() if r["fingerprint"] == key["fingerprint"]]
    return jsonify(type=key["type"], bits=key["bits"], comment=key["comment"], fingerprint=key["fingerprint"],
                   known=[{"account": r["account"], "servers": len(r["servers"])} for r in rec])


@app.get("/api/access")
def access_list():
    recs = sorted(read_access().values(), key=lambda r: r.get("updated_at") or r["added_at"], reverse=True)
    out = []
    for r in recs:
        envs = sorted({s["environment"] for s in r["servers"].values()})
        out.append({k: r[k] for k in ("fingerprint", "type", "comment", "account", "added_by", "added_at", "note")}
                   | {"id": access_record_id(r["fingerprint"], r["account"]), "environments": envs,
                      "servers": sorted(s["host"] or ip for ip, s in r["servers"].items()),
                      "updated_at": r.get("updated_at")})
    return jsonify(keys=out)


@app.post("/api/access/run")
def access_run():
    body = request.get_json(silent=True) or {}
    mode = body.get("action")
    if mode not in ("add", "remove", "check"):
        return jsonify(error="Choose add, remove or check."), 400
    creds = session.get("ssh")
    if not creds:
        return jsonify(error="Set your SSH user ID and private key path first.", need_credentials=True), 409
    account = str(body.get("account") or "").strip()
    if account and not SAFE_NAME.match(account):
        return jsonify(error="The account name can only use letters, digits, . _ and -."), 400
    if account == "root":
        return jsonify(error="Pegasus doesn't add keys for root. Use opc (or another sudo user) instead."), 400
    note = str(body.get("note") or "").strip()[:300]
    hosts = None
    if body.get("record"):                 # check or remove a key from the register, on the servers it's recorded on
        rec = read_access().get(str(body["record"]))
        if not rec:
            return jsonify(error="That key isn't in the register any more."), 404
        key, _ = parse_pubkey(rec["line"])
        account = rec["account"]
        env_names = sorted({s["environment"] for s in rec["servers"].values()})
        hosts = set(rec["servers"])
    else:
        key, err = parse_pubkey(body.get("key"))
        if err:
            return jsonify(error=err), 400
        env_names = [str(n) for n in body.get("environments") or []]
    if not env_names:
        return jsonify(error="Choose at least one environment."), 400
    targets, unknown = access_targets(env_names, hosts)
    if unknown:
        return jsonify(error="Not in the inventory: " + ", ".join(unknown)), 404
    if not targets:
        return jsonify(error="None of those servers are in the inventory any more."), 400
    if mode != "check":
        prd = sorted({e["name"] for e, _ in targets if is_prd(e["tier"])})
        if prd:
            expected = prd[0] if len(prd) == 1 else "PRODUCTION"
            if env_key(body.get("confirm")) != env_key(expected):
                return jsonify(error=f"Type {expected} to confirm.", need_confirm=True, expected=expected,
                               prd=prd), 409
    with access_lock:
        if key["fingerprint"] in access_running:
            return jsonify(error="That key is already being changed. Wait for it to finish."), 409
        access_running.add(key["fingerprint"])
    names = sorted({e["name"] for e, _ in targets})
    who = (key["comment"] or key["fingerprint"][:20])
    job_id = new_job("ssh_access", ", ".join(names), f"{mode} SSH key {who}"
                     + (f" for {account}" if account else ""), f"{len(targets)} servers")
    threading.Thread(target=run_access_job, args=(job_id, mode, key, account, targets, creds,
                                                  passphrases.get(session.get("token")), note), daemon=True).start()
    return jsonify(job=job_id, servers=len(targets), environments=names)


# ---------------------------------------------------------------- page
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    if not PASSWORD:
        raise SystemExit("Set PSDASH_PASSWORD before starting, e.g.  export PSDASH_PASSWORD='choose-a-strong-one'")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not CSV_PATH.exists():
        write_rows([])
    print(f"Pegasus is running on http://{HOST}:{PORT}  (inventory: {CSV_PATH})")
    app.run(host=HOST, port=PORT, threaded=True)
