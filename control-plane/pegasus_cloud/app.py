"""Pegasus control plane (milestone 1).

Hosted web app and job queue. Clients' connectors call in over HTTPS; this service never connects to a client.

* Clients (tenants), their connectors, their server inventory and jobs live in a SQLite database for now
  (milestone 2 moves to a managed database and adds per-user SSO and roles).
* Every job handed to a connector is signed with this service's Ed25519 key (protocol.py).
"""
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory, session

from . import __version__, protocol

DATA_DIR = Path(os.environ.get("PEGASUS_DATA", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = DATA_DIR / "pegasus.db"
KEY_PATH = DATA_DIR / "signing_key.pem"
ADMIN_PASSWORD = os.environ.get("PEGASUS_ADMIN_PASSWORD", "")
PUBLIC_URL = os.environ.get("PEGASUS_PUBLIC_URL", "")
# true: the web page and admin API answer only requests made on this machine directly; anything arriving through a
# tunnel or proxy (which adds forwarding headers) can reach the connector API only.
ADMIN_LOCAL_ONLY = os.environ.get("PEGASUS_ADMIN_LOCAL_ONLY", "false").lower() == "true"
FORWARD_HEADERS = ("X-Forwarded-For", "Cf-Connecting-Ip", "X-Real-Ip", "Forwarded", "Cf-Ray")
TOKEN_TTL = 24 * 3600          # registration tokens
QUEUE_TTL = 15 * 60            # a queued job nobody picks up within this expires
SIGNED_TTL = 10 * 60           # a connector must receive a signed job within this window
ONLINE_WINDOW = 90             # seconds since last contact to count as online
LOST_AFTER = 10 * 60           # a running job whose connector has been silent this long is marked failed

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./~\-]{1,255}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")
ROLES = ("app", "prcs", "web")
START_ORDER, STOP_ORDER = ["app", "prcs", "web"], ["web", "prcs", "app"]
SERVER_COLS = ["environment", "tier", "host", "ip", "role", "os_user", "domain", "env_script", "ssh_port"]

app = Flask(__name__, static_folder="static")
app.secret_key = os.environ.get("PEGASUS_SECRET") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
                  SESSION_COOKIE_SECURE=os.environ.get("PEGASUS_COOKIE_SECURE", "true").lower() != "false",
                  MAX_CONTENT_LENGTH=2 * 1024 * 1024)
_key_lock = threading.Lock()
_signing_key = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS reg_tokens (token_hash TEXT PRIMARY KEY, client_id TEXT NOT NULL, created_by TEXT,
  created_at REAL NOT NULL, expires_at REAL NOT NULL, used_at REAL, connector_id TEXT);
CREATE TABLE IF NOT EXISTS connectors (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, name TEXT, hostname TEXT,
  version TEXT, platform TEXT, secret_hash TEXT NOT NULL, created_at REAL NOT NULL, last_seen REAL,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS servers (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL,
  environment TEXT NOT NULL, tier TEXT, host TEXT, ip TEXT, role TEXT, os_user TEXT, domain TEXT,
  env_script TEXT, ssh_port INTEGER);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, environment TEXT, title TEXT,
  params TEXT NOT NULL, status TEXT NOT NULL, connector_id TEXT, created_by TEXT, created_at REAL NOT NULL,
  claimed_at REAL, finished_at REAL, expires_at REAL NOT NULL, results TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS job_events (job_id TEXT NOT NULL, seq INTEGER NOT NULL, text TEXT, at REAL NOT NULL,
  PRIMARY KEY (job_id, seq));
CREATE INDEX IF NOT EXISTS jobs_queue ON jobs (client_id, status, created_at);
"""


# ---------------------------------------------------------------- storage
def db():
    if "db" not in g:
        g.db = connect()
    return g.db


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=30000")
    return c


@app.teardown_appcontext
def close_db(_):
    c = g.pop("db", None)
    if c is not None:
        c.close()


def init_db():
    c = connect()
    c.executescript(SCHEMA)
    c.close()


def signing_key():
    """This service's Ed25519 signing key, created on first start. (Production: keep it in OCI Vault.)"""
    global _signing_key
    with _key_lock:
        if _signing_key is None:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            if KEY_PATH.exists():
                _signing_key = protocol.load_private_key(KEY_PATH.read_text())
            else:
                _signing_key = protocol.new_private_key()
                fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(protocol.private_key_pem(_signing_key))
        return _signing_key


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds") if t else None


def row(r):
    return dict(r) if r else None


# ---------------------------------------------------------------- admin auth (milestone 2: per-user SSO + roles)
def is_local_request():
    return request.remote_addr in ("127.0.0.1", "::1") and not any(h in request.headers for h in FORWARD_HEADERS)


@app.before_request
def guard():
    p = request.path
    if p.startswith("/api/connector/"):
        return None
    if ADMIN_LOCAL_ONLY and not is_local_request():
        return jsonify(error="Not found."), 404
    if p.startswith("/api/") and p not in ("/api/login", "/api/session"):
        if not session.get("auth"):
            return jsonify(error="Sign in first."), 401
        if request.method != "GET" and request.headers.get("X-Requested-With") != "pegasus":
            return jsonify(error="Bad request origin."), 400
    return None


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    if not ADMIN_PASSWORD or not hmac.compare_digest(str(body.get("password", "")).encode(), ADMIN_PASSWORD.encode()):
        time.sleep(1.5)
        return jsonify(error="Wrong password."), 401
    session.clear()
    session.update(auth=True, who=(str(body.get("name") or "").strip()[:40] or "admin"))
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/session")
def session_info():
    return jsonify(auth=bool(session.get("auth")), who=session.get("who"), version=__version__,
                   signing_key=protocol.fingerprint(protocol.public_key_b64(signing_key())))


def who():
    return session.get("who") or "admin"


# ---------------------------------------------------------------- clients, tokens, connectors
def connector_view(c, now=None):
    now = now or time.time()
    online = bool(c["last_seen"] and now - c["last_seen"] < ONLINE_WINDOW and not c["revoked"])
    return {"id": c["id"], "name": c["name"], "hostname": c["hostname"], "version": c["version"],
            "platform": c["platform"], "last_seen": iso(c["last_seen"]), "online": online,
            "revoked": bool(c["revoked"]), "created_at": iso(c["created_at"])}


@app.get("/api/clients")
def list_clients():
    now = time.time()
    out = []
    for c in db().execute("SELECT * FROM clients ORDER BY name COLLATE NOCASE"):
        cons = db().execute("SELECT * FROM connectors WHERE client_id=? AND revoked=0", (c["id"],)).fetchall()
        envs = db().execute("SELECT COUNT(DISTINCT environment) n FROM servers WHERE client_id=?", (c["id"],)).fetchone()
        out.append({"id": c["id"], "name": c["name"], "environments": envs["n"],
                    "connectors": len(cons), "online": sum(connector_view(x, now)["online"] for x in cons)})
    return jsonify(clients=out)


@app.post("/api/clients")
def create_client():
    name = str((request.get_json(silent=True) or {}).get("name") or "").strip()
    if not 1 <= len(name) <= 80:
        return jsonify(error="Enter the client's name."), 400
    cid = "c_" + uuid.uuid4().hex[:12]
    db().execute("INSERT INTO clients VALUES (?,?,?)", (cid, name, time.time()))
    return jsonify(id=cid, name=name)


def get_client(cid):
    c = db().execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    if not c:
        from flask import abort
        abort(404)
    return c


@app.get("/api/clients/<cid>")
def client_detail(cid):
    c = get_client(cid)
    expire_stale(cid)
    now = time.time()
    cons = [connector_view(x, now) for x in
            db().execute("SELECT * FROM connectors WHERE client_id=? AND revoked=0 ORDER BY created_at", (cid,))]
    servers = [row(s) for s in db().execute(
        "SELECT * FROM servers WHERE client_id=? ORDER BY environment COLLATE NOCASE, id", (cid,))]
    envs = {}
    for s in servers:
        e = envs.setdefault(s["environment"], {"name": s["environment"], "tier": s["tier"] or "", "servers": []})
        e["tier"] = e["tier"] or s["tier"] or ""
        e["servers"].append(s)
    return jsonify(id=c["id"], name=c["name"], connectors=cons, environments=list(envs.values()),
                   jobs=recent_jobs(cid))


@app.post("/api/clients/<cid>/tokens")
def create_token(cid):
    get_client(cid)
    token = "pgr_" + secrets.token_urlsafe(24)
    now = time.time()
    db().execute("INSERT INTO reg_tokens (token_hash, client_id, created_by, created_at, expires_at) VALUES (?,?,?,?,?)",
                 (sha(token), cid, who(), now, now + TOKEN_TTL))
    url = PUBLIC_URL or request.host_url.rstrip("/")
    return jsonify(token=token, expires_at=iso(now + TOKEN_TTL), url=url,
                   fingerprint=protocol.fingerprint(protocol.public_key_b64(signing_key())),
                   command=f"python -m pegasus_connector register --url {url} --token {token} "
                           f"--ssh-user opc --ssh-key /home/opc/.ssh/id_rsa")


@app.delete("/api/connectors/<con_id>")
def revoke_connector(con_id):
    r = db().execute("UPDATE connectors SET revoked=1 WHERE id=?", (con_id,))
    if not r.rowcount:
        return jsonify(error="No such connector."), 404
    db().execute("UPDATE jobs SET status='failed', finished_at=?, note='connector removed' "
                 "WHERE connector_id=? AND status='running'", (time.time(), con_id))
    return jsonify(ok=True)


# ---------------------------------------------------------------- inventory
def parse_inventory(text):
    rows, problems = [], []
    reader = csv.DictReader(io.StringIO(text.strip()))
    if not reader.fieldnames:
        return [], ["Paste a CSV with a header row."]
    fields = [f.strip().lower() for f in reader.fieldnames]
    missing = [c for c in ("environment", "host", "role") if c not in fields]
    if missing:
        return [], [f"Missing column(s): {', '.join(missing)}."]
    for n, r in enumerate(reader, start=2):
        r = {k.strip().lower(): (v or "").strip() for k, v in r.items() if k}
        if not any(r.values()):
            continue
        s = {c: r.get(c, "") for c in SERVER_COLS}
        s["role"] = s["role"].lower()
        if not SAFE_NAME.match(s["environment"]):
            problems.append(f"Line {n}: environment name has unexpected characters.")
        if not SAFE_HOST.match(s["host"]) or (s["ip"] and not SAFE_HOST.match(s["ip"])):
            problems.append(f"Line {n}: host or IP has unexpected characters.")
        if s["role"] not in ROLES:
            problems.append(f"Line {n}: role must be app, prcs or web.")
        for k, rx in (("os_user", SAFE_NAME), ("domain", SAFE_NAME), ("env_script", SAFE_PATH), ("tier", SAFE_NAME)):
            if s[k] and not rx.match(s[k]):
                problems.append(f"Line {n}: {k} has unexpected characters.")
        if not s["domain"]:
            problems.append(f"Line {n}: domain is empty.")
        try:
            s["ssh_port"] = int(s["ssh_port"] or 22)
        except ValueError:
            problems.append(f"Line {n}: ssh_port must be a number.")
        rows.append(s)
    if not rows and not problems:
        problems.append("No servers in that CSV.")
    return rows, problems


@app.put("/api/clients/<cid>/inventory")
def put_inventory(cid):
    get_client(cid)
    rows, problems = parse_inventory(str((request.get_json(silent=True) or {}).get("csv") or ""))
    if problems:
        return jsonify(error=" ".join(problems[:8])), 400
    c = db()
    c.execute("BEGIN")
    c.execute("DELETE FROM servers WHERE client_id=?", (cid,))
    c.executemany("INSERT INTO servers (client_id, environment, tier, host, ip, role, os_user, domain, env_script, "
                  "ssh_port) VALUES (?,?,?,?,?,?,?,?,?,?)",
                  [(cid, *[s[k] for k in SERVER_COLS]) for s in rows])
    c.execute("COMMIT")
    return jsonify(ok=True, servers=len(rows))


# ---------------------------------------------------------------- jobs
def is_prd(tier):
    return str(tier or "").strip().lower() in ("prd", "prod", "production")


def target_of(s):
    return {k: s[k] for k in ("host", "ip", "role", "os_user", "domain", "env_script", "ssh_port")}


def plan_steps(servers, action):
    if action in ("ping", "levels"):
        seen, steps = set(), []
        for s in servers:
            key = s["ip"] or s["host"]
            if key in seen:
                continue
            seen.add(key)
            steps.append({"op": action, "target": target_of(s),
                          "label": "Connection check" if action == "ping" else "Read patch levels"})
        return steps, False
    if action == "status":
        return [{"op": "domain.status", "target": target_of(s), "label": f"Status of {s['role']} {s['domain']}"}
                for s in servers], False

    def ordered(order, op, verb):
        return [{"op": op, "target": target_of(s), "label": f"{verb} {s['role']} {s['domain']}"}
                for role in order for s in servers if s["role"] == role]
    if action == "start":
        return ordered(START_ORDER, "domain.start", "Start"), True
    if action == "stop":
        return ordered(STOP_ORDER, "domain.stop", "Stop"), True
    if action == "restart":
        return ordered(STOP_ORDER, "domain.stop", "Stop") + ordered(START_ORDER, "domain.start", "Start"), True
    raise ValueError("Unknown action.")


@app.post("/api/clients/<cid>/run")
def run(cid):
    get_client(cid)
    body = request.get_json(silent=True) or {}
    env, action, host = str(body.get("environment") or ""), str(body.get("action") or ""), body.get("host")
    servers = [row(s) for s in db().execute("SELECT * FROM servers WHERE client_id=? AND environment=?", (cid, env))]
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    if host:
        servers = [s for s in servers if host in (s["host"], s["ip"])]
        if not servers:
            return jsonify(error="That server isn't in the environment."), 404
    tier = next((s["tier"] for s in servers if s["tier"]), "")
    if action in ("start", "stop", "restart") and is_prd(tier) and str(body.get("confirm") or "").upper() != env.upper():
        return jsonify(error=f"Type {env} to confirm.", need_confirm=True), 409
    try:
        steps, stop_on_failure = plan_steps(servers, action)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    if not steps:
        return jsonify(error="Nothing to run for that selection."), 400
    if not db().execute("SELECT 1 FROM connectors WHERE client_id=? AND revoked=0", (cid,)).fetchone():
        return jsonify(error="This client has no connector yet. Add one first."), 409
    if db().execute("SELECT 1 FROM jobs WHERE client_id=? AND environment=? AND status IN ('queued','running')",
                    (cid, env)).fetchone():
        return jsonify(error=f"Something is already running or queued for {env}."), 409
    jid = "j_" + uuid.uuid4().hex[:16]
    title = f"{action} {env}" + (f" / {host}" if host else "")
    now = time.time()
    db().execute("INSERT INTO jobs (id, client_id, environment, title, params, status, created_by, created_at, "
                 "expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                 (jid, cid, env, title, json.dumps({"steps": steps, "stop_on_failure": stop_on_failure}),
                  "queued", who(), now, now + QUEUE_TTL))
    return jsonify(job=jid, steps=len(steps))


def expire_stale(cid=None):
    now = time.time()
    where, args = ("AND client_id=?", (cid,)) if cid else ("", ())
    db().execute(f"UPDATE jobs SET status='expired', finished_at=?, note='no connector picked it up in time' "
                 f"WHERE status='queued' AND expires_at<? {where}", (now, now, *args))
    db().execute(f"UPDATE jobs SET status='failed', finished_at=?, note='the connector stopped responding' "
                 f"WHERE status='running' {where} AND connector_id IN "
                 f"(SELECT id FROM connectors WHERE last_seen<?)", (now, *args, now - LOST_AFTER))


def domain_state(role, op, output, code):
    """running / stopped / unknown, from psadmin's output (same rules as self-hosted Pegasus)."""
    action = op.split(".", 1)[1] if "." in op else op
    t = (output or "").lower()
    stopped = ("is not started", "not running", "has stopped", "is stopped", "no bulletin board exists",
               "tmadmin_cat:1330", "cannot attach", "unable to attach", "not booted", "server is not running")
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
    return None


def job_view(j, with_steps=False):
    out = {"id": j["id"], "environment": j["environment"], "title": j["title"], "status": j["status"],
           "created_by": j["created_by"], "created_at": iso(j["created_at"]), "finished_at": iso(j["finished_at"]),
           "note": j["note"]}
    if with_steps:
        steps = json.loads(j["params"])["steps"]
        results = {r["step"]: r for r in json.loads(j["results"] or "[]")}
        out["steps"] = []
        for i, st in enumerate(steps):
            r = results.get(i)
            item = {"label": st.get("label") or st["op"], "host": st["target"]["host"], "op": st["op"],
                    "exit_code": r["exit_code"] if r else None, "done": bool(r)}
            if r and st["op"].startswith("domain."):
                item["state"] = domain_state(st["target"]["role"], st["op"], r.get("output"), r["exit_code"])
            out["steps"].append(item)
    return out


def recent_jobs(cid, limit=25):
    return [job_view(j) for j in db().execute(
        "SELECT * FROM jobs WHERE client_id=? ORDER BY created_at DESC LIMIT ?", (cid, limit))]


@app.get("/api/jobs/<jid>")
def get_job(jid):
    j = db().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not j:
        return jsonify(error="No such job."), 404
    expire_stale(j["client_id"])
    j = db().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    since = int(request.args.get("since", 0) or 0)
    ev = db().execute("SELECT seq, text FROM job_events WHERE job_id=? AND seq>=? ORDER BY seq", (jid, since)).fetchall()
    out = job_view(j, with_steps=True)
    out.update(text="".join(e["text"] or "" for e in ev), next=(ev[-1]["seq"] + 1) if ev else since)
    return jsonify(out)


# ---------------------------------------------------------------- connector API (called by connectors only)
def connector_auth():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer ") or "." not in h:
        return None
    cid, _, secret = h[7:].partition(".")
    c = db().execute("SELECT * FROM connectors WHERE id=? AND revoked=0", (cid,)).fetchone()
    if not c or not hmac.compare_digest(c["secret_hash"], sha(secret)):
        return None
    db().execute("UPDATE connectors SET last_seen=?, version=? WHERE id=?",
                 (time.time(), request.headers.get("X-Connector-Version", c["version"])[:20], cid))
    return c


@app.post("/api/connector/v1/register")
def connector_register():
    body = request.get_json(silent=True) or {}
    token = str(body.get("token") or "")
    c = db()
    c.execute("BEGIN IMMEDIATE")
    t = c.execute("SELECT * FROM reg_tokens WHERE token_hash=?", (sha(token),)).fetchone()
    now = time.time()
    if not t or t["used_at"] or t["expires_at"] < now:
        c.execute("ROLLBACK")
        time.sleep(1)
        return jsonify(error="That registration token isn't valid. It may have expired or already been used."), 401
    con_id, secret = "k_" + uuid.uuid4().hex[:12], secrets.token_urlsafe(32)
    clean = lambda k, n: re.sub(r"[^\x20-\x7e]", "", str(body.get(k) or ""))[:n]
    c.execute("INSERT INTO connectors (id, client_id, name, hostname, version, platform, secret_hash, created_at, "
              "last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
              (con_id, t["client_id"], clean("name", 80), clean("hostname", 120), clean("version", 20),
               clean("platform", 120), sha(secret), now, now))
    c.execute("UPDATE reg_tokens SET used_at=?, connector_id=? WHERE token_hash=?", (now, con_id, t["token_hash"]))
    c.execute("COMMIT")
    client = c.execute("SELECT name FROM clients WHERE id=?", (t["client_id"],)).fetchone()
    return jsonify(connector_id=con_id, secret=secret, tenant=t["client_id"], client_name=client["name"],
                   signing_public_key=protocol.public_key_b64(signing_key()))


@app.post("/api/connector/v1/heartbeat")
def connector_heartbeat():
    if not connector_auth():
        return jsonify(error="Unknown connector."), 401
    return jsonify(ok=True)


def claim(con):
    """Atomically hand the oldest queued job of this connector's client to it, signed."""
    c = db()
    now = time.time()
    j = c.execute("SELECT * FROM jobs WHERE client_id=? AND status='queued' AND expires_at>=? "
                  "ORDER BY created_at LIMIT 1", (con["client_id"], now)).fetchone()
    if not j:
        return None
    r = c.execute("UPDATE jobs SET status='running', connector_id=?, claimed_at=? WHERE id=? AND status='queued'",
                  (con["id"], now, j["id"]))
    if not r.rowcount:
        return None
    job = {"v": protocol.PROTOCOL_VERSION, "id": j["id"], "tenant": j["client_id"], "connector": con["id"],
           "op": "run", "params": json.loads(j["params"]), "issued_at": int(now), "expires_at": int(now + SIGNED_TTL)}
    return {"job": job, "signature": protocol.sign(job, signing_key())}


@app.get("/api/connector/v1/jobs/next")
def connector_next():
    con = connector_auth()
    if not con:
        return jsonify(error="Unknown connector."), 401
    try:
        wait = max(0.0, min(float(request.args.get("wait", 25)), 30.0))
    except ValueError:
        wait = 25.0
    deadline = time.time() + wait
    while True:
        out = claim(con)
        if out:
            return jsonify(out)
        if time.time() >= deadline:
            return "", 204
        time.sleep(0.5)


@app.post("/api/connector/v1/jobs/<jid>/events")
def connector_events(jid):
    con = connector_auth()
    if not con:
        return jsonify(error="Unknown connector."), 401
    j = db().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not j or j["connector_id"] != con["id"]:
        return jsonify(error="That job wasn't given to this connector."), 404
    body = request.get_json(silent=True) or {}
    try:
        seq = int(body.get("seq"))
    except (TypeError, ValueError):
        return jsonify(error="seq is required."), 400
    db().execute("INSERT OR IGNORE INTO job_events (job_id, seq, text, at) VALUES (?,?,?,?)",
                 (jid, seq, str(body.get("text") or "")[:200000], time.time()))
    if body.get("done") and j["status"] == "running":
        status = body.get("status") if body.get("status") in ("succeeded", "failed", "rejected") else "failed"
        results = body.get("results") if isinstance(body.get("results"), list) else []
        db().execute("UPDATE jobs SET status=?, finished_at=?, results=? WHERE id=?",
                     (status, time.time(), json.dumps(results)[:500000], jid))
    return jsonify(ok=True)


# ---------------------------------------------------------------- page
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


def main():
    if not ADMIN_PASSWORD:
        raise SystemExit("Set PEGASUS_ADMIN_PASSWORD before starting.")
    init_db()
    signing_key()
    host, port = os.environ.get("PEGASUS_HOST", "127.0.0.1"), int(os.environ.get("PEGASUS_PORT", "8443"))
    print(f"Pegasus control plane {__version__} on http://{host}:{port} "
          f"(signing key {protocol.fingerprint(protocol.public_key_b64(signing_key()))})")
    app.run(host=host, port=port, threaded=True)


init_db()

if __name__ == "__main__":
    main()
