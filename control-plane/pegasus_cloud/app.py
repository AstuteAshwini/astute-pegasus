"""Pegasus control plane.

Hosted web app and job queue. Clients' connectors call in over HTTPS; this service never connects to a client.

* People sign in with their Google account (when PEGASUS_GOOGLE_CLIENT_ID is set; Google handles their 2-step
  verification), or with an email, a password and an authenticator-app code. Each has a role (admin, operator or
  viewer) and is either Astute staff (every client) or a client's own user (that client only).
* Clients (tenants), their connectors, server inventory, jobs, patch levels, Jira change requests and the SSH key
  register live in a SQLite database for now (a managed database comes with hosting).
* Every job handed to a connector is signed with this service's Ed25519 key (protocol.py). Connectors run only the
  operations they know, built from their own templates; nothing here is ever executed as a shell command.
* Each connector holds its own key and a certificate this service issued for it; it signs every request, and
  certificates are renewed automatically. Removing a connector revokes its certificate.
* Connector updates are signed with Astute's release key (kept offline). This service only stores and offers them;
  connectors verify them against the key built into their own code.
"""
import csv
import datetime as dt
import functools
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
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, abort, g, jsonify, request, send_file, send_from_directory, session

from . import __version__, advisory, auth, evaluate as ev, jira as jiramod, protocol, sshkeys

DATA_DIR = Path(os.environ.get("PEGASUS_DATA", Path(__file__).resolve().parent.parent / "data"))
DB_PATH = DATA_DIR / "pegasus.db"
KEY_PATH = DATA_DIR / "signing_key.pem"
RELEASES_DIR = DATA_DIR / "releases"
# Optional: only offer releases signed by these release keys (comma-separated base64 public keys).
RELEASE_KEYS = [k.strip() for k in os.environ.get("PEGASUS_RELEASE_KEYS", "").split(",") if k.strip()]
# Only needed to create the first admin account. Once someone has signed in it's no longer used.
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
SESSION_HOURS = 12             # sign in again after this
LOCK_AFTER, LOCK_MINUTES = 5, 15
DEFAULT_STAGING = "/u01/app/oracle/staging/cpu"
# true when Pegasus sits behind a reverse proxy on the same machine (Caddy, nginx, an OCI load balancer): take the
# client's address and https from the proxy's X-Forwarded-* headers, from one proxy hop only.
TRUST_PROXY = os.environ.get("PEGASUS_TRUST_PROXY", "false").lower() == "true"
THREADS = int(os.environ.get("PEGASUS_THREADS", "48"))      # connectors hold one each for their 25-second long-poll
# Pegasus checks every domain's status by itself this often (seconds); 0 turns automatic checks off.
STATUS_EVERY = int(os.environ.get("PEGASUS_STATUS_EVERY", "600"))
# Patch watch: how often Pegasus re-reads every environment's patch levels and Oracle's latest releases by itself.
PATCH_WATCH_HOURS = float(os.environ.get("PEGASUS_PATCH_WATCH_HOURS", "24"))
# Sign in with Google (OpenID Connect). Only people who already have a Pegasus account (same email) get in; Pegasus
# keeps deciding what each of them can see and do. GOOGLE_DOMAIN limits it to one Google Workspace (e.g. beastute.com).
GOOGLE_CLIENT_ID = os.environ.get("PEGASUS_GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("PEGASUS_GOOGLE_CLIENT_SECRET", "")
GOOGLE_DOMAIN = os.environ.get("PEGASUS_GOOGLE_DOMAIN", "").strip().lower()
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = os.environ.get("PEGASUS_GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token")
# Who may still sign in with a password once Google sign-in is on: "all" (default) or "admins" (a break-glass way in).
PASSWORD_SIGNIN = os.environ.get("PEGASUS_PASSWORD_SIGNIN", "all").strip().lower()

SAFE_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_./~\-]{1,255}$")
SAFE_HOST = re.compile(r"^[A-Za-z0-9_.\-]{1,253}$")
SAFE_ABS_PATH = re.compile(r"^/[A-Za-z0-9_./\-]{1,250}$")
ROLES = ("app", "prcs", "web")
START_ORDER, STOP_ORDER = ["app", "prcs", "web"], ["web", "prcs", "app"]
SERVER_COLS = ["environment", "tier", "host", "ip", "role", "os_user", "domain", "env_script", "ssh_port"]
CR_OPEN = ("pending", "approved", "applying")

app = Flask(__name__, static_folder="static")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_NAME="pegasus",
                  SESSION_COOKIE_SECURE=os.environ.get("PEGASUS_COOKIE_SECURE", "true").lower() != "false",
                  PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=SESSION_HOURS), MAX_CONTENT_LENGTH=2 * 1024 * 1024)
_key_lock = threading.Lock()
_signing_key = None
_box = None
_finalize_lock = threading.Lock()

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
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT,
  pw_hash TEXT NOT NULL, role TEXT NOT NULL, client_id TEXT, totp_secret TEXT, totp_last INTEGER NOT NULL DEFAULT 0,
  mfa_enabled INTEGER NOT NULL DEFAULT 0, recovery TEXT NOT NULL DEFAULT '[]', must_change INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0, locked_until REAL NOT NULL DEFAULT 0,
  session_ver INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, last_login REAL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, client_id TEXT,
  event TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS audit_client ON audit (client_id, at);
CREATE TABLE IF NOT EXISTS settings (client_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT,
  PRIMARY KEY (client_id, key));
CREATE TABLE IF NOT EXISTS levels (client_id TEXT NOT NULL, environment TEXT NOT NULL, host_key TEXT NOT NULL,
  host TEXT, data TEXT NOT NULL, checked_at REAL NOT NULL, PRIMARY KEY (client_id, environment, host_key));
CREATE TABLE IF NOT EXISTS catalog (client_id TEXT PRIMARY KEY, data TEXT NOT NULL, checked_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS staged (client_id TEXT NOT NULL, environment TEXT NOT NULL, host_key TEXT NOT NULL,
  patch_key TEXT NOT NULL, dir TEXT NOT NULL, files TEXT NOT NULL, at REAL NOT NULL,
  PRIMARY KEY (client_id, environment, host_key, patch_key));
CREATE TABLE IF NOT EXISTS change_requests (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, environment TEXT NOT NULL,
  scope TEXT NOT NULL, groups TEXT NOT NULL, signature TEXT NOT NULL, jira_key TEXT, url TEXT, summary TEXT,
  hosts TEXT, notes TEXT, requested_by TEXT, window TEXT, change_type TEXT, requested_at REAL NOT NULL,
  status TEXT NOT NULL, approval TEXT, jira_status TEXT, approver TEXT, checked_at REAL, job_id TEXT,
  finished_at REAL);
CREATE TABLE IF NOT EXISTS domain_states (client_id TEXT NOT NULL, environment TEXT NOT NULL, host_key TEXT NOT NULL,
  role TEXT NOT NULL, domain TEXT NOT NULL, state TEXT NOT NULL, at REAL NOT NULL, job_id TEXT,
  PRIMARY KEY (client_id, environment, host_key, role, domain));
CREATE TABLE IF NOT EXISTS schedules (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, environment TEXT NOT NULL,
  action TEXT NOT NULL, days TEXT, once_date TEXT, at_time TEXT NOT NULL, tz TEXT NOT NULL, note TEXT,
  enabled INTEGER NOT NULL DEFAULT 1, skip_next INTEGER NOT NULL DEFAULT 0, created_by TEXT, created_at REAL NOT NULL,
  next_run REAL, last_run REAL, last_status TEXT, last_job TEXT, last_detail TEXT);
CREATE INDEX IF NOT EXISTS schedules_due ON schedules (enabled, next_run);
CREATE TABLE IF NOT EXISTS nonces (connector_id TEXT NOT NULL, nonce TEXT NOT NULL, at REAL NOT NULL,
  PRIMARY KEY (connector_id, nonce));
CREATE TABLE IF NOT EXISTS access_keys (client_id TEXT NOT NULL, rid TEXT NOT NULL, fingerprint TEXT NOT NULL,
  type TEXT, comment TEXT, line TEXT NOT NULL, account TEXT, added_by TEXT, added_at REAL, note TEXT,
  servers TEXT NOT NULL DEFAULT '{}', updated_at REAL, PRIMARY KEY (client_id, rid));
CREATE TABLE IF NOT EXISTS access_requests (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, mode TEXT NOT NULL,
  body TEXT NOT NULL, summary TEXT, environments TEXT, note TEXT, expires_on TEXT, requested_by TEXT,
  requested_by_id TEXT, requested_at REAL NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_by_id TEXT,
  decided_at REAL, decision_note TEXT, job_id TEXT);
CREATE INDEX IF NOT EXISTS access_requests_client ON access_requests (client_id, requested_at);
CREATE TABLE IF NOT EXISTS removed_environments (id TEXT PRIMARY KEY, client_id TEXT NOT NULL, environment TEXT NOT NULL,
  servers TEXT NOT NULL, schedules TEXT NOT NULL, removed_by TEXT, removed_at REAL NOT NULL, restored_at REAL);
"""
MIGRATIONS = {"jobs": [("kind", "TEXT"), ("meta", "TEXT"), ("finalized", "INTEGER NOT NULL DEFAULT 0")],
              "connectors": [("public_key", "TEXT"), ("cert_serial", "TEXT"), ("cert_not_after", "REAL"),
                             ("cert_issued_at", "REAL"), ("prev_public_key", "TEXT"), ("prev_until", "REAL"),
                             ("update_to", "TEXT"), ("update_state", "TEXT"), ("update_version", "TEXT"),
                             ("update_detail", "TEXT"), ("update_at", "REAL"), ("can_update", "INTEGER"),
                             ("update_requested_at", "REAL")],
              "access_keys": [("expires_on", "TEXT")],
              "schedules": [("plan", "TEXT")],
              "access_requests": [("jira_key", "TEXT"), ("jira_url", "TEXT"), ("jira_status", "TEXT"),
                                  ("checked_at", "REAL")]}


# ---------------------------------------------------------------- storage
def db():
    if "db" not in g:
        g.db = connect()
    return g.db


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None, check_same_thread=False)
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
    for table, cols in MIGRATIONS.items():
        have = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
        for name, kind in cols:
            if name not in have:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {kind}")
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


def box():
    global _box
    with _key_lock:
        if _box is None:
            _box = auth.SecretBox(DATA_DIR / "secret.key")
        return _box


def session_secret():
    if os.environ.get("PEGASUS_SECRET"):
        return os.environ["PEGASUS_SECRET"]
    p = DATA_DIR / "session.key"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    return p.read_text().strip()


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="seconds") if t else None


def now_text():
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")


def row(r):
    return dict(r) if r else None


def jload(text, default=None):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def get_setting(cid, key, default=None):
    r = db().execute("SELECT value FROM settings WHERE client_id=? AND key=?", (cid, key)).fetchone()
    return jload(r["value"], default) if r else default


def put_setting(cid, key, value):
    db().execute("INSERT INTO settings (client_id, key, value) VALUES (?,?,?) ON CONFLICT(client_id, key) "
                 "DO UPDATE SET value=excluded.value", (cid, key, json.dumps(value)))


def audit(event, cid=None, actor=None, **detail):
    db().execute("INSERT INTO audit (at, actor, client_id, event, detail) VALUES (?,?,?,?,?)",
                 (time.time(), actor if actor is not None else actor_label(), cid, event,
                  json.dumps(detail)[:4000] if detail else None))


# ---------------------------------------------------------------- people: sessions, roles
def is_local_request():
    return request.remote_addr in ("127.0.0.1", "::1") and not any(h in request.headers for h in FORWARD_HEADERS)


OPEN_PATHS = ("/api/login", "/api/login/mfa", "/api/mfa/enroll", "/api/session", "/api/setup", "/api/logout",
              "/api/sso/google/start", "/api/sso/google/callback")
MUST_CHANGE_PATHS = ("/api/password",)


def current_user():
    if "user" in g:
        return g.user
    g.user = None
    uid = session.get("uid")
    if uid and session.get("stage") == "full" and time.time() - session.get("at", 0) < SESSION_HOURS * 3600:
        u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if u and not u["disabled"] and u["session_ver"] == session.get("sv"):
            g.user = u
    return g.user


def actor_label():
    u = current_user() if request else None
    return (u["name"] or u["email"]) if u else "pegasus"


def who():
    return actor_label()


@app.before_request
def guard():
    p = request.path
    if p.startswith("/api/connector/"):
        return None
    if ADMIN_LOCAL_ONLY and not is_local_request():
        return jsonify(error="Not found."), 404
    if not p.startswith("/api/"):
        return None
    if request.method != "GET" and request.headers.get("X-Requested-With") != "pegasus":
        return jsonify(error="Bad request origin."), 400
    if p in OPEN_PATHS:
        return None
    u = current_user()
    if not u:
        return jsonify(error="Sign in first."), 401
    if u["must_change"] and p not in MUST_CHANGE_PATHS:
        return jsonify(error="Choose a new password first.", must_change_password=True), 403
    return None


def need(role):
    """Endpoint decorator: the signed-in person must have at least this role."""
    def wrap(fn):
        @functools.wraps(fn)
        def inner(*a, **kw):
            u = current_user()
            if not u or auth.ROLE_RANK[u["role"]] < auth.ROLE_RANK[role]:
                return jsonify(error=f"This needs the {role} role."), 403
            return fn(*a, **kw)
        return inner
    return wrap


def staff():
    u = current_user()
    return bool(u and not u["client_id"])


def get_client(cid):
    """The client, if the signed-in person may see it; 404 otherwise (so other clients' ids don't leak)."""
    c = db().execute("SELECT * FROM clients WHERE id=?", (cid,)).fetchone()
    u = current_user()
    if not c or not u or (u["client_id"] and u["client_id"] != cid):
        abort(404)
    return c


def user_view(u):
    return {"id": u["id"], "email": u["email"], "name": u["name"], "role": u["role"], "client_id": u["client_id"],
            "mfa": bool(u["mfa_enabled"]), "disabled": bool(u["disabled"]), "must_change": bool(u["must_change"]),
            "locked": u["locked_until"] > time.time(), "last_login": iso(u["last_login"]),
            "created_at": iso(u["created_at"]), "recovery_left": len(jload(u["recovery"], []))}


def start_session(u, stage):
    session.clear()
    session.permanent = True
    session.update(uid=u["id"], sv=u["session_ver"], stage=stage, at=time.time())


@app.get("/api/session")
def session_info():
    n = db().execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    u = current_user()
    out = {"auth": bool(u), "setup_needed": n == 0, "version": __version__,
           "signing_key": protocol.fingerprint(protocol.public_key_b64(signing_key())),
           "setup_needs_password": bool(ADMIN_PASSWORD), "stage": session.get("stage"),
           "google": google_enabled(), "password_signin": PASSWORD_SIGNIN if google_enabled() else "all"}
    if u:
        out["user"] = user_view(u)
        out["who"] = u["name"] or u["email"]
        out["must_change_password"] = bool(u["must_change"])
    return jsonify(out)


@app.post("/api/setup")
def setup():
    """Create the first admin account. Needs PEGASUS_ADMIN_PASSWORD, or (if that isn't set) a request made on this
    machine. Works only while there are no accounts."""
    body = request.get_json(silent=True) or {}
    c = db()
    if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]:
        return jsonify(error="Pegasus already has accounts. Sign in."), 409
    if ADMIN_PASSWORD:
        if not hmac.compare_digest(str(body.get("setup_password", "")).encode(), ADMIN_PASSWORD.encode()):
            time.sleep(1.5)
            return jsonify(error="That isn't the setup password (PEGASUS_ADMIN_PASSWORD)."), 401
    elif not is_local_request():
        return jsonify(error="Set PEGASUS_ADMIN_PASSWORD, or create the first account on the machine Pegasus runs on."), 403
    email, name = str(body.get("email") or "").strip().lower(), str(body.get("name") or "").strip()[:80]
    pw = str(body.get("password") or "")
    if not auth.EMAIL.match(email):
        return jsonify(error="Enter a valid email address."), 400
    if not name:
        return jsonify(error="Enter your name."), 400
    problem = auth.password_problem(pw, email, name)
    if problem:
        return jsonify(error=problem), 400
    uid = "u_" + uuid.uuid4().hex[:12]
    c.execute("INSERT INTO users (id, email, name, pw_hash, role, created_at) VALUES (?,?,?,?,?,?)",
              (uid, email, name, auth.hash_password(pw), "admin", time.time()))
    audit("first_admin_created", actor=email, email=email)
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    email, pw = str(body.get("email") or "").strip().lower(), str(body.get("password") or "")
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if u and u["locked_until"] > time.time():
        return jsonify(error=f"Too many failed sign-ins. Try again after "
                             f"{dt.datetime.fromtimestamp(u['locked_until']).strftime('%H:%M')}."), 429
    if not u or u["disabled"] or not auth.check_password(pw, u["pw_hash"]):
        if u:
            failed = u["failed"] + 1
            db().execute("UPDATE users SET failed=?, locked_until=? WHERE id=?",
                         (failed % LOCK_AFTER if failed >= LOCK_AFTER else failed,
                          time.time() + LOCK_MINUTES * 60 if failed >= LOCK_AFTER else u["locked_until"], u["id"]))
            audit("sign_in_failed", actor=email, locked=failed >= LOCK_AFTER)
        time.sleep(1.5)
        return jsonify(error="Wrong email or password."), 401
    if google_enabled() and PASSWORD_SIGNIN == "admins" and u["role"] != "admin":
        return jsonify(error="Use Sign in with Google."), 403
    if u["mfa_enabled"]:
        start_session(u, "mfa")
        return jsonify(next="mfa")
    secret = auth.new_totp_secret()
    db().execute("UPDATE users SET totp_secret=?, totp_last=0 WHERE id=?", (secret, u["id"]))
    start_session(u, "enroll")
    return jsonify(next="enroll", secret=secret, uri=auth.otpauth_uri(secret, u["email"]))


def pending_user(stage):
    if session.get("stage") != stage or time.time() - session.get("at", 0) > 600:
        return None
    u = db().execute("SELECT * FROM users WHERE id=?", (session.get("uid"),)).fetchone()
    return u if u and not u["disabled"] and u["session_ver"] == session.get("sv") else None


def signed_in(u):
    db().execute("UPDATE users SET failed=0, locked_until=0, last_login=? WHERE id=?", (time.time(), u["id"]))
    u = db().execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    start_session(u, "full")
    g.pop("user", None)
    audit("signed_in", actor=u["email"])


def mfa_failed(u):
    failed = u["failed"] + 1
    db().execute("UPDATE users SET failed=?, locked_until=? WHERE id=?",
                 (0 if failed >= LOCK_AFTER else failed,
                  time.time() + LOCK_MINUTES * 60 if failed >= LOCK_AFTER else u["locked_until"], u["id"]))
    audit("mfa_failed", actor=u["email"])
    if failed >= LOCK_AFTER:
        session.clear()
    time.sleep(1)


@app.post("/api/login/mfa")
def login_mfa():
    u = pending_user("mfa")
    if not u:
        return jsonify(error="Sign in again.", restart=True), 401
    code = str((request.get_json(silent=True) or {}).get("code") or "").strip()
    step = auth.verify_totp(u["totp_secret"], code, u["totp_last"])
    if step:
        db().execute("UPDATE users SET totp_last=? WHERE id=?", (step, u["id"]))
        signed_in(u)
        return jsonify(ok=True)
    left = auth.use_recovery_code(code, jload(u["recovery"], []))
    if left is not None:
        db().execute("UPDATE users SET recovery=? WHERE id=?", (json.dumps(left), u["id"]))
        signed_in(u)
        audit("recovery_code_used", actor=u["email"], left=len(left))
        return jsonify(ok=True, recovery_left=len(left))
    mfa_failed(u)
    return jsonify(error="That code didn't work. Use the current 6-digit code from your authenticator app, or a "
                         "recovery code."), 401


@app.post("/api/mfa/enroll")
def mfa_enroll():
    u = pending_user("enroll")
    if not u:
        return jsonify(error="Sign in again.", restart=True), 401
    step = auth.verify_totp(u["totp_secret"], (request.get_json(silent=True) or {}).get("code"), 0)
    if not step:
        mfa_failed(u)
        return jsonify(error="That code didn't match. Check the time on your phone and enter the current code."), 401
    codes, hashes = auth.new_recovery_codes()
    db().execute("UPDATE users SET mfa_enabled=1, totp_last=?, recovery=? WHERE id=?",
                 (step, json.dumps(hashes), u["id"]))
    audit("mfa_enrolled", actor=u["email"])
    signed_in(u)
    return jsonify(ok=True, recovery_codes=codes)


# ---------------------------------------------------------------- sign in with Google
def google_enabled():
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


def google_redirect_uri():
    return (PUBLIC_URL or request.host_url.rstrip("/")) + "/api/sso/google/callback"


def sso_signer():
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(app.secret_key, salt="pegasus-google-sso")


def sso_fail(message, email=""):
    from urllib.parse import quote
    audit("google_sign_in_refused", actor=email or "unknown", reason=message)
    r = app.redirect("/?sso_error=" + quote(message))
    r.delete_cookie("pegasus_sso", path="/api/sso/")
    return r


def google_exchange(code, verifier):
    """Trade the one-time code for Google's ID token, straight from Google over HTTPS, and return its claims.
    (A token received directly from Google's token endpoint like this needn't have its signature checked; its claims
    are checked by the caller.)"""
    import base64
    import requests
    r = requests.post(GOOGLE_TOKEN_URL, timeout=20, data={
        "code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": google_redirect_uri(), "grant_type": "authorization_code", "code_verifier": verifier})
    if r.status_code != 200:
        raise ValueError(f"Google refused the sign-in ({r.status_code}).")
    token = (r.json() or {}).get("id_token") or ""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Google didn't send an ID token.")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


@app.get("/api/sso/google/start")
def google_start():
    import base64
    from urllib.parse import urlencode
    if not google_enabled():
        return app.redirect("/?sso_error=" + "Google%20sign-in%20isn%27t%20set%20up.")
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": GOOGLE_CLIENT_ID, "redirect_uri": google_redirect_uri(), "response_type": "code",
              "scope": "openid email profile", "state": state, "nonce": nonce, "code_challenge": challenge,
              "code_challenge_method": "S256", "prompt": "select_account"}
    if GOOGLE_DOMAIN:
        params["hd"] = GOOGLE_DOMAIN
    r = app.redirect(GOOGLE_AUTH_URL + "?" + urlencode(params))
    # Google sends the browser back from another site, so this short-lived cookie is Lax (the session cookie is Strict)
    r.set_cookie("pegasus_sso", sso_signer().dumps({"s": state, "n": nonce, "v": verifier}), max_age=600,
                 path="/api/sso/", httponly=True, samesite="Lax", secure=app.config["SESSION_COOKIE_SECURE"])
    return r


@app.get("/api/sso/google/callback")
def google_callback():
    if not google_enabled():
        return sso_fail("Google sign-in isn't set up.")
    try:
        saved = sso_signer().loads(request.cookies.get("pegasus_sso", ""), max_age=600)
    except Exception:
        return sso_fail("The Google sign-in took too long or started in another browser. Try again.")
    if request.args.get("error"):
        return sso_fail("Google sign-in was cancelled.")
    if not hmac.compare_digest(str(request.args.get("state", "")), saved["s"]):
        return sso_fail("The Google sign-in didn't match. Try again.")
    try:
        claims = google_exchange(str(request.args.get("code", "")), saved["v"])
    except Exception as e:
        return sso_fail(f"Couldn't finish signing in with Google: {e}")
    email = str(claims.get("email") or "").strip().lower()
    problems = [
        claims.get("iss") not in ("accounts.google.com", "https://accounts.google.com") and "issuer",
        claims.get("aud") != GOOGLE_CLIENT_ID and "audience",
        not (isinstance(claims.get("exp"), (int, float)) and claims["exp"] > time.time()) and "expiry",
        not hmac.compare_digest(str(claims.get("nonce", "")), saved["n"]) and "nonce",
        claims.get("email_verified") not in (True, "true") and "unverified email"]
    problems = [p for p in problems if p]
    if problems:
        return sso_fail("Google's answer didn't check out (" + ", ".join(problems) + ").", email)
    if GOOGLE_DOMAIN and str(claims.get("hd") or "").lower() != GOOGLE_DOMAIN:
        return sso_fail(f"Use your {GOOGLE_DOMAIN} Google account.", email)
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or u["disabled"]:
        return sso_fail(f"{email} doesn't have a Pegasus account. Ask a Pegasus admin to add you.", email)
    if u["must_change"]:
        # a temporary password from an admin is no longer needed: retire it rather than leave it usable
        db().execute("UPDATE users SET must_change=0, pw_hash=? WHERE id=?",
                     (auth.hash_password(secrets.token_urlsafe(32)), u["id"]))
    signed_in(u)
    audit("signed_in_with_google", actor=u["email"])
    r = app.redirect("/")
    r.delete_cookie("pegasus_sso", path="/api/sso/")
    return r


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.post("/api/password")
def change_password():
    u = current_user()
    body = request.get_json(silent=True) or {}
    if not auth.check_password(body.get("current"), u["pw_hash"]):
        time.sleep(1)
        return jsonify(error="Your current password isn't right."), 401
    new = str(body.get("new") or "")
    problem = auth.password_problem(new, u["email"], u["name"] or "")
    if problem:
        return jsonify(error=problem), 400
    if auth.check_password(new, u["pw_hash"]):
        return jsonify(error="Choose a password you haven't just used."), 400
    db().execute("UPDATE users SET pw_hash=?, must_change=0, session_ver=session_ver+1 WHERE id=?",
                 (auth.hash_password(new), u["id"]))
    audit("password_changed")
    u = db().execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    start_session(u, "full")
    return jsonify(ok=True)


@app.post("/api/mfa/recovery-codes")
def new_recovery_codes():
    u = current_user()
    if not auth.check_password((request.get_json(silent=True) or {}).get("password"), u["pw_hash"]):
        time.sleep(1)
        return jsonify(error="Your password isn't right."), 401
    codes, hashes = auth.new_recovery_codes()
    db().execute("UPDATE users SET recovery=? WHERE id=?", (json.dumps(hashes), u["id"]))
    audit("recovery_codes_replaced")
    return jsonify(recovery_codes=codes)


# ---------------------------------------------------------------- people: administration
def admin_scope_ok(target):
    """Staff admins manage everyone. (Client users can't be admins.)"""
    return staff() and current_user()["role"] == "admin" and target is not None


def clean_user_fields(body, existing=None):
    role = body.get("role", existing["role"] if existing else "viewer")
    if role not in auth.ROLES:
        return None, "Choose admin, operator or viewer."
    cid = body.get("client_id", existing["client_id"] if existing else None) or None
    if cid and not db().execute("SELECT 1 FROM clients WHERE id=?", (cid,)).fetchone():
        return None, "That client doesn't exist."
    if cid and role == "admin":
        return None, "A client's own users can be operators or viewers. Admins are Astute staff."
    return {"role": role, "client_id": cid}, None


def admins_left(excluding):
    return db().execute("SELECT COUNT(*) n FROM users WHERE role='admin' AND client_id IS NULL AND disabled=0 "
                        "AND id<>?", (excluding,)).fetchone()["n"]


@app.get("/api/users")
@need("admin")
def list_users():
    if not staff():
        return jsonify(error="Only Astute staff manage accounts."), 403
    us = db().execute("SELECT * FROM users ORDER BY client_id IS NOT NULL, email").fetchall()
    return jsonify(users=[user_view(u) for u in us])


@app.post("/api/users")
@need("admin")
def create_user():
    if not staff():
        return jsonify(error="Only Astute staff manage accounts."), 403
    body = request.get_json(silent=True) or {}
    email, name = str(body.get("email") or "").strip().lower(), str(body.get("name") or "").strip()[:80]
    if not auth.EMAIL.match(email):
        return jsonify(error="Enter a valid email address."), 400
    if not name:
        return jsonify(error="Enter the person's name."), 400
    fields, err = clean_user_fields(body)
    if err:
        return jsonify(error=err), 400
    if db().execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return jsonify(error="Someone already has that email."), 409
    temp = auth.temporary_password()
    uid = "u_" + uuid.uuid4().hex[:12]
    db().execute("INSERT INTO users (id, email, name, pw_hash, role, client_id, must_change, created_at) "
                 "VALUES (?,?,?,?,?,?,1,?)", (uid, email, name, auth.hash_password(temp), fields["role"],
                                              fields["client_id"], time.time()))
    audit("user_created", fields["client_id"], email=email, role=fields["role"])
    return jsonify(user=user_view(db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()),
                   temporary_password=temp)


def target_user(uid):
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not admin_scope_ok(u):
        abort(404)
    return u


@app.patch("/api/users/<uid>")
@need("admin")
def update_user(uid):
    u = target_user(uid)
    body = request.get_json(silent=True) or {}
    fields, err = clean_user_fields(body, u)
    if err:
        return jsonify(error=err), 400
    disabled = bool(body.get("disabled", u["disabled"]))
    name = str(body.get("name", u["name"]) or "").strip()[:80] or u["name"]
    losing_admin = u["role"] == "admin" and not u["client_id"] and (fields["role"] != "admin" or disabled
                                                                     or fields["client_id"])
    if losing_admin and not admins_left(u["id"]):
        return jsonify(error="Pegasus needs at least one active admin. Make someone else an admin first."), 409
    bump = disabled != bool(u["disabled"]) or fields != {"role": u["role"], "client_id": u["client_id"]}
    db().execute("UPDATE users SET name=?, role=?, client_id=?, disabled=?, session_ver=session_ver+? WHERE id=?",
                 (name, fields["role"], fields["client_id"], int(disabled), int(bump), uid))
    audit("user_updated", fields["client_id"], email=u["email"], role=fields["role"], disabled=disabled)
    return jsonify(user=user_view(db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()))


@app.post("/api/users/<uid>/reset-password")
@need("admin")
def reset_password(uid):
    u = target_user(uid)
    temp = auth.temporary_password()
    db().execute("UPDATE users SET pw_hash=?, must_change=1, failed=0, locked_until=0, session_ver=session_ver+1 "
                 "WHERE id=?", (auth.hash_password(temp), uid))
    audit("password_reset", u["client_id"], email=u["email"])
    return jsonify(temporary_password=temp)


@app.post("/api/users/<uid>/reset-mfa")
@need("admin")
def reset_mfa(uid):
    u = target_user(uid)
    db().execute("UPDATE users SET mfa_enabled=0, totp_secret='', totp_last=0, recovery='[]', "
                 "session_ver=session_ver+1 WHERE id=?", (uid,))
    audit("mfa_reset", u["client_id"], email=u["email"])
    return jsonify(ok=True)


@app.get("/api/audit")
@need("viewer")
def audit_log():
    cid = request.args.get("client") or None
    if cid:
        get_client(cid)
    elif not staff():
        cid = current_user()["client_id"]
    if cid:
        rs = db().execute("SELECT * FROM audit WHERE client_id=? ORDER BY at DESC LIMIT 300", (cid,)).fetchall()
    else:
        rs = db().execute("SELECT * FROM audit ORDER BY at DESC LIMIT 300").fetchall()
    return jsonify(events=[{"at": iso(r["at"]), "actor": r["actor"], "client_id": r["client_id"], "event": r["event"],
                            "detail": jload(r["detail"], {})} for r in rs])


# ---------------------------------------------------------------- clients, tokens, connectors
def connector_view(c, now=None):
    now = now or time.time()
    online = bool(c["last_seen"] and now - c["last_seen"] < ONLINE_WINDOW and not c["revoked"])
    rel = latest_release()
    return {"id": c["id"], "name": c["name"], "hostname": c["hostname"], "version": c["version"],
            "platform": c["platform"], "last_seen": iso(c["last_seen"]), "online": online,
            "revoked": bool(c["revoked"]), "created_at": iso(c["created_at"]),
            "auth": "certificate" if c["public_key"] else "secret",
            "certificate": {"serial": c["cert_serial"], "valid_until": iso(c["cert_not_after"]),
                            "issued_at": iso(c["cert_issued_at"])} if c["public_key"] else None,
            "update": {"state": c["update_state"], "version": c["update_version"], "detail": c["update_detail"],
                       "at": iso(c["update_at"])} if c["update_state"] else None,
            "update_to": c["update_to"], "can_update": c["can_update"] == 1,
            "update_available": rel["version"] if rel and is_newer(rel["version"], c["version"]) else None}


@app.get("/api/clients")
@need("viewer")
def list_clients():
    now = time.time()
    out = []
    u = current_user()
    rows = (db().execute("SELECT * FROM clients WHERE id=?", (u["client_id"],)) if u["client_id"] else
            db().execute("SELECT * FROM clients ORDER BY name COLLATE NOCASE"))
    for c in rows:
        cons = db().execute("SELECT * FROM connectors WHERE client_id=? AND revoked=0", (c["id"],)).fetchall()
        envs = db().execute("SELECT COUNT(DISTINCT environment) n FROM servers WHERE client_id=?", (c["id"],)).fetchone()
        out.append({"id": c["id"], "name": c["name"], "environments": envs["n"],
                    "connectors": len(cons), "online": sum(connector_view(x, now)["online"] for x in cons)})
    return jsonify(clients=out)


@app.post("/api/clients")
@need("admin")
def create_client():
    if not staff():
        return jsonify(error="Only Astute staff add clients."), 403
    name = str((request.get_json(silent=True) or {}).get("name") or "").strip()
    if not 1 <= len(name) <= 80:
        return jsonify(error="Enter the client's name."), 400
    cid = "c_" + uuid.uuid4().hex[:12]
    db().execute("INSERT INTO clients VALUES (?,?,?)", (cid, name, time.time()))
    audit("client_created", cid, name=name)
    return jsonify(id=cid, name=name)


@app.get("/api/clients/<cid>")
@need("viewer")
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
    rel = latest_release()
    oci = oci_console(cid)
    return jsonify(id=c["id"], name=c["name"], connectors=cons, environments=list(envs.values()), oci_console=oci,
                   jobs=recent_jobs(cid), connector_updates=get_setting(cid, "connector_updates", "manual"),
                   latest_release=release_view(rel) if rel else None)


@app.post("/api/clients/<cid>/tokens")
@need("admin")
def create_token(cid):
    get_client(cid)
    token = "pgr_" + secrets.token_urlsafe(24)
    now = time.time()
    db().execute("INSERT INTO reg_tokens (token_hash, client_id, created_by, created_at, expires_at) VALUES (?,?,?,?,?)",
                 (sha(token), cid, who(), now, now + TOKEN_TTL))
    audit("connector_token_created", cid)
    url = PUBLIC_URL or request.host_url.rstrip("/")
    return jsonify(token=token, expires_at=iso(now + TOKEN_TTL), url=url,
                   fingerprint=protocol.fingerprint(protocol.public_key_b64(signing_key())),
                   command=f"python -m pegasus_connector register --url {url} --token {token} "
                           f"--ssh-user opc --ssh-key /home/opc/.ssh/id_rsa")


@app.delete("/api/connectors/<con_id>")
@need("admin")
def revoke_connector(con_id):
    c = db().execute("SELECT * FROM connectors WHERE id=?", (con_id,)).fetchone()
    if not c:
        return jsonify(error="No such connector."), 404
    get_client(c["client_id"])
    db().execute("UPDATE connectors SET revoked=1, prev_public_key=NULL, prev_until=NULL WHERE id=?", (con_id,))
    db().execute("UPDATE jobs SET status='failed', finished_at=?, note='connector removed' "
                 "WHERE connector_id=? AND status='running'", (time.time(), con_id))
    audit("connector_removed", c["client_id"], connector=con_id, name=c["name"],
          certificate=c["cert_serial"] or "", note="certificate revoked" if c["public_key"] else "")
    finalize_pending()
    return jsonify(ok=True)


# ---------------------------------------------------------------- inventory
def check_server(r, where):
    """A clean inventory row, and its problems."""
    s = {c: str(r.get(c) if r.get(c) is not None else "").strip() for c in SERVER_COLS}
    s["role"] = s["role"].lower()
    problems = []
    if not SAFE_NAME.match(s["environment"]):
        problems.append(f"{where}: environment name has unexpected characters.")
    if not SAFE_HOST.match(s["host"]) or (s["ip"] and not SAFE_HOST.match(s["ip"])):
        problems.append(f"{where}: host or IP has unexpected characters.")
    if s["role"] not in ROLES:
        problems.append(f"{where}: role must be app, prcs or web.")
    for k, rx in (("os_user", SAFE_NAME), ("domain", SAFE_NAME), ("env_script", SAFE_PATH), ("tier", SAFE_NAME)):
        if s[k] and not rx.match(s[k]):
            problems.append(f"{where}: {k} has unexpected characters.")
    if not s["domain"]:
        problems.append(f"{where}: domain is empty.")
    try:
        s["ssh_port"] = int(s["ssh_port"] or 22)
        assert 0 < s["ssh_port"] < 65536
    except (ValueError, AssertionError):
        problems.append(f"{where}: ssh_port must be a port number.")
    return s, problems


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
        s, p = check_server(r, f"Line {n}")
        problems += p
        rows.append(s)
    if not rows and not problems:
        problems.append("No servers in that CSV.")
    return rows, problems


@app.put("/api/clients/<cid>/inventory")
@need("admin")
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
    audit("inventory_imported", cid, servers=len(rows))
    jobs = queue_levels(cid, sorted({r["environment"] for r in rows}), who())
    return jsonify(ok=True, servers=len(rows), levels_jobs=jobs)


@app.post("/api/clients/<cid>/inventory/add")
@need("admin")
def add_inventory(cid):
    """Add domains (usually found by a scan) to one environment, keeping the rest of the inventory. A domain that's
    already there (same environment, server, role and domain) is updated rather than added twice."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    env, tier = str(body.get("environment") or "").strip(), str(body.get("tier") or "").strip()
    rows, problems = [], []
    for i, r in enumerate(body.get("rows") or [], start=1):
        s, p = check_server(dict(r, environment=env, tier=tier), f"Row {i}")
        problems += p
        rows.append(s)
    if not env:
        problems.insert(0, "Give the environment a name.")
    if not rows:
        problems.append("Choose at least one domain.")
    if problems:
        return jsonify(error=" ".join(dict.fromkeys(problems[:8]))), 400
    c = db()
    c.execute("BEGIN")
    added = 0
    for s in rows:
        hit = c.execute("SELECT id FROM servers WHERE client_id=? AND environment=? AND (host=? OR ip=?) AND role=? "
                        "AND domain=?", (cid, env, s["host"], s["ip"] or s["host"], s["role"], s["domain"])).fetchone()
        if hit:
            c.execute("UPDATE servers SET tier=?, host=?, ip=?, os_user=?, env_script=?, ssh_port=? WHERE id=?",
                      (tier, s["host"], s["ip"], s["os_user"], s["env_script"], s["ssh_port"], hit["id"]))
        else:
            c.execute("INSERT INTO servers (client_id, environment, tier, host, ip, role, os_user, domain, env_script, "
                      "ssh_port) VALUES (?,?,?,?,?,?,?,?,?,?)", (cid, *[s[k] for k in SERVER_COLS]))
            added += 1
    if tier:
        c.execute("UPDATE servers SET tier=? WHERE client_id=? AND environment=?", (tier, cid, env))
    c.execute("COMMIT")
    audit("inventory_added", cid, environment=env, added=added, updated=len(rows) - added)
    jobs = queue_levels(cid, [env], who())             # patch levels straight away, then Oracle's latest
    return jsonify(ok=True, added=added, updated=len(rows) - added, levels_jobs=jobs)


@app.delete("/api/clients/<cid>/environments/<env>")
@need("admin")
def delete_environment(cid, env):
    """Admins only, with the environment's name typed to confirm. Nothing is lost for 30 days: the servers and
    schedules are kept aside and can be restored."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    if str(body.get("confirm") or request.args.get("confirm") or "") != env:
        return jsonify(error=f"Type {env} to confirm.", need_confirm=True, expected=env), 409
    servers = [dict(r) for r in db().execute("SELECT * FROM servers WHERE client_id=? AND environment=?", (cid, env))]
    if not servers:
        return jsonify(error="No such environment."), 404
    scheds = [dict(r) for r in db().execute("SELECT * FROM schedules WHERE client_id=? AND environment=?", (cid, env))]
    rid = "re_" + uuid.uuid4().hex[:12]
    db().execute("INSERT INTO removed_environments (id, client_id, environment, servers, schedules, removed_by, "
                 "removed_at) VALUES (?,?,?,?,?,?,?)",
                 (rid, cid, env, json.dumps(servers), json.dumps(scheds), who(), time.time()))
    db().execute("DELETE FROM servers WHERE client_id=? AND environment=?", (cid, env))
    db().execute("DELETE FROM domain_states WHERE client_id=? AND environment=?", (cid, env))
    db().execute("DELETE FROM schedules WHERE client_id=? AND environment=?", (cid, env))
    audit("environment_removed", cid, environment=env, servers=len(servers), schedules_removed=len(scheds) or "",
          restorable_until=iso(time.time() + REMOVED_KEEP_DAYS * 86400))
    return jsonify(ok=True, restore_id=rid)


REMOVED_KEEP_DAYS = 30


@app.get("/api/clients/<cid>/removed-environments")
@need("viewer")
def removed_environments(cid):
    get_client(cid)
    rows = db().execute("SELECT * FROM removed_environments WHERE client_id=? AND restored_at IS NULL AND removed_at>? "
                        "ORDER BY removed_at DESC", (cid, time.time() - REMOVED_KEEP_DAYS * 86400)).fetchall()
    return jsonify(removed=[{"id": r["id"], "environment": r["environment"], "servers": len(jload(r["servers"], [])),
                             "schedules": len(jload(r["schedules"], [])), "removed_by": r["removed_by"],
                             "removed_at": iso(r["removed_at"]),
                             "until": iso(r["removed_at"] + REMOVED_KEEP_DAYS * 86400)} for r in rows])


@app.post("/api/removed-environments/<rid>/restore")
@need("admin")
def restore_environment(rid):
    r = db().execute("SELECT * FROM removed_environments WHERE id=? AND restored_at IS NULL", (rid,)).fetchone()
    if not r:
        abort(404)
    cid, env = r["client_id"], r["environment"]
    get_client(cid)
    if env_servers(cid, env):
        return jsonify(error=f"There's an environment called {env} again. Remove or rename it first."), 409
    c = db()
    c.execute("BEGIN")
    for s in jload(r["servers"], []):
        c.execute("INSERT INTO servers (client_id, environment, tier, host, ip, role, os_user, domain, env_script, "
                  "ssh_port) VALUES (?,?,?,?,?,?,?,?,?,?)", (cid, *[s.get(k) for k in SERVER_COLS]))
    paused = 0
    for sc in jload(r["schedules"], []):
        cols = [k for k in sc if k != "enabled"]
        c.execute(f"INSERT OR IGNORE INTO schedules ({', '.join(cols)}, enabled) VALUES "
                  f"({', '.join('?' * len(cols))}, 0)", [sc[k] for k in cols])
        paused += 1
    c.execute("UPDATE removed_environments SET restored_at=? WHERE id=?", (time.time(), rid))
    c.execute("COMMIT")
    audit("environment_restored", cid, environment=env, schedules_paused=paused or "")
    return jsonify(ok=True, environment=env, schedules_paused=paused)


def purge_removed(now=None):
    db().execute("DELETE FROM removed_environments WHERE removed_at<?",
                 ((now or time.time()) - REMOVED_KEEP_DAYS * 86400,))


def parse_target(text):
    text = text.strip()
    port = 22
    m = re.match(r"^\[?([^\]]+?)\]?:(\d{1,5})$", text)
    if m:
        text, port = m.group(1), int(m.group(2))
    if not SAFE_HOST.match(text) or not 0 < port < 65536:
        raise ValueError(f"'{text[:60]}' isn't an IP address or host name.")
    return {"host": text, "ip": text, "ssh_port": port}


@app.post("/api/clients/<cid>/discover")
@need("admin")
def discover(cid):
    """Scan servers for PeopleSoft domains, through the client's connector. Read-only on the servers."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    texts = [t for t in re.split(r"[\s,;]+", str(body.get("targets") or "")) if t]
    users = [u for u in re.split(r"[\s,;]+", str(body.get("users") or "")) if u]
    if not texts:
        return jsonify(error="Enter at least one IP address."), 400
    if len(texts) > 20:
        return jsonify(error="Scan up to 20 servers at a time."), 400
    bad = [u for u in users if not SAFE_NAME.match(u) or u == "root"]
    if bad or len(users) > 5:
        return jsonify(error="OS users: up to 5 names, letters, digits, . _ and - only, not root."), 400
    try:
        targets = list({(t["ip"], t["ssh_port"]): t for t in map(parse_target, texts)}.values())
    except ValueError as e:
        return jsonify(error=str(e)), 400
    steps = [{"op": "discover", "target": t, "users": users, "independent": True,
              "label": "Scan for PeopleSoft domains"} for t in targets]
    try:
        jid = queue_job(cid, None, "discover", f"scan {', '.join(t['ip'] for t in targets)}", steps,
                        stop_on_failure=True)
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    audit("job_queued", cid, job=jid, title="scan servers", targets=[t["ip"] for t in targets])
    return jsonify(job=jid, servers=len(targets))


@app.post("/api/clients/<cid>/trust-host")
@need("admin")
def trust_host(cid):
    """Have the connector trust a server's SSH host key, after the operator compared the fingerprint."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    try:
        t = parse_target(str(body.get("target") or ""))
    except ValueError as e:
        return jsonify(error=str(e)), 400
    fp = str(body.get("fingerprint") or "")
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fp):
        return jsonify(error="That isn't a host key fingerprint."), 400
    try:
        jid = queue_job(cid, None, "hostkey", f"trust host key of {t['ip']}",
                        [{"op": "hostkey.trust", "target": t, "fingerprint": fp, "label": "Trust host key"}])
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    audit("host_key_trusted", cid, target=t["ip"], fingerprint=fp)
    return jsonify(job=jid)


@app.get("/api/jobs/<jid>/discovery")
@need("viewer")
def discovery_results(jid):
    j = db().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not j or j["kind"] != "discover":
        return jsonify(error="No such scan."), 404
    get_client(j["client_id"])
    out = []
    for st, r in step_results(j):
        t = st["target"]
        target = t["ip"] if int(t.get("ssh_port") or 22) == 22 else f"{t['ip']}:{t['ssh_port']}"
        if not r:
            out.append({"target": target, "error": "Not scanned (the job ended first)."})
            continue
        data = r.get("data") if isinstance(r.get("data"), dict) else None
        if data is None:
            tail = [l for l in str(r.get("output") or "").splitlines() if l.strip()]
            out.append({"target": target, "error": tail[-1][:300] if tail else "No answer from the server."})
            continue
        out.append(dict(data, target=target))
    return jsonify(status=j["status"], results=out)


def env_servers(cid, env):
    return [row(s) for s in db().execute("SELECT * FROM servers WHERE client_id=? AND environment=? ORDER BY id",
                                         (cid, env))]


def env_tier(servers):
    return next((s["tier"] for s in servers if s["tier"]), "")


def host_key(s):
    return s["ip"] or s["host"]


def unique_hosts(servers):
    seen, out = set(), []
    for s in servers:
        if host_key(s) not in seen:
            seen.add(host_key(s))
            out.append(s)
    return out


# ---------------------------------------------------------------- jobs
def is_prd(tier):
    return str(tier or "").strip().lower() in ("prd", "prod", "production")


def target_of(s):
    return {k: s[k] for k in ("host", "ip", "role", "os_user", "domain", "env_script", "ssh_port")}


def domain_steps(servers, action, **flags):
    def ordered(order, op, verb):
        return [dict({"op": op, "target": target_of(s), "label": f"{verb} {s['role']} {s['domain']}"}, **flags)
                for role in order for s in servers if s["role"] == role]
    if action == "start":
        return ordered(START_ORDER, "domain.start", "Start")
    if action == "stop":
        return ordered(STOP_ORDER, "domain.stop", "Stop")
    if action == "status":
        return ordered(START_ORDER, "domain.status", "Status of")
    raise ValueError("Unknown action.")


def plan_steps(servers, action):
    if action in ("ping", "levels"):
        return [{"op": action, "target": target_of(s),
                 "label": "Connection check" if action == "ping" else "Read patch levels"}
                for s in unique_hosts(servers)], False
    if action == "status":
        return domain_steps(servers, "status"), False
    if action in ("start", "stop"):
        return domain_steps(servers, action), True
    if action == "restart":
        return domain_steps(servers, "stop") + domain_steps(servers, "start"), True
    if action == "clearcache":
        # stop (web, scheduler, app), clear each domain's cache, then start again (app, scheduler, web). The starts
        # always run, so domains come back even if a stop or a clear failed; a clear never runs after a failed stop.
        clears = [{"op": "domain.clearcache", "target": target_of(s), "label": f"Clear cache of {s['role']} {s['domain']}"}
                  for role in STOP_ORDER for s in servers if s["role"] == role]
        return domain_steps(servers, "stop") + clears + domain_steps(servers, "start", always=True), True
    raise ValueError("Unknown action.")


# what each action needs from the connector, for actions newer connectors added
NEEDS_VERSION = {"clearcache": "0.4.0", "os": "0.5.0", "space": "0.6.0"}
OS_VERSION = NEEDS_VERSION["os"]


def os_capable(cid):
    """True when every connector of the client can check and apply Linux OS updates."""
    cons = db().execute("SELECT version FROM connectors WHERE client_id=? AND revoked=0", (cid,)).fetchall()
    return bool(cons) and not any(is_newer(OS_VERSION, c["version"] or "0") for c in cons)


def can_all(cid, action):
    """True when every connector of the client is new enough for the action."""
    cons = db().execute("SELECT version FROM connectors WHERE client_id=? AND revoked=0", (cid,)).fetchall()
    return bool(cons) and not any(is_newer(NEEDS_VERSION[action], c["version"] or "0") for c in cons)


def levels_steps(cid, servers):
    """Read middleware patch levels on every server, plus the available Linux OS updates (when the connector can)."""
    steps, _ = plan_steps(servers, "levels")
    if os_capable(cid):
        steps += [{"op": "os.check", "target": target_of(s), "label": "Check OS updates", "ignore_failure": True}
                  for s in unique_hosts(servers)]
    return steps
ACTION_TITLES = {"clearcache": "Clear cache and restart"}


def check_connectors_can(cid, action):
    """JobRefused if a connector of this client is too old for the action (any of them may pick the job up)."""
    need = NEEDS_VERSION.get(action)
    if not need:
        return
    old = [c for c in db().execute("SELECT name, version FROM connectors WHERE client_id=? AND revoked=0", (cid,))
           if is_newer(need, c["version"] or "0")]
    if old:
        names = ", ".join(f"{c['name']} ({c['version'] or 'unknown'})" for c in old)
        raise JobRefused(f"This needs connector {need} or newer; update {names} first (Overview, Update).")


class JobRefused(Exception):
    def __init__(self, msg, status=409):
        super().__init__(msg)
        self.status = status


def queue_job(cid, env, kind, title, steps, stop_on_failure=False, meta=None, created_by=None):
    if not steps:
        raise JobRefused("Nothing to run for that selection.", 400)
    if not db().execute("SELECT 1 FROM connectors WHERE client_id=? AND revoked=0", (cid,)).fetchone():
        raise JobRefused("This client has no connector yet. Add one first.")
    if env and db().execute("SELECT 1 FROM jobs WHERE client_id=? AND environment=? AND status IN ('queued','running')",
                            (cid, env)).fetchone():
        raise JobRefused(f"Something is already running or queued for {env}.")
    jid = "j_" + uuid.uuid4().hex[:16]
    now = time.time()
    db().execute("INSERT INTO jobs (id, client_id, environment, title, params, status, created_by, created_at, "
                 "expires_at, kind, meta) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                 (jid, cid, env, title, json.dumps({"steps": steps, "stop_on_failure": stop_on_failure}),
                  "queued", created_by or who(), now, now + QUEUE_TTL, kind, json.dumps(meta or {})))
    return jid


@app.post("/api/clients/<cid>/run")
@need("operator")
def run(cid):
    get_client(cid)
    body = request.get_json(silent=True) or {}
    env, action, host = str(body.get("environment") or ""), str(body.get("action") or ""), body.get("host")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    role, domain = str(body.get("role") or ""), str(body.get("domain") or "")
    if host or role or domain:
        servers = [s for s in servers if (not host or host in (s["host"], s["ip"])) and (not role or s["role"] == role)
                   and (not domain or s["domain"] == domain)]
        if not servers:
            return jsonify(error="That server or domain isn't in the environment."), 404
    tier = env_tier(servers)
    if action in ("start", "stop", "restart", "clearcache") and is_prd(tier) and \
            str(body.get("confirm") or "").upper() != env.upper():
        return jsonify(error=f"Type {env} to confirm.", need_confirm=True), 409
    try:
        steps, stop_on_failure = plan_steps(servers, action)
        check_connectors_can(cid, action)
        title = f"{ACTION_TITLES.get(action, action)} {env}" + (f" / {host}" if host else "") + \
            (f" {role} {domain}" if domain else "")
        jid = queue_job(cid, env, action, title, steps, stop_on_failure)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    audit("job_queued", cid, job=jid, title=title)
    return jsonify(job=jid, steps=len(steps))


# ---------------------------------------------------------------- schedules
SCHEDULE_ACTIONS = ("start", "stop", "restart", "clearcache")
LATE_GRACE = 15 * 60          # a run more than this late (Pegasus was down) is skipped, not started hours late
DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def schedule_days(sch):
    return sorted({int(d) for d in str(sch["days"] or "").split(",") if d.strip().isdigit() and 0 <= int(d) <= 6})


def next_occurrence(sch, after):
    """The next time (epoch seconds) strictly after `after` that this schedule fires, or None. Local wall-clock
    time in the schedule's own time zone, so 7:00 stays 7:00 across daylight-saving changes."""
    tz = ZoneInfo(sch["tz"])
    hh, mm = (int(x) for x in sch["at_time"].split(":"))
    if sch["once_date"]:
        t = dt.datetime.combine(dt.date.fromisoformat(sch["once_date"]), dt.time(hh, mm), tzinfo=tz).timestamp()
        return t if t > after else None
    days = schedule_days(sch)
    if not days:
        return None
    start = dt.datetime.fromtimestamp(after, tz).date()
    for i in range(8):
        d = start + dt.timedelta(days=i)
        if d.weekday() in days:
            t = dt.datetime.combine(d, dt.time(hh, mm), tzinfo=tz).timestamp()
            if t > after:
                return t
    return None


def schedule_view(sch):
    j = db().execute("SELECT status FROM jobs WHERE id=?", (sch["last_job"],)).fetchone() if sch["last_job"] else None
    servers = env_servers(sch["client_id"], sch["environment"])
    return {"id": sch["id"], "environment": sch["environment"], "tier": env_tier(servers), "action": sch["action"],
            "days": schedule_days(sch), "once_date": sch["once_date"], "time": sch["at_time"], "tz": sch["tz"],
            "note": sch["note"] or "", "enabled": bool(sch["enabled"]), "skip_next": bool(sch["skip_next"]),
            "created_by": sch["created_by"], "next_run": iso(sch["next_run"]), "last_run": iso(sch["last_run"]),
            "last_status": sch["last_status"], "last_detail": sch["last_detail"] or "", "last_job": sch["last_job"],
            "last_job_status": j["status"] if j else None}


def get_schedule(sid):
    sch = db().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    if not sch:
        abort(404)
    get_client(sch["client_id"])
    return sch


def describe_schedule(sch):
    days = schedule_days(sch)
    if sch["once_date"]:
        when_ = f"on {sch['once_date']}"
    elif days == [0, 1, 2, 3, 4]:
        when_ = "Mon-Fri"
    elif len(days) == 7:
        when_ = "every day"
    else:
        when_ = ", ".join(DAY_NAMES[d] for d in days)
    return f"{sch['action']} {sch['environment']} {when_} at {sch['at_time']} {sch['tz']}"


@app.get("/api/clients/<cid>/schedules")
@need("viewer")
def list_schedules(cid):
    get_client(cid)
    rs = db().execute("SELECT * FROM schedules WHERE client_id=? ORDER BY environment COLLATE NOCASE, at_time, action",
                      (cid,)).fetchall()
    return jsonify(schedules=[schedule_view(r) for r in rs])


@app.post("/api/clients/<cid>/schedules")
@need("operator")
def create_schedule(cid):
    get_client(cid)
    b = request.get_json(silent=True) or {}
    env, action = str(b.get("environment") or ""), str(b.get("action") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="Choose an environment that has servers."), 400
    if action not in SCHEDULE_ACTIONS:
        return jsonify(error="Choose start, stop, restart or clear cache."), 400
    at_time = str(b.get("time") or "")
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", at_time):
        return jsonify(error="Enter the time as HH:MM (24-hour)."), 400
    tz = str(b.get("tz") or "")
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        return jsonify(error="Choose a valid time zone."), 400
    once, days = b.get("once_date"), ""
    if once:
        try:
            dt.date.fromisoformat(str(once))
        except ValueError:
            return jsonify(error="Enter the date as YYYY-MM-DD."), 400
        once = str(once)
    else:
        try:
            ds = sorted({int(d) for d in b.get("days") or [] if 0 <= int(d) <= 6})
        except (TypeError, ValueError):
            ds = []
        if not ds:
            return jsonify(error="Pick at least one day."), 400
        days = ",".join(str(d) for d in ds)
    if is_prd(env_tier(servers)) and str(b.get("confirm") or "").upper() != env.upper():
        return jsonify(error=f"Type {env} to confirm a schedule on production.", need_confirm=True), 409
    sch = {"id": "s_" + uuid.uuid4().hex[:12], "client_id": cid, "environment": env, "action": action,
           "days": days, "once_date": once or None, "at_time": at_time, "tz": tz,
           "note": re.sub(r"[^\x20-\x7e]", "", str(b.get("note") or ""))[:200]}
    nxt = next_occurrence(sch, time.time())
    if nxt is None:
        return jsonify(error="That date and time have already passed."), 400
    db().execute("INSERT INTO schedules (id, client_id, environment, action, days, once_date, at_time, tz, note, "
                 "created_by, created_at, next_run) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                 (sch["id"], cid, env, action, days, sch["once_date"], at_time, tz, sch["note"], who(), time.time(), nxt))
    audit("schedule_created", cid, schedule=sch["id"], what=describe_schedule(sch), next_run=iso(nxt))
    return jsonify(schedule_view(db().execute("SELECT * FROM schedules WHERE id=?", (sch["id"],)).fetchone()))


HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


@app.get("/api/clients/<cid>/schedules/weekly")
@need("viewer")
def get_weekly_plan(cid):
    """The environment's weekly plan: a start and a stop time (or none) for each day of the week."""
    get_client(cid)
    env = str(request.args.get("environment") or "")
    plan = [{"day": d, "start": "", "stop": ""} for d in range(7)]
    tz = ""
    for r in db().execute("SELECT * FROM schedules WHERE client_id=? AND environment=? AND plan='weekly'", (cid, env)):
        tz = tz or r["tz"]
        for d in schedule_days(r):
            plan[d][r["action"]] = r["at_time"]
    return jsonify(environment=env, tz=tz, plan=plan)


@app.put("/api/clients/<cid>/schedules/weekly")
@need("operator")
def put_weekly_plan(cid):
    """Replace the environment's weekly plan. Days that share a time become one schedule (e.g. start Mon-Fri 07:00),
    so the schedule list stays short; other schedules of the environment are left alone."""
    get_client(cid)
    b = request.get_json(silent=True) or {}
    env = str(b.get("environment") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="Choose an environment that has servers."), 400
    tz = str(b.get("tz") or "")
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError):
        return jsonify(error="Choose a valid time zone."), 400
    groups = {}                                  # (action, time) -> days
    for row_ in b.get("plan") or []:
        try:
            d = int(row_.get("day"))
        except (TypeError, ValueError):
            return jsonify(error="Each day needs a number from 0 (Monday) to 6 (Sunday)."), 400
        if not 0 <= d <= 6:
            return jsonify(error="Each day needs a number from 0 (Monday) to 6 (Sunday)."), 400
        for action in ("start", "stop"):
            t = str(row_.get(action) or "").strip()
            if not t:
                continue
            if not HHMM.match(t):
                return jsonify(error=f"Enter {action} times as HH:MM (24-hour)."), 400
            groups.setdefault((action, t), set()).add(d)
    if groups and is_prd(env_tier(servers)) and str(b.get("confirm") or "").upper() != env.upper():
        return jsonify(error=f"Type {env} to confirm a schedule on production.", need_confirm=True), 409
    old = db().execute("DELETE FROM schedules WHERE client_id=? AND environment=? AND plan='weekly'",
                       (cid, env)).rowcount
    made = []
    for (action, t), ds in sorted(groups.items(), key=lambda x: (min(x[1]), x[0][0] != "start", x[0][1])):
        sch = {"id": "s_" + uuid.uuid4().hex[:12], "client_id": cid, "environment": env, "action": action,
               "days": ",".join(str(d) for d in sorted(ds)), "once_date": None, "at_time": t, "tz": tz,
               "note": "Weekly plan"}
        nxt = next_occurrence(sch, time.time())
        db().execute("INSERT INTO schedules (id, client_id, environment, action, days, once_date, at_time, tz, note, "
                     "created_by, created_at, next_run, plan) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'weekly')",
                     (sch["id"], cid, env, action, sch["days"], None, t, tz, sch["note"], who(), time.time(), nxt))
        made.append(describe_schedule(sch))
    audit("weekly_plan_saved", cid, environment=env, schedules=made or "none", replaced=old)
    return jsonify(ok=True, schedules=len(made), described=made)


@app.patch("/api/schedules/<sid>")
@need("operator")
def change_schedule(sid):
    sch = get_schedule(sid)
    b = request.get_json(silent=True) or {}
    changes = {}
    if "enabled" in b:
        changes["enabled"] = 1 if b["enabled"] else 0
        if b["enabled"]:                                  # resuming: the next run from now, not a missed one
            changes["next_run"] = next_occurrence(sch, time.time())
    if "skip_next" in b:
        changes["skip_next"] = 1 if b["skip_next"] else 0
    if not changes:
        return jsonify(error="Nothing to change."), 400
    db().execute(f"UPDATE schedules SET {', '.join(k + '=?' for k in changes)} WHERE id=?",
                 (*changes.values(), sid))
    what = ("resumed" if changes.get("enabled") else "paused") if "enabled" in changes else \
        ("will skip its next run" if changes["skip_next"] else "won't skip its next run")
    audit("schedule_changed", sch["client_id"], schedule=sid, what=describe_schedule(sch), change=what)
    return jsonify(schedule_view(db().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()))


@app.delete("/api/schedules/<sid>")
@need("operator")
def delete_schedule(sid):
    sch = get_schedule(sid)
    db().execute("DELETE FROM schedules WHERE id=?", (sid,))
    audit("schedule_deleted", sch["client_id"], schedule=sid, what=describe_schedule(sch))
    return jsonify(ok=True)


def run_due_schedules(now=None):
    """Queue every schedule that is due. Called every 30 seconds by the scheduler thread."""
    now = now or time.time()
    due = db().execute("SELECT * FROM schedules WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=? "
                       "ORDER BY next_run", (now,)).fetchall()
    for sch in due:
        at = sch["next_run"]
        nxt = next_occurrence(sch, max(now, at))
        claimed = db().execute("UPDATE schedules SET next_run=? WHERE id=? AND next_run=?", (nxt, sch["id"], at))
        if not claimed.rowcount:
            continue                                       # another round already handled it
        job, detail = None, ""
        servers = env_servers(sch["client_id"], sch["environment"])
        if sch["skip_next"]:
            status, detail = "skipped", "skipped once, as requested"
        elif now - at > LATE_GRACE:
            status, detail = "missed", f"Pegasus wasn't running at {iso(at)}, and it's too late to run it now"
        elif not servers:
            status, detail = "skipped", "the environment has no servers"
        else:
            try:
                steps, stop_on_failure = plan_steps(servers, sch["action"])
                check_connectors_can(sch["client_id"], sch["action"])
                job = queue_job(sch["client_id"], sch["environment"], sch["action"],
                                f"{ACTION_TITLES.get(sch['action'], sch['action'])} {sch['environment']} (scheduled)",
                                steps, stop_on_failure,
                                meta={"schedule": sch["id"]}, created_by="schedule")
                status = "queued"
            except JobRefused as e:
                status, detail = "skipped", str(e)
        db().execute("UPDATE schedules SET last_run=?, last_status=?, last_job=?, last_detail=?, skip_next=CASE "
                     "WHEN ?='skipped' AND skip_next=1 THEN 0 ELSE skip_next END WHERE id=?",
                     (at, status, job, detail, status, sch["id"]))
        audit("schedule_ran" if job else "schedule_" + status, sch["client_id"], actor="schedule",
              schedule=sch["id"], what=describe_schedule(sch), job=job or "", reason=detail,
              next_run=iso(nxt) or "none")


def schedule_loop():
    while True:
        time.sleep(30)
        try:
            with app.app_context():
                run_due_schedules()
                expire_access()
                check_access_jira()
                run_patch_watch()
                purge_removed()
        except Exception as e:                       # keep going even if one round fails
            app.logger.warning("scheduled start/stop failed: %s", e)


def expire_stale(cid=None):
    now = time.time()
    where, args = ("AND client_id=?", (cid,)) if cid else ("", ())
    db().execute(f"UPDATE jobs SET status='expired', finished_at=?, note='no connector picked it up in time' "
                 f"WHERE status='queued' AND expires_at<? {where}", (now, now, *args))
    db().execute(f"UPDATE jobs SET status='failed', finished_at=?, note='the connector stopped responding' "
                 f"WHERE status='running' {where} AND connector_id IN "
                 f"(SELECT id FROM connectors WHERE last_seen<?)", (now, *args, now - LOST_AFTER))
    finalize_pending()


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
    meta = jload(j["meta"], {}) or {}
    out = {"id": j["id"], "environment": j["environment"], "title": j["title"], "status": j["status"],
           "kind": j["kind"], "created_by": j["created_by"], "created_at": iso(j["created_at"]),
           "finished_at": iso(j["finished_at"]), "note": j["note"], "followup": meta.get("followup")}
    if with_steps:
        steps = json.loads(j["params"])["steps"]
        results = {r["step"]: r for r in jload(j["results"], []) or []}
        out["steps"] = []
        for i, st in enumerate(steps):
            r = results.get(i)
            t = st.get("target") or {}
            item = {"label": st.get("label") or st["op"], "host": t.get("host", ""), "op": st["op"],
                    "exit_code": r["exit_code"] if r else None, "done": bool(r)}
            if r and st["op"].startswith("domain."):
                item["state"] = domain_state(t.get("role"), st["op"], r.get("output"), r["exit_code"])
            out["steps"].append(item)
    return out


def recent_jobs(cid, limit=25):
    return [job_view(j) for j in db().execute(
        "SELECT * FROM jobs WHERE client_id=? AND COALESCE(kind,'')<>'status_auto' ORDER BY created_at DESC LIMIT ?",
        (cid, limit))]


@app.get("/api/jobs/<jid>")
@need("viewer")
def get_job(jid):
    j = db().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    if not j:
        return jsonify(error="No such job."), 404
    get_client(j["client_id"])
    expire_stale(j["client_id"])
    j = db().execute("SELECT * FROM jobs WHERE id=?", (jid,)).fetchone()
    since = int(request.args.get("since", 0) or 0)
    ev_rows = db().execute("SELECT seq, text FROM job_events WHERE job_id=? AND seq>=? ORDER BY seq",
                           (jid, since)).fetchall()
    out = job_view(j, with_steps=True)
    out.update(text="".join(e["text"] or "" for e in ev_rows), next=(ev_rows[-1]["seq"] + 1) if ev_rows else since)
    return jsonify(out)


# ---------------------------------------------------------------- what happens when a job finishes
def finalize_pending():
    """Process finished jobs once: store patch levels, Oracle catalog, staged files, SSH key results, and close
    change requests. Runs after a connector reports a job done, and after jobs expire or lose their connector."""
    with _finalize_lock:
        c = db()
        js = c.execute("SELECT * FROM jobs WHERE finalized=0 AND status NOT IN ('queued','running')").fetchall()
        for j in js:
            c.execute("UPDATE jobs SET finalized=1 WHERE id=?", (j["id"],))
            try:
                finalize(j)
            except Exception as e:           # never let bookkeeping break the connector API
                app.logger.exception("finalizing %s failed: %s", j["id"], e)


def step_results(j):
    steps = json.loads(j["params"])["steps"]
    res = {r.get("step"): r for r in jload(j["results"], []) or [] if isinstance(r, dict)}
    return [(st, res.get(i)) for i, st in enumerate(steps)]


def store_os(cid, env, st, r):
    """Keep a server's OS update check with its patch levels."""
    t = st.get("target") or {}
    hk = t.get("ip") or t.get("host")
    data = (r.get("data") or {}).get("os") if isinstance(r.get("data"), dict) else None
    if not hk:
        return
    if not data:
        tail = [l for l in str(r.get("output") or "").splitlines() if l.strip()]
        data = {"error": tail[-1][:300] if tail else "No answer from the server."}
    row_ = db().execute("SELECT data FROM levels WHERE client_id=? AND environment=? AND host_key=?",
                        (cid, env, hk)).fetchone()
    lv = jload(row_["data"], {}) if row_ else {}
    lv["os"] = data
    db().execute("INSERT INTO levels (client_id, environment, host_key, host, data, checked_at) VALUES (?,?,?,?,?,?) "
                 "ON CONFLICT(client_id, environment, host_key) DO UPDATE SET data=excluded.data",
                 (cid, env, hk, t.get("host") or hk, json.dumps(lv), time.time()))


def store_levels(cid, env, st, r):
    t = st.get("target") or {}
    hk = t.get("ip") or t.get("host")
    if not hk:
        return
    if r and r.get("exit_code") == 0 and isinstance(r.get("data"), dict):
        data = r["data"]
    else:
        tail = [l for l in str((r or {}).get("output") or "").splitlines() if l.strip()]
        data = {"error": (tail[-1][:300] if tail else "No answer from the server.")}
    db().execute("INSERT INTO levels (client_id, environment, host_key, host, data, checked_at) VALUES (?,?,?,?,?,?) "
                 "ON CONFLICT(client_id, environment, host_key) DO UPDATE SET host=excluded.host, data=excluded.data, "
                 "checked_at=excluded.checked_at", (cid, env, hk, t.get("host") or hk, json.dumps(data), time.time()))


def queue_catalog(cid, created_by="pegasus", refresh=False):
    """Ask the client's connector to look up the latest Oracle releases for the JDKs and products it has seen."""
    if db().execute("SELECT 1 FROM jobs WHERE client_id=? AND kind='catalog' AND status IN ('queued','running')",
                    (cid,)).fetchone():
        return None
    majors, versions = set(), set()
    for r in db().execute("SELECT data FROM levels WHERE client_id=?", (cid,)):
        jdk = (jload(r["data"], {}) or {}).get("jdk") or {}
        if jdk.get("version"):
            versions.add(jdk["version"])
            majors.add(ev.jdk_major(jdk["version"]))
    majors = {m for m in majors if re.fullmatch(r"\d{1,3}", m)}
    versions = {v for v in versions if re.fullmatch(r"[0-9][0-9._]{0,30}", v)}
    step = {"op": "catalog", "label": "Look up the latest Oracle releases", "jdk_majors": sorted(majors)[:10],
            "jdk_versions": sorted(versions)[:50], "refresh": refresh}
    try:
        return queue_job(cid, None, "catalog", "look up latest Oracle patches", [step], created_by=created_by)
    except JobRefused:
        return None


def record_states(j, pairs):
    """Remember each domain's last known state from status, start, stop, restart and patch runs."""
    for st, r in pairs:
        if not r or not str(st.get("op", "")).startswith("domain."):
            continue
        t = st.get("target") or {}
        env = st.get("environment") or j["environment"]
        state = "unreachable" if r.get("exit_code") is None else \
            domain_state(t.get("role"), st["op"], r.get("output"), r.get("exit_code"))
        if not env or not state:
            continue
        db().execute("INSERT INTO domain_states (client_id, environment, host_key, role, domain, state, at, job_id) "
                     "VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(client_id, environment, host_key, role, domain) DO UPDATE "
                     "SET state=excluded.state, at=excluded.at, job_id=excluded.job_id",
                     (j["client_id"], env, t.get("ip") or t.get("host"), t.get("role"), t.get("domain"), state,
                      time.time(), j["id"]))


def connector_online(cid):
    return bool(db().execute("SELECT 1 FROM connectors WHERE client_id=? AND revoked=0 AND last_seen>?",
                             (cid, time.time() - ONLINE_WINDOW)).fetchone())


def maybe_auto_status(cid, force=False):
    """Queue one status check of every domain of the client, unless one ran recently or is already waiting."""
    if not STATUS_EVERY and not force:
        return None
    if not connector_online(cid):
        return None
    if db().execute("SELECT 1 FROM jobs WHERE client_id=? AND kind='status_auto' AND status IN ('queued','running')",
                    (cid,)).fetchone():
        return None
    last = db().execute("SELECT MAX(created_at) t FROM jobs WHERE client_id=? AND kind='status_auto'",
                        (cid,)).fetchone()["t"] or 0
    if not force and time.time() - last < STATUS_EVERY:
        return None
    servers = [row(s) for s in db().execute("SELECT * FROM servers WHERE client_id=? ORDER BY environment, id", (cid,))]
    steps = []
    for env in dict.fromkeys(s["environment"] for s in servers):
        steps += domain_steps([s for s in servers if s["environment"] == env], "status", environment=env,
                              independent=True)
    if not steps:
        return None
    try:
        return queue_job(cid, None, "status_auto", "automatic status check", steps, created_by="Pegasus (automatic)")
    except JobRefused:
        return None


def auto_status_loop():
    while True:
        time.sleep(30)
        try:
            with app.app_context():
                for c in db().execute("SELECT id FROM clients").fetchall():
                    maybe_auto_status(c["id"])
                expire_stale()
        except Exception as e:                       # keep checking even if one round fails
            app.logger.warning("automatic status check failed: %s", e)


@app.get("/api/clients/<cid>/states")
@need("viewer")
def client_states(cid):
    get_client(cid)
    expire_stale(cid)
    if request.args.get("now") and can_operate():
        maybe_auto_status(cid, force=True)
    else:
        maybe_auto_status(cid)
    states = {f"{r['environment']}|{r['host_key']}|{r['role']}|{r['domain']}": {"state": r["state"], "at": iso(r["at"])}
              for r in db().execute("SELECT * FROM domain_states WHERE client_id=?", (cid,))}
    auto = db().execute("SELECT * FROM jobs WHERE client_id=? AND kind='status_auto' ORDER BY created_at DESC LIMIT 1",
                        (cid,)).fetchone()
    return jsonify(states=states, checking=bool(auto and auto["status"] in ("queued", "running")),
                   last_auto=iso(auto["finished_at"]) if auto else None, every=STATUS_EVERY,
                   online=connector_online(cid))


def can_operate():
    u = current_user()
    return bool(u and auth.ROLE_RANK[u["role"]] >= auth.ROLE_RANK["operator"])


def finalize(j):
    cid, env, kind = j["client_id"], j["environment"], j["kind"]
    meta = jload(j["meta"], {}) or {}
    pairs = step_results(j)
    record_states(j, pairs)
    if kind in ("levels", "apply"):
        for st, r in pairs:
            if st["op"] == "levels" and r:
                store_levels(cid, env, st, r)
        for st, r in pairs:
            if st["op"] == "os.check" and r:
                store_os(cid, env, st, r)
        if kind == "levels" and j["status"] in ("succeeded", "failed"):
            follow = queue_catalog(cid, j["created_by"])
            if follow:
                meta["followup"] = follow
                db().execute("UPDATE jobs SET meta=? WHERE id=?", (json.dumps(meta), j["id"]))
    if kind == "catalog":
        for st, r in pairs:
            if st["op"] == "catalog" and r and isinstance(r.get("data"), dict):
                db().execute("INSERT INTO catalog (client_id, data, checked_at) VALUES (?,?,?) ON CONFLICT(client_id) "
                             "DO UPDATE SET data=excluded.data, checked_at=excluded.checked_at",
                             (cid, json.dumps(r["data"]), time.time()))
    if kind == "stage":
        for st, r in pairs:
            if st["op"] == "os.download" and r and r.get("exit_code") == 0 and st.get("key"):
                hk = st["target"].get("ip") or st["target"].get("host")
                db().execute("INSERT INTO staged (client_id, environment, host_key, patch_key, dir, files, at) "
                             "VALUES (?,?,?,?,?,?,?) ON CONFLICT(client_id, environment, host_key, patch_key) DO "
                             "UPDATE SET dir=excluded.dir, files=excluded.files, at=excluded.at",
                             (cid, env, hk, st["key"], "package manager cache", json.dumps(["downloaded"]), time.time()))
        for st, r in pairs:
            if st["op"] == "patch.stage" and r and r.get("exit_code") == 0:
                hk = st["target"].get("ip") or st["target"].get("host")
                for key, v in ((r.get("data") or {}).get("staged") or {}).items():
                    db().execute("INSERT INTO staged (client_id, environment, host_key, patch_key, dir, files, at) "
                                 "VALUES (?,?,?,?,?,?,?) ON CONFLICT(client_id, environment, host_key, patch_key) DO "
                                 "UPDATE SET dir=excluded.dir, files=excluded.files, at=excluded.at",
                                 (cid, env, hk, key, v.get("dir", ""), json.dumps(v.get("files") or []), time.time()))
        audit("patches_staged", cid, actor=j["created_by"], job=j["id"], environment=env, result=j["status"])
    if kind == "apply":
        short = space_refused(pairs)
        audit("patches_applied", cid, actor=j["created_by"], job=j["id"], environment=env, result=j["status"],
              not_started="not enough disk space" if short is not None else None)
        if meta.get("cr") and short is not None:
            # nothing was stopped or changed, so the approval still stands for the same plan
            db().execute("UPDATE change_requests SET status='approved', job_id=NULL WHERE id=?", (meta["cr"],))
            cr = db().execute("SELECT * FROM change_requests WHERE id=?", (meta["cr"],)).fetchone()
            tail = "\n".join(l for l in short.splitlines() if l.strip())[-3000:]
            jira_later(cid, cr["jira_key"],
                       f"Pegasus did NOT start this change on {now_text()}: there isn't enough free disk space on "
                       f"the server(s). Nothing was stopped or changed, and this approval can still be used once "
                       f"space has been freed. Job {j['id']}.\n\n{{noformat}}\n"
                       + tail.replace("{noformat}", "{ noformat}") + "\n{noformat}")
        elif meta.get("cr"):
            ok = j["status"] == "succeeded"
            db().execute("UPDATE change_requests SET status=?, finished_at=? WHERE id=?",
                         ("applied" if ok else "failed", time.time(), meta["cr"]))
            cr = db().execute("SELECT * FROM change_requests WHERE id=?", (meta["cr"],)).fetchone()
            text = "".join(e["text"] or "" for e in db().execute(
                "SELECT text FROM job_events WHERE job_id=? ORDER BY seq", (j["id"],)))
            tail = "\n".join(text.splitlines()[-40:])
            report = (f"Pegasus finished applying on {now_text()}: *{'SUCCEEDED' if ok else 'FAILED'}*"
                      + (f" ({j['note']})" if j["note"] else "") + f".\nJob {j['id']}. The full log is in Pegasus.\n\n"
                      "{noformat}\n" + tail.replace("{noformat}", "{ noformat}") + "\n{noformat}")
            jira_later(cid, cr["jira_key"], report, "done_transition" if ok else None)
    if kind and kind.startswith("access"):
        record_access(j, pairs)


def jira_for(cid):
    cfg = jiramod.config(get_setting(cid, "jira", {}))
    return jiramod.Jira(cfg, box().open(get_setting(cid, "jira_token", "")))


def jira_later(cid, key, comment, transition_field=None):
    """Comment on (and optionally move) a ticket without holding up the request that triggered it."""
    cfg = jiramod.config(get_setting(cid, "jira", {}))
    token = box().open(get_setting(cid, "jira_token", ""))

    def work():
        try:
            j = jiramod.Jira(cfg, token)
            j.comment(key, comment)
            if transition_field:
                j.transition(key, cfg.get(transition_field))
        except jiramod.JiraError as e:
            c = connect()
            c.execute("INSERT INTO audit (at, actor, client_id, event, detail) VALUES (?,?,?,?,?)",
                      (time.time(), "pegasus", cid, "jira_update_failed", json.dumps({"ticket": key, "error": str(e)})))
            c.close()
    t = threading.Thread(target=work, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------- patching: levels, latest releases, staging
def patch_settings(cid):
    return {"staging_root": get_setting(cid, "staging_root", DEFAULT_STAGING),
            "targets": get_setting(cid, "cpu_targets", []),
            # monthly: every release as Oracle ships it; quarterly: only Critical Patch Updates (what the client signed up for)
            "cadence": get_setting(cid, "patch_cadence", "monthly")}


def env_levels(cid, env):
    return {r["host_key"]: dict(jload(r["data"], {}) or {}, host=r["host"], checked_at=r["checked_at"])
            for r in db().execute("SELECT * FROM levels WHERE client_id=? AND environment=?", (cid, env))}


def client_catalog(cid):
    r = db().execute("SELECT * FROM catalog WHERE client_id=?", (cid,)).fetchone()
    return (jload(r["data"], {}) or {}, r["checked_at"]) if r else ({}, None)


def env_staged(cid, env):
    out = {}
    for r in db().execute("SELECT * FROM staged WHERE client_id=? AND environment=?", (cid, env)):
        out.setdefault(r["host_key"], {})[r["patch_key"]] = {"dir": r["dir"], "files": jload(r["files"], []),
                                                             "at": iso(r["at"])}
    return out


def posture(cid, env):
    """Per host: installed levels, what's newer, and what's already staged."""
    servers = env_servers(cid, env)
    levels, staged = env_levels(cid, env), env_staged(cid, env)
    cat, cat_at = client_catalog(cid)
    ps = patch_settings(cid)
    targets, cadence = ps["targets"], ps["cadence"]
    java_dates = dict(cat.get("java_dates") or {})
    for info in (cat.get("java") or {}).values():         # a JDK just updated to the latest release
        if info.get("version") and info.get("date"):
            java_dates.setdefault(info["version"], info["date"])
    hosts = []
    for s in unique_hosts(servers):
        hk = host_key(s)
        lv = levels.get(hk)
        roles = sorted({x["role"] for x in servers if host_key(x) == hk})
        h = {"host": s["host"], "ip": s["ip"], "host_key": hk, "roles": roles, "checked": None, "items": [],
             "pt": "", "warnings": [], "error": ""}
        if lv:
            h.update(checked=iso(lv["checked_at"]), pt=lv.get("pt", ""), warnings=lv.get("warnings", []),
                     error=lv.get("error", ""))
            if not lv.get("error"):
                items = ev.apply_cadence(ev.evaluate(lv, targets, cat.get("java"), cat.get("oracle"), java_dates),
                                         cadence)
                osi = ev.os_item(lv.get("os"))
                if osi:
                    items.insert(0, osi)
                hs = staged.get(hk, {})
                for it in items:
                    st = hs.get(it.get("key") or "-")
                    if st and it.get("needs_opatch") and ev.OPATCH_19_KEY not in hs:
                        st = None              # OPatch for the Database client goes with it
                    it["staged"] = st
                h["items"] = items
        hosts.append(h)
    return {"hosts": hosts, "catalog": cat, "catalog_checked": iso(cat_at), "servers": servers}


def outstanding_groups(hosts):
    groups = []
    for h in hosts:
        for it in h["items"]:
            if it["status"] == "needed" and it.get("key") and (it["component"], it["key"]) not in groups:
                groups.append((it["component"], it["key"]))
    return groups


def change_request_view(cr):
    out = {k: cr[k] for k in ("id", "environment", "scope", "jira_key", "url", "summary", "notes", "requested_by",
                              "change_type", "status", "approval", "jira_status", "approver", "job_id")}
    out.update(hosts=jload(cr["hosts"], []), window=jload(cr["window"], {}), requested_at=iso(cr["requested_at"]),
               checked_at=iso(cr["checked_at"]), finished_at=iso(cr["finished_at"]))
    return out


def approval_required(cid, tier):
    c = jiramod.config(get_setting(cid, "jira", {}))
    return bool(c["enabled"]) and (c["require"] == "all" or is_prd(tier))


def refresh_cr(cr, j):
    if cr["status"] not in ("pending", "approved"):
        return cr
    state, name, approver = j.approval_state(cr["jira_key"])
    status = {"approved": "approved", "rejected": "rejected"}.get(state, "pending")
    db().execute("UPDATE change_requests SET status=?, approval=?, jira_status=?, approver=?, checked_at=? WHERE id=?",
                 (status, state, name, approver, time.time(), cr["id"]))
    return db().execute("SELECT * FROM change_requests WHERE id=?", (cr["id"],)).fetchone()


@app.get("/api/clients/<cid>/patching")
@need("viewer")
def patching_view(cid):
    get_client(cid)
    env = str(request.args.get("environment") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    p = posture(cid, env)
    cat = p["catalog"]
    crs = db().execute("SELECT * FROM change_requests WHERE client_id=? AND environment=? ORDER BY requested_at DESC",
                       (cid, env)).fetchall()
    latest = {}
    for c in crs:
        latest.setdefault(c["scope"], c)
    jira_error = None
    jcfg = jiramod.config(get_setting(cid, "jira", {}))
    if request.args.get("refresh") and jcfg["enabled"]:
        try:
            jc = None
            for scope, c in latest.items():
                if c["status"] in ("pending", "approved"):
                    jc = jc or jira_for(cid)
                    latest[scope] = refresh_cr(c, jc)
        except jiramod.JiraError as e:
            jira_error = str(e)
    tier = env_tier(servers)
    return jsonify(environment=env, tier=tier, hosts=p["hosts"], cpu=ev.cpu_dates(),
                   catalog_checked=p["catalog_checked"], oracle_error=(cat.get("oracle") or {}).get("error"),
                   infra_dpk=(cat.get("oracle") or {}).get("infra_dpk"), settings=patch_settings(cid),
                   approval={"enabled": bool(jcfg["enabled"]), "required": approval_required(cid, tier),
                             "error": jira_error},
                   change_requests=[change_request_view(c) for c in latest.values()],
                   outstanding=len(outstanding_groups(p["hosts"])), advisory=advisory_view())


@app.post("/api/clients/<cid>/patching/check")
@need("operator")
def patching_check(cid):
    """Read installed levels on every server of the environment; the connector then looks up Oracle's latest."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    env = str(body.get("environment") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    steps = levels_steps(cid, servers)
    try:
        jid = queue_job(cid, env, "levels", f"check patch levels {env}", steps)
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    if body.get("refresh"):
        db().execute("DELETE FROM catalog WHERE client_id=?", (cid,))
    audit("job_queued", cid, job=jid, title=f"check patch levels {env}")
    return jsonify(job=jid)


@app.post("/api/clients/<cid>/patching/lookup")
@need("operator")
def patching_lookup(cid):
    """Look up the latest Oracle releases again (fresh from Oracle, not the connector's 12-hour cache)."""
    get_client(cid)
    jid = queue_catalog(cid, who(), refresh=True)
    if not jid:
        return jsonify(error="A lookup is already queued or running, or this client has no connector."), 409
    return jsonify(job=jid)


def select_items(hosts, body):
    """[(host dict, item)] for the updates the request names: items=[{host_key, key}] or all=true (every needed)."""
    want = {(str(i.get("host_key") or i.get("ip") or i.get("host")), str(i.get("key"))) for i in body.get("items") or []}
    out = []
    for h in hosts:
        for it in h["items"]:
            if it["status"] != "needed" or not it.get("key"):
                continue
            if body.get("all") or (h["host_key"], it["key"]) in want or (h["host"], it["key"]) in want:
                out.append((h, it))
    return out


@app.post("/api/clients/<cid>/patching/stage")
@need("operator")
def patching_stage(cid):
    """Download the selected updates on the connector and copy them to each server's staging folder."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    env = str(body.get("environment") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    p = posture(cid, env)
    chosen = select_items(p["hosts"], body)
    if not chosen:
        return jsonify(error="Select at least one outstanding update to download."), 400
    try:
        jid, keys, hosts = queue_stage(cid, env, servers, chosen)
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    audit("job_queued", cid, job=jid, title=f"download and stage {env}", keys=keys)
    return jsonify(job=jid, hosts=hosts, updates=len(keys))


def queue_stage(cid, env, servers, chosen, created_by=None):
    """Queue one job that downloads the chosen updates on the connector and stages them on each server.
    Returns (job id, update keys, number of hosts). Raises JobRefused."""
    keys, per_host, os_hosts = [], {}, {}
    for h, it in chosen:
        if it["component"] == "os":
            os_hosts[h["host_key"]] = it
            continue
        need_keys = [(it["key"], ev.stage_label(it))]
        if it.get("needs_opatch"):
            need_keys.append((ev.OPATCH_19_KEY, "p6880880"))
        for k, label in need_keys:
            if k not in keys:
                keys.append(k)
            items = per_host.setdefault(h["host_key"], [])
            if k not in [x["key"] for x in items]:
                items.append({"key": k, "label": label})
    root = patch_settings(cid)["staging_root"]
    by_key = {host_key(s): s for s in unique_hosts(servers)}
    if os_hosts:
        check_connectors_can(cid, "os")
    steps = [{"op": "patch.download", "label": f"Download {len(keys)} update(s) on the connector", "keys": keys}] \
        if keys else []
    for hk, items in per_host.items():
        steps.append({"op": "patch.stage", "target": target_of(by_key[hk]), "stage_root": root, "items": items,
                      "label": f"Stage {len(items)} file set(s) in {root}", "independent": True})
    for hk, it in os_hosts.items():         # OS packages download into the server's own package cache
        steps.append({"op": "os.download", "target": target_of(by_key[hk]), "key": it["key"], "independent": True,
                      "label": f"Download OS updates ({it.get('latest_label') or it['target']}) on the server"})
    jid = queue_job(cid, env, "stage", f"download and stage CPU patches {env}", steps, stop_on_failure=True,
                    created_by=created_by)
    return jid, keys + [it["key"] for it in os_hosts.values()][:1], len(set(per_host) | set(os_hosts))


# ---------------------------------------------------------------- Oracle's CPU advisory (risk scores)
def fetch_advisory_page(url):
    import requests
    r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0 (Pegasus CPU advisory reader)"})
    r.raise_for_status()
    return r.text


def refresh_advisory(now=None, force=False):
    """Read the latest CPU advisory's risk matrices once a day (retrying hourly if it fails). The control plane does
    this itself: the page is public, and no client data is involved."""
    now = now or time.time()
    cpu = ev.cpu_dates()["last"]
    cur = get_setting("_global", "cpu_advisory", {}) or {}
    if not force:
        if cur.get("cpu") == cpu and not cur.get("error") and now - cur.get("fetched", 0) < 24 * 3600:
            return cur
        if now - cur.get("tried", 0) < 3600:
            return cur
    url = advisory.advisory_url(cpu)
    try:
        found = advisory.parse(fetch_advisory_page(url))
        data = {"cpu": cpu, "url": url, "fetched": now, "tried": now, "components": found,
                "error": "" if found else "Oracle's advisory page didn't have the risk matrices Pegasus expects."}
        if not found and cur.get("components"):
            data = dict(cur, tried=now, error=data["error"])
    except Exception as e:
        data = dict(cur, tried=now, error=f"Couldn't read Oracle's advisory ({url}): {e}")
        data.setdefault("cpu", cpu)
        data.setdefault("url", url)
    put_setting("_global", "cpu_advisory", data)
    return data


def advisory_loop():
    while True:
        try:
            with app.app_context():
                refresh_advisory()
        except Exception as e:
            app.logger.warning("reading the CPU advisory failed: %s", e)
        time.sleep(300)


def advisory_view():
    a = get_setting("_global", "cpu_advisory", {}) or {}
    comps = {k: dict(v, severity=advisory.severity(v["max"]), title=advisory.TITLES.get(k, k))
             for k, v in (a.get("components") or {}).items()}
    return {"cpu": a.get("cpu"), "url": a.get("url") or advisory.advisory_url(ev.cpu_dates()["last"]),
            "components": comps, "checked": iso(a.get("fetched")), "error": a.get("error") or ""}


# ---------------------------------------------------------------- patch watch (automatic checks and staging)
WATCH_DEFAULT = {"check": True, "stage": "nonprod"}      # stage: off | nonprod | all


def watch_settings(cid):
    w = dict(WATCH_DEFAULT)
    w.update(get_setting(cid, "patch_watch", {}) or {})
    return w


def queue_levels(cid, envs, created_by):
    """Read patch levels on every server of these environments (read-only); a lookup of Oracle's latest follows."""
    jobs = []
    for env in envs:
        servers = env_servers(cid, env)
        if not servers:
            continue
        steps = levels_steps(cid, servers)
        try:
            jobs.append(queue_job(cid, env, "levels", f"check patch levels {env}", steps, created_by=created_by))
        except JobRefused:
            pass
    return jobs


def client_envs(cid):
    return [r["environment"] for r in db().execute(
        "SELECT DISTINCT environment FROM servers WHERE client_id=? ORDER BY environment", (cid,))]


def run_patch_watch(now=None):
    """Per client, every PATCH_WATCH_HOURS: re-read patch levels and Oracle's latest releases, then (if the client's
    admins allow it) download and stage the outstanding updates, so they're ready to read about and apply. Staging
    only copies files into the staging folder; nothing is installed or restarted."""
    now = now or time.time()
    for c in db().execute("SELECT id FROM clients").fetchall():
        cid = c["id"]
        w, st = watch_settings(cid), get_setting(cid, "patch_watch_state", {}) or {}
        if not w["check"]:
            continue
        if st.get("phase") == "checking":
            busy = db().execute("SELECT 1 FROM jobs WHERE client_id=? AND kind IN ('levels','catalog') AND status IN "
                                "('queued','signed','running')", (cid,)).fetchone()
            if busy and now - st.get("started", now) < 2 * 3600:
                continue
            outstanding, staged_jobs = {}, []
            for env in client_envs(cid):
                servers = env_servers(cid, env)
                p = posture(cid, env)
                need = [(h, it) for h, it in select_items(p["hosts"], {"all": True})]
                if need:
                    outstanding[env] = len(need)
                todo = [(h, it) for h, it in need if not it.get("staged")]
                allowed = w["stage"] == "all" or (w["stage"] == "nonprod" and not is_prd(env_tier(servers)))
                if todo and allowed and not db().execute(
                        "SELECT 1 FROM jobs WHERE client_id=? AND environment=? AND kind='stage' AND status IN "
                        "('queued','signed','running')", (cid, env)).fetchone():
                    try:
                        staged_jobs.append(queue_stage(cid, env, servers, todo, created_by="pegasus (patch watch)")[0])
                    except JobRefused:
                        pass
            put_setting(cid, "patch_watch_state", {"phase": "idle", "last": st.get("started", now),
                                                   "outstanding": outstanding, "staging_jobs": staged_jobs})
            audit("patch_watch_ran", cid, actor="pegasus", outstanding=outstanding, staging_jobs=len(staged_jobs))
        elif now - st.get("last", 0) >= PATCH_WATCH_HOURS * 3600 and connector_online(cid):
            if queue_levels(cid, client_envs(cid), "pegasus (patch watch)"):
                put_setting(cid, "patch_watch_state", dict(st, phase="checking", started=now))


@app.get("/api/clients/<cid>/patch-watch")
@need("viewer")
def get_patch_watch(cid):
    get_client(cid)
    st = get_setting(cid, "patch_watch_state", {}) or {}
    return jsonify(settings=watch_settings(cid), phase=st.get("phase", "idle"), last=iso(st.get("last")),
                   outstanding=st.get("outstanding") or {}, every_hours=PATCH_WATCH_HOURS)


@app.put("/api/clients/<cid>/patch-watch")
@need("admin")
def put_patch_watch(cid):
    get_client(cid)
    body = request.get_json(silent=True) or {}
    w = watch_settings(cid)
    if "check" in body:
        w["check"] = bool(body["check"])
    if "stage" in body:
        if body["stage"] not in ("off", "nonprod", "all"):
            return jsonify(error="Choose off, nonprod or all."), 400
        w["stage"] = body["stage"]
    put_setting(cid, "patch_watch", w)
    audit("patch_watch_changed", cid, **w)
    return jsonify(settings=w)


# ---------------------------------------------------------------- OCI Console link
# Console AI lives only inside the OCI Console (no API), so Pegasus links people straight to each client's console,
# where they sign in with their own OCI account.
OCI_TENANCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$")
OCI_REGION = re.compile(r"^[a-z]{2,3}-[a-z]+-\d{1,2}$")


def oci_console(cid):
    c = get_setting(cid, "oci_console", {}) or {}
    if not c.get("tenancy"):
        return None
    url = f"https://cloud.oracle.com/?tenant={c['tenancy']}" + (f"&region={c['region']}" if c.get("region") else "")
    return {"tenancy": c["tenancy"], "region": c.get("region") or "", "url": url}


@app.put("/api/clients/<cid>/oci-console")
@need("admin")
def put_oci_console(cid):
    get_client(cid)
    b = request.get_json(silent=True) or {}
    tenancy, region = str(b.get("tenancy") or "").strip(), str(b.get("region") or "").strip().lower()
    if tenancy and not OCI_TENANCY.match(tenancy):
        return jsonify(error="Enter the tenancy name as it appears in the OCI Console (letters, numbers, - and _)."), 400
    if region and not OCI_REGION.match(region):
        return jsonify(error="Enter the region identifier, e.g. us-phoenix-1."), 400
    put_setting(cid, "oci_console", {"tenancy": tenancy, "region": region} if tenancy else {})
    audit("oci_console_changed", cid, tenancy=tenancy or "removed", region=region)
    return jsonify(oci_console=oci_console(cid))


@app.get("/api/clients/<cid>/patch-settings")
@need("viewer")
def get_patch_settings(cid):
    get_client(cid)
    return jsonify(dict(patch_settings(cid), components=ev.COMPONENTS, default_platform=ev.DEFAULT_PLATFORM))


@app.put("/api/clients/<cid>/patch-settings")
@need("admin")
def put_patch_settings(cid):
    get_client(cid)
    body = request.get_json(silent=True) or {}
    if "staging_root" in body:
        root = str(body.get("staging_root") or "").strip().rstrip("/")
        if not SAFE_ABS_PATH.match(root) or ".." in root or root.count("/") < 3:
            return jsonify(error="The staging folder must be a dedicated absolute path like "
                                 "/u01/app/oracle/staging/cpu."), 400
        put_setting(cid, "staging_root", root)
    if "cadence" in body:
        if body["cadence"] not in ("monthly", "quarterly"):
            return jsonify(error="Choose monthly or quarterly."), 400
        put_setting(cid, "patch_cadence", body["cadence"])
        audit("patch_cadence_changed", cid, cadence=body["cadence"])
    if "targets" in body:
        clean, problems = [], []
        for i, r in enumerate(body.get("targets") or [], start=1):
            r = {c: str(r.get(c) or "").strip() for c in ev.TARGET_COLS}
            if not any(r.values()):
                continue
            if r["component"] not in ev.COMPONENTS:
                problems.append(f"Row {i}: choose jdk, weblogic, dbclient or tuxedo.")
            if not r["target"] or len(r["target"]) > 120:
                problems.append(f"Row {i}: the target is empty.")
            if r["component"] == "jdk" and not r["patch_number"] and not re.fullmatch(r"[0-9][0-9._]{0,30}", r["target"]):
                problems.append(f"Row {i}: a JDK target is a version like 21.0.6.")
            if r["patch_number"] and not re.match(r"^\d{5,12}$", r["patch_number"]):
                problems.append(f"Row {i}: the Oracle Support patch number should be digits only.")
            if r["platform"] and not re.match(r"^\d{1,5}[PL]$", r["platform"]):
                problems.append(f"Row {i}: platform codes look like 226P (Linux x86-64) or 2000P (Generic).")
            if r["label"] and not SAFE_NAME.match(r["label"]):
                problems.append(f"Row {i}: the label can only use letters, digits, . _ and -.")
            if r["file_filter"] and not re.fullmatch(r"[A-Za-z0-9_.\-]{1,40}", r["file_filter"]):
                problems.append(f"Row {i}: the file filter may use letters, digits, . _ and - only.")
            clean.append(r)
        if problems:
            return jsonify(error=" ".join(problems)), 400
        put_setting(cid, "cpu_targets", clean)
    audit("patch_settings_updated", cid)
    return jsonify(patch_settings(cid))


# ---------------------------------------------------------------- patching: change approval and apply
def build_apply_plan(cid, env, groups):
    """(plan, missing, error). One entry per component and server, in the safe order."""
    servers = env_servers(cid, env)
    p = posture(cid, env)
    if not any(h["checked"] for h in p["hosts"]):
        return None, [], "Check patch levels first."
    staged = env_staged(cid, env)
    levels = env_levels(cid, env)
    by_key = {host_key(s): s for s in unique_hosts(servers)}
    plan, missing = [], []
    for component, key in sorted(groups, key=lambda x: ev.APPLY_ORDER.index(x[0])):
        for h in p["hosts"]:
            item = next((it for it in h["items"] if it["component"] == component and it.get("key") == key
                         and it["status"] == "needed"), None)
            if not item:
                continue
            if component == "os":           # installed straight from the Linux repositories; downloading first is optional
                plan.append({"component": "os", "key": key, "label": item.get("latest_label") or item["target"],
                             "host": h["host"], "host_key": h["host_key"], "owner": "", "home": "",
                             "kernel_update": bool(item.get("kernel_update"))})
                continue
            st = staged.get(h["host_key"], {}).get(key)
            if not st or not st["files"]:
                missing.append(f"{ev.COMP_TITLE[component]} on {h['host']}")
                continue
            lv = levels[h["host_key"]]
            home = (lv.get(component) or {}).get("home", "")
            server = by_key[h["host_key"]]
            owner = (lv.get("owners") or {}).get(home) or server["os_user"] or "psadm1"
            if not SAFE_NAME.match(owner) or not SAFE_ABS_PATH.match(home or "-"):
                return None, [], f"{h['host']}: unexpected owner or home for {ev.COMP_TITLE[component]}."
            opz = ""
            if item.get("needs_opatch"):
                sto = staged.get(h["host_key"], {}).get(ev.OPATCH_19_KEY)
                if not sto or not sto["files"]:
                    missing.append(f"OPatch on {h['host']}")
                    continue
                opz = f"{sto['dir']}/{sto['files'][0]}"
            plan.append({"component": component, "key": key, "label": item.get("latest_label") or item["target"],
                         "host": h["host"], "host_key": h["host_key"], "owner": owner, "home": home,
                         "jdk_home": (lv.get("jdk") or {}).get("home", ""),
                         "wl_home": (lv.get("weblogic") or {}).get("home", ""), "staged": st,
                         "version": item["target"] if component == "jdk" else "",
                         "ids": item.get("verify_ids") or [x for x in re.split(r"[\s,;]+", item["target"]) if x.isdigit()],
                         "level": item.get("level") or item["target"], "opatch_zip": opz})
    return plan, missing, None


def apply_steps(cid, servers, plan, reboot=True):
    """One maintenance window: stop every domain once, check nothing is left running, install the OS updates, apply
    each middleware update, reboot the servers where Linux says it's needed, then start everything once (even after
    a failure), check status and read the levels again."""
    by_key = {host_key(s): s for s in unique_hosts(servers)}
    steps = space_steps(cid, by_key, plan)
    steps += domain_steps(servers, "stop", ignore_failure=True)
    for hk in dict.fromkeys(p["host_key"] for p in plan):
        steps.append({"op": "host.idle", "target": target_of(by_key[hk]), "label": "Check nothing is still running"})
    for p in plan:
        if p["component"] == "os":
            steps.append({"op": "os.update", "target": target_of(by_key[p["host_key"]]),
                          "label": f"Install OS updates ({p['label']})"})
            continue
        steps.append({"op": "patch.apply", "target": target_of(by_key[p["host_key"]]),
                      "label": f"Apply {ev.COMP_TITLE[p['component']]} {p['label']} as {p['owner']}",
                      "component": p["component"], "owner": p["owner"], "home": p["home"],
                      "jdk_home": p["jdk_home"], "wl_home": p["wl_home"],
                      "staged": {"dir": p["staged"]["dir"], "files": p["staged"]["files"]},
                      "version": p["version"], "ids": p["ids"], "level": p["level"], "opatch_zip": p["opatch_zip"]})
    if reboot:
        for hk in dict.fromkeys(p["host_key"] for p in plan if p["component"] == "os"):
            steps.append({"op": "host.reboot", "target": target_of(by_key[hk]), "if_needed": True,
                          "label": "Reboot if Linux says it's needed, and wait for the server"})
    steps += domain_steps(servers, "start", always=True)
    steps += domain_steps(servers, "status", always=True, ignore_failure=True)
    steps += [dict(s, always=True, ignore_failure=True) for s in levels_steps(cid, servers)]
    return steps


def space_steps(cid, by_key, plan):
    """Before anything is stopped: one disk-space check per server for everything the window will write there. A
    'gate' step: if it fails, the connector skips the rest of the job, including the domain starts, since nothing was
    stopped. Left out for connectors older than 0.6.0, which don't know the check."""
    if not can_all(cid, "space"):
        return []
    per_host = {}
    for p in plan:
        if p["component"] == "os":
            item = {"component": "os", "kernel": bool(p.get("kernel_update"))}
        else:
            item = {"component": p["component"], "owner": p["owner"], "home": p["home"],
                    "staged": {"dir": p["staged"]["dir"], "files": p["staged"]["files"]}}
        per_host.setdefault(p["host_key"], []).append(item)
    return [{"op": "space.check", "target": target_of(by_key[hk]), "items": items, "gate": True,
             "label": "Check there's enough free disk space"} for hk, items in per_host.items()]


def space_refused(pairs):
    """The space check output of a job that stopped at it (nothing was changed), or None."""
    for st, r in pairs:
        if st["op"] == "space.check" and r and r.get("exit_code") != 0:
            return str(r.get("output") or "")
    return None


def groups_for_scope(hosts, scope):
    if scope == "all":
        groups = outstanding_groups(hosts)
        return (groups, None) if groups else (None, "Nothing outstanding. Check patch levels again.")
    comp, _, key = str(scope or "").partition("~")
    if comp not in ev.ALL_COMPONENTS or not key:
        return None, "Choose an update."
    return [(comp, key)], None


def scope_of(groups, all_mode):
    return "all" if all_mode else f"{groups[0][0]}~{groups[0][1]}"


@app.post("/api/clients/<cid>/change-requests")
@need("operator")
def create_change_request(cid):
    client = get_client(cid)
    body = request.get_json(silent=True) or {}
    env = str(body.get("environment") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    jcfg = jiramod.config(get_setting(cid, "jira", {}))
    if not jcfg["enabled"]:
        return jsonify(error="Change approval isn't switched on for this client."), 400
    groups, err = groups_for_scope(posture(cid, env)["hosts"], body.get("scope"))
    if err:
        return jsonify(error=err), 400
    plan, missing, err = build_apply_plan(cid, env, groups)
    if err:
        return jsonify(error=err), 400
    if missing:
        return jsonify(error="Download these first, so the ticket shows exactly what will be applied: "
                             + ", ".join(missing)), 409
    if not plan:
        return jsonify(error="Nothing needs applying. Check patch levels again."), 400
    sig = ev.plan_signature(plan)
    scope = scope_of(groups, body.get("scope") == "all")
    for c in db().execute("SELECT * FROM change_requests WHERE client_id=? AND environment=? AND scope=? AND "
                          "status IN ('pending','approved','applying')", (cid, env, scope)):
        if jload(c["signature"], []) == sig:
            return jsonify(error=f"{c['jira_key']} already covers this update.", request=change_request_view(c)), 409
    notes = str(body.get("notes") or "").strip()[:2000]
    window = {}
    for k in ("start", "end"):
        v = str((body.get("window") or {}).get(k) or "").strip()
        if v and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{3})?)?[+-]\d{4}$", v):
            return jsonify(error="The planned window dates aren't in a format Jira accepts."), 400
        window[k] = v
    if window.get("start") and window.get("end") and window["end"] <= window["start"]:
        return jsonify(error="The planned end must be after the planned start."), 400
    comps = [f"{ev.COMP_TITLE[comp]} {next(p['label'] for p in plan if p['component'] == comp)}"
             for comp in dict.fromkeys(p["component"] for p in plan)]
    summary = f"[Pegasus] {env}: apply {', '.join(comps)}"
    change_type = str(body.get("change_type") or "").strip()[:40]
    if change_type:
        jcfg["change_type"] = change_type
    try:
        jc = jiramod.Jira(jcfg, box().open(get_setting(cid, "jira_token", "")))
        key = jc.create(summary, ev.describe_plan(env, client["name"], env_tier(servers), plan, notes, who(),
                                                 now_text(), window), window)
    except jiramod.JiraError as e:
        return jsonify(error=str(e)), 502
    note = None
    try:
        jc.transition(key, jcfg["submit_transition"])
    except jiramod.JiraError as e:
        note = f"{key} was created, but Pegasus couldn't send it for approval: {e}"
    cr_id = "cr_" + uuid.uuid4().hex[:12]
    db().execute("UPDATE change_requests SET status='superseded' WHERE client_id=? AND environment=? AND scope=? AND "
                 "status IN ('pending','approved')", (cid, env, scope))
    db().execute("INSERT INTO change_requests (id, client_id, environment, scope, groups, signature, jira_key, url, "
                 "summary, hosts, notes, requested_by, window, change_type, requested_at, status, approval) "
                 "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                 (cr_id, cid, env, scope, json.dumps(groups), json.dumps(sig), key, jc.browse(key), summary,
                  json.dumps(list(dict.fromkeys(p["host"] for p in plan))), notes, who(), json.dumps(window),
                  jcfg.get("change_type") or "", time.time(), "pending", "pending"))
    cr = db().execute("SELECT * FROM change_requests WHERE id=?", (cr_id,)).fetchone()
    try:
        cr = refresh_cr(cr, jc)
    except jiramod.JiraError:
        pass
    audit("change_request_raised", cid, environment=env, ticket=key, summary=summary)
    return jsonify(request=change_request_view(cr), note=note)


@app.post("/api/change-requests/<cr_id>/withdraw")
@need("operator")
def withdraw_change_request(cr_id):
    c = db().execute("SELECT * FROM change_requests WHERE id=?", (cr_id,)).fetchone()
    if not c:
        return jsonify(error="That change request doesn't exist."), 404
    get_client(c["client_id"])
    if c["status"] not in ("pending", "approved"):
        return jsonify(error=f"{c['jira_key']} can't be withdrawn now ({c['status']})."), 409
    db().execute("UPDATE change_requests SET status='withdrawn', finished_at=? WHERE id=?", (time.time(), cr_id))
    jira_later(c["client_id"], c["jira_key"], f"Withdrawn in Pegasus by {who()} on {now_text()}. Pegasus won't apply "
                                              "this plan under this ticket.")
    audit("change_request_withdrawn", c["client_id"], ticket=c["jira_key"])
    return jsonify(ok=True)


def claim_approval(cid, env, cr_id, plan):
    """At the moment of applying: an approved ticket must cover exactly this plan. Marks it used. (cr, error)."""
    if not cr_id:
        return None, f"{env} needs an approved Jira ticket before it can be patched. Use Request approval first."
    c = db().execute("SELECT * FROM change_requests WHERE id=? AND client_id=?", (str(cr_id), cid)).fetchone()
    if not c or c["environment"] != env:
        return None, "That change request isn't for this environment."
    if c["status"] in ("applying", "applied", "failed"):
        return None, f"{c['jira_key']} has already been used for an apply. Request approval again."
    if c["status"] not in ("pending", "approved"):
        return None, f"{c['jira_key']} is {c['status'].replace('_', ' ')}. Request approval again."
    if jload(c["signature"], []) != ev.plan_signature(plan):
        db().execute("UPDATE change_requests SET status='stale' WHERE id=?", (c["id"],))
        return None, (f"The patch plan has changed since {c['jira_key']} was raised (different updates or servers), so "
                      "that approval doesn't cover it. Request approval again.")
    try:
        state, name, approver = jira_for(cid).approval_state(c["jira_key"])
    except jiramod.JiraError as e:
        return None, f"Couldn't confirm the approval of {c['jira_key']} with Jira: {e}"
    new_status = {"approved": "applying", "rejected": "rejected"}.get(state, c["status"])
    r = db().execute("UPDATE change_requests SET status=?, approval=?, jira_status=?, approver=?, checked_at=? "
                     "WHERE id=? AND status IN ('pending','approved')",
                     (new_status, state, name, approver, time.time(), c["id"]))
    if state == "approved":
        if not r.rowcount:
            return None, f"{c['jira_key']} was just used by someone else."
        return db().execute("SELECT * FROM change_requests WHERE id=?", (c["id"],)).fetchone(), None
    if state == "self_approved":
        return None, (f"{c['jira_key']} was approved by the account Pegasus uses to raise tickets, or Pegasus can't tell "
                      "who approved it. It needs approval from someone else.")
    if state == "rejected":
        return None, f"{c['jira_key']} was declined in Jira (status: {name or 'unknown'}). Nothing was applied."
    return None, f"{c['jira_key']} isn't approved yet (status: {name or 'unknown'})."


@app.post("/api/clients/<cid>/patching/apply")
@need("operator")
def patching_apply(cid):
    get_client(cid)
    body = request.get_json(silent=True) or {}
    env = str(body.get("environment") or "")
    servers = env_servers(cid, env)
    if not servers:
        return jsonify(error="That environment has no servers."), 404
    tier = env_tier(servers)
    if is_prd(tier) and str(body.get("confirm") or "").upper() != env.upper():
        return jsonify(error=f"Type {env} to confirm.", need_confirm=True), 409
    groups, err = groups_for_scope(posture(cid, env)["hosts"], body.get("scope"))
    if err:
        return jsonify(error=err), 400
    plan, missing, err = build_apply_plan(cid, env, groups)
    if err:
        return jsonify(error=err), 400
    if missing:
        return jsonify(error="Download these first: " + ", ".join(missing)), 409
    if not plan:
        return jsonify(error="Nothing needs applying. Check patch levels again."), 400
    if any(p["component"] == "os" for p in plan):
        try:
            check_connectors_can(cid, "os")
        except JobRefused as e:
            return jsonify(error=str(e)), e.status
    if db().execute("SELECT 1 FROM jobs WHERE client_id=? AND environment=? AND status IN ('queued','running')",
                    (cid, env)).fetchone():
        return jsonify(error=f"Something is already running or queued for {env}."), 409
    cr = None
    if approval_required(cid, tier):
        cr, err = claim_approval(cid, env, body.get("change_request"), plan)
        if err:
            return jsonify(error=err, need_approval=True), 409
    title = ("apply all outstanding updates " if body.get("scope") == "all" else "apply ") + env
    if body.get("scope") != "all":
        title = f"apply {ev.COMP_TITLE[plan[0]['component']]} {plan[0]['label']} to {env}"
    try:
        jid = queue_job(cid, env, "apply", title, apply_steps(cid, servers, plan, reboot=body.get("reboot", True)
                                                              is not False), stop_on_failure=True,
                        meta={"cr": cr["id"] if cr else None, "signature": ev.plan_signature(plan),
                              "reboot": body.get("reboot", True) is not False})
    except JobRefused as e:
        if cr:
            db().execute("UPDATE change_requests SET status='approved' WHERE id=?", (cr["id"],))
        return jsonify(error=str(e)), e.status
    if cr:
        db().execute("UPDATE change_requests SET job_id=? WHERE id=?", (jid, cr["id"]))
        jira_later(cid, cr["jira_key"], f"Pegasus queued this change on {now_text()} (job {jid}, by {who()}). "
                                        f"Approved by {cr['approver'] or 'unknown'}.", "start_transition")
    audit("apply_queued", cid, job=jid, environment=env, ticket=cr["jira_key"] if cr else None,
          plan=ev.plan_signature(plan))
    return jsonify(job=jid, steps=len(plan), change_request=cr["jira_key"] if cr else None)


# ---------------------------------------------------------------- Jira settings (per client)
@app.get("/api/clients/<cid>/jira")
@need("viewer")
def get_jira(cid):
    get_client(cid)
    return jsonify(config=jiramod.config(get_setting(cid, "jira", {})),
                   has_token=bool(get_setting(cid, "jira_token", "")))


@app.put("/api/clients/<cid>/jira")
@need("admin")
def put_jira(cid):
    get_client(cid)
    body = request.get_json(silent=True) or {}
    token = str(body.get("token") or "").strip()
    has = bool(token or get_setting(cid, "jira_token", ""))
    new, problems = jiramod.validate(body, jiramod.config(get_setting(cid, "jira", {})), has)
    if problems:
        return jsonify(error=" ".join(problems)), 400
    if token:
        put_setting(cid, "jira_token", box().seal(token))
    put_setting(cid, "jira", new)
    audit("jira_settings_updated", cid, enabled=new["enabled"], project=new["project"], token_changed=bool(token))
    return jsonify(config=new, has_token=has)


@app.delete("/api/clients/<cid>/jira/token")
@need("admin")
def forget_jira_token(cid):
    get_client(cid)
    put_setting(cid, "jira_token", "")
    cfg = jiramod.config(get_setting(cid, "jira", {}))
    if cfg["enabled"]:
        cfg["enabled"] = False
        put_setting(cid, "jira", cfg)
    audit("jira_token_removed", cid)
    return jsonify(ok=True, has_token=False)


@app.post("/api/clients/<cid>/jira/test")
@need("admin")
def test_jira(cid):
    get_client(cid)
    try:
        j = jira_for(cid)
        me = j.myself()
        proj = j.project()
    except jiramod.JiraError as e:
        return jsonify(error=str(e)), 400
    warn, filled = None, []
    try:
        meta = j.create_meta()
        fields = j.change_fields(meta, {"start": "2030-01-01T20:00:00.000+0000", "end": "2030-01-01T23:00:00.000+0000"})
        filled = [f["name"] for f in meta.values() if f.get("fieldId") in fields]
        fields.update(j.cfg.get("extra_fields") or {})
        fields.update({"project": 1, "summary": 1, "description": 1, "issuetype": 1})
        missing = jiramod.missing_required(meta, fields)
        if missing:
            warn = (f"A {j.cfg['issue_type']} in this project also needs: {'; '.join(missing)}. Add them under "
                    "Additional fields, or Request approval will fail.")
    except jiramod.JiraError as e:
        warn = str(e)
    return jsonify(ok=True, user=me.get("displayName") or me.get("name"), project=proj.get("name"),
                   issue_types=[t["name"] for t in proj.get("issueTypes") or []], filled=filled, warning=warn)


# ---------------------------------------------------------------- SSH access register
def access_rid(fp, account):
    return f"{fp}|{account or ''}"


def cid_of(j):
    return j["client_id"]


def record_access(j, pairs):
    meta = jload(j["meta"], {}) or {}
    key, _ = sshkeys.parse(meta.get("line"))
    if not key:
        return
    mode, account, cid = meta.get("mode"), meta.get("account") or "", j["client_id"]
    if meta.get("request"):
        ok = j["status"] == "succeeded"
        db().execute("UPDATE access_requests SET status=? WHERE id=?", ("done" if ok else "failed", meta["request"]))
        ar = db().execute("SELECT jira_key FROM access_requests WHERE id=?", (meta["request"],)).fetchone()
        if ar and ar["jira_key"]:
            jira_later(cid_of(j), ar["jira_key"],
                       f"Pegasus finished this SSH access change on {now_text()}: *{'SUCCEEDED' if ok else 'FAILED'}*"
                       + (f" ({j['note']})" if j["note"] else "") + f". Job {j['id']}; the details are in Pegasus.",
                       "done_transition" if ok else None)
    rid = access_rid(key["fingerprint"], account)
    rec = db().execute("SELECT * FROM access_keys WHERE client_id=? AND rid=?", (cid, rid)).fetchone()
    if mode == "check" and not rec:
        return
    servers = jload(rec["servers"], {}) if rec else {}
    for st, r in pairs:
        if not r or not isinstance(r.get("data"), dict):
            continue
        res, t = r["data"].get("result"), st.get("target") or {}
        hk = t.get("ip") or t.get("host")
        if res in ("ADDED", "EXISTS", "PRESENT"):
            prev = servers.get(hk, {})
            servers[hk] = {"host": t.get("host"), "environment": st.get("environment"), "account": r["data"].get("account"),
                           "since": prev.get("since") or iso(time.time())}
        elif res in ("REMOVED", "NOT_PRESENT", "ABSENT"):
            servers.pop(hk, None)
    if not servers:
        db().execute("DELETE FROM access_keys WHERE client_id=? AND rid=?", (cid, rid))
        return
    expires = meta.get("expires_on") if mode == "add" else None
    if rec:
        db().execute("UPDATE access_keys SET servers=?, updated_at=?, note=COALESCE(NULLIF(?, ''), note), "
                     "expires_on=CASE WHEN ? THEN ? ELSE expires_on END WHERE client_id=? AND rid=?",
                     (json.dumps(servers), time.time(), meta.get("note") if mode == "add" else "", mode == "add",
                      expires, cid, rid))
    else:
        db().execute("INSERT INTO access_keys (client_id, rid, fingerprint, type, comment, line, account, added_by, "
                     "added_at, note, servers, updated_at, expires_on) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (cid, rid, key["fingerprint"], key["type"], key["comment"], key["line"], account,
                      j["created_by"], time.time(), meta.get("note") or "", json.dumps(servers), time.time(), expires))
    audit(f"ssh_key_{mode}", cid, actor=j["created_by"], fingerprint=key["fingerprint"], account=account,
          servers=len(servers), result=j["status"])


@app.post("/api/access/parse")
@need("viewer")
def access_parse():
    key, err = sshkeys.parse((request.get_json(silent=True) or {}).get("key"))
    if err:
        return jsonify(error=err), 400
    return jsonify(type=key["type"], bits=key["bits"], comment=key["comment"], fingerprint=key["fingerprint"])


@app.get("/api/clients/<cid>/access")
@need("viewer")
def access_list(cid):
    get_client(cid)
    out = []
    for r in db().execute("SELECT * FROM access_keys WHERE client_id=? ORDER BY COALESCE(updated_at, added_at) DESC",
                          (cid,)):
        servers = jload(r["servers"], {})
        out.append({"id": r["rid"], "fingerprint": r["fingerprint"], "type": r["type"], "comment": r["comment"],
                    "account": r["account"], "added_by": r["added_by"], "added_at": iso(r["added_at"]),
                    "note": r["note"], "updated_at": iso(r["updated_at"]), "expires_on": r["expires_on"],
                    "environments": sorted({s.get("environment") or "" for s in servers.values()} - {""}),
                    "servers": sorted(s.get("host") or hk for hk, s in servers.items())})
    return jsonify(keys=out)


class AccessProblem(Exception):
    def __init__(self, msg, status=400, **extra):
        super().__init__(msg)
        self.status, self.extra = status, extra


def access_plan(cid, body):
    """Validate an SSH access change and work out its steps. Raises AccessProblem."""
    mode = body.get("action")
    if mode not in ("add", "remove", "check"):
        raise AccessProblem("Choose add, remove or check.")
    account = str(body.get("account") or "").strip()
    if account and not SAFE_NAME.match(account):
        raise AccessProblem("The account name can only use letters, digits, . _ and -.")
    if account == "root":
        raise AccessProblem("Pegasus doesn't add keys for root. Use opc (or another sudo user) instead.")
    note = str(body.get("note") or "").strip()[:300]
    expires = str(body.get("expires_on") or "").strip()
    if expires:
        try:
            if dt.date.fromisoformat(expires) < dt.date.today():
                raise AccessProblem("The end date has already passed.")
        except ValueError:
            raise AccessProblem("Give the end date as YYYY-MM-DD.")
    only = None
    if body.get("record"):
        rec = db().execute("SELECT * FROM access_keys WHERE client_id=? AND rid=?", (cid, str(body["record"]))).fetchone()
        if not rec:
            raise AccessProblem("That key isn't in the register any more.", 404)
        key, _ = sshkeys.parse(rec["line"])
        account = rec["account"] or ""
        servers_rec = jload(rec["servers"], {})
        env_names = sorted({s.get("environment") for s in servers_rec.values() if s.get("environment")})
        only = set(servers_rec)
    else:
        key, err = sshkeys.parse(body.get("key"))
        if err:
            raise AccessProblem(err)
        env_names = [str(n) for n in body.get("environments") or []]
    if not env_names:
        raise AccessProblem("Choose at least one environment.")
    steps, seen, prd = [], set(), set()
    for env in env_names:
        servers = env_servers(cid, env)
        if not servers:
            raise AccessProblem(f"{env} isn't in the inventory.", 404)
        if is_prd(env_tier(servers)):
            prd.add(env)
        for s in unique_hosts(servers):
            hk = host_key(s)
            if hk in seen or (only is not None and hk not in only):
                continue
            seen.add(hk)
            steps.append({"op": f"access.{mode}", "target": target_of(s), "environment": env, "key": key["line"],
                          "account": account, "independent": True,
                          "label": f"{mode.capitalize()} key {key['comment'] or key['fingerprint'][:20]}"
                                   + (f" for {account}" if account else "")})
    if not steps:
        raise AccessProblem("None of those servers are in the inventory any more.")
    title = f"{mode} SSH key {key['comment'] or key['fingerprint'][:20]}" + (f" for {account}" if account else "")
    return {"mode": mode, "key": key, "account": account, "note": note, "expires_on": expires or None,
            "envs": env_names, "prd": sorted(prd), "steps": steps, "title": title}


def check_prd_confirm(plan, body):
    if plan["mode"] != "check" and plan["prd"]:
        expected = plan["prd"][0] if len(plan["prd"]) == 1 else "PRODUCTION"
        if str(body.get("confirm") or "").upper() != expected.upper():
            raise AccessProblem(f"Type {expected} to confirm.", 409, need_confirm=True, expected=expected,
                                prd=plan["prd"])


def queue_access(cid, plan, created_by=None, request_id=None):
    meta = {"mode": plan["mode"], "line": plan["key"]["line"], "account": plan["account"], "note": plan["note"],
            "expires_on": plan["expires_on"], "request": request_id}
    return queue_job(cid, None, f"access.{plan['mode']}", plan["title"], plan["steps"], stop_on_failure=True,
                     meta=meta, created_by=created_by)


def access_approval_required(cid):
    return bool(get_setting(cid, "access_approval", True))


@app.post("/api/clients/<cid>/access")
@need("operator")
def access_run(cid):
    """Check runs straight away. Adding or removing a key needs a second person's approval (unless the client's admins
    turned that off): it's saved as a request, and runs when another admin approves it."""
    get_client(cid)
    body = request.get_json(silent=True) or {}
    try:
        plan = access_plan(cid, body)
        if plan["mode"] != "check" and access_approval_required(cid):
            if not plan["note"]:
                raise AccessProblem("Say who this is for and why (the note); the approver needs it.")
            if plan["mode"] == "add" and plan["prd"] and not plan["expires_on"]:
                raise AccessProblem("Access to production needs an end date.")
            rid = "ar_" + uuid.uuid4().hex[:12]
            u = current_user()
            saved = {k: body.get(k) for k in ("action", "key", "account", "note", "environments", "record",
                                              "expires_on")}
            key, url, jstatus = None, None, None
            if access_uses_jira(cid):
                try:
                    key, url = raise_access_ticket(cid, plan)
                except jiramod.JiraError as e:
                    return jsonify(error=f"Couldn't raise the Jira ticket: {e}"), 502
                jstatus = "raised"
            db().execute("INSERT INTO access_requests (id, client_id, mode, body, summary, environments, note, "
                         "expires_on, requested_by, requested_by_id, requested_at, status, jira_key, jira_url, "
                         "jira_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (rid, cid, plan["mode"], json.dumps(saved), plan["title"], json.dumps(plan["envs"]),
                          plan["note"], plan["expires_on"], who(), u["id"], time.time(), "pending", key, url, jstatus))
            audit("ssh_access_requested", cid, request=rid, title=plan["title"], environments=plan["envs"],
                  servers=len(plan["steps"]), note=plan["note"], expires_on=plan["expires_on"], ticket=key or "")
            return jsonify(request=rid, pending=True, servers=len(plan["steps"]), environments=plan["envs"],
                           jira_key=key, jira_url=url)
        check_prd_confirm(plan, body)
        jid = queue_access(cid, plan)
    except AccessProblem as e:
        return jsonify(error=str(e), **e.extra), e.status
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    audit("job_queued", cid, job=jid, title=plan["title"], environments=plan["envs"])
    return jsonify(job=jid, servers=len(plan["steps"]), environments=plan["envs"])


def access_request_view(r):
    u = current_user()
    mine = bool(u and r["requested_by_id"] == u["id"])
    body = jload(r["body"], {}) or {}
    key, _ = sshkeys.parse(body.get("key")) if body.get("key") else (None, None)
    return {"id": r["id"], "mode": r["mode"], "summary": r["summary"], "environments": jload(r["environments"], []),
            "note": r["note"], "expires_on": r["expires_on"], "account": body.get("account") or "",
            "fingerprint": key["fingerprint"] if key else "", "requested_by": r["requested_by"],
            "requested_at": iso(r["requested_at"]), "status": r["status"], "decided_by": r["decided_by"],
            "decided_at": iso(r["decided_at"]), "decision_note": r["decision_note"], "job": r["job_id"],
            "jira_key": r["jira_key"], "jira_url": r["jira_url"], "jira_status": r["jira_status"],
            "checked_at": iso(r["checked_at"]),
            "mine": mine, "can_decide": bool(r["status"] == "pending" and not r["jira_key"] and u
                                             and u["role"] == "admin" and not mine),
            "can_withdraw": bool(r["status"] == "pending" and (mine or (u and u["role"] == "admin")))}


@app.get("/api/clients/<cid>/access-requests")
@need("viewer")
def access_requests(cid):
    get_client(cid)
    rows = db().execute("SELECT * FROM access_requests WHERE client_id=? ORDER BY status='pending' DESC, "
                        "requested_at DESC LIMIT 60", (cid,)).fetchall()
    return jsonify(requests=[access_request_view(r) for r in rows], approval=access_approval_required(cid),
                   jira=access_uses_jira(cid))


def pending_access_request(rid):
    r = db().execute("SELECT * FROM access_requests WHERE id=?", (rid,)).fetchone()
    if not r:
        abort(404)
    get_client(r["client_id"])
    if r["status"] != "pending":
        abort(409, description=f"This request is already {r['status']}.")
    return r


@app.post("/api/access-requests/<rid>/approve")
@need("admin")
def approve_access_request(rid):
    r = pending_access_request(rid)
    u = current_user()
    if r["jira_key"]:
        return jsonify(error=f"This request is approved in Jira ({r['jira_key']}). Pegasus makes the change as soon "
                             "as it sees the approval."), 409
    if r["requested_by_id"] == u["id"]:
        return jsonify(error="Someone other than the requester has to approve it."), 403
    body = request.get_json(silent=True) or {}
    saved = jload(r["body"], {}) or {}
    try:
        plan = access_plan(r["client_id"], saved)          # worked out again: the inventory may have changed
        check_prd_confirm(plan, body)
        jid = queue_access(r["client_id"], plan, created_by=f"{r['requested_by']} (approved by {who()})",
                           request_id=rid)
    except AccessProblem as e:
        return jsonify(error=str(e), **e.extra), e.status
    except JobRefused as e:
        return jsonify(error=str(e)), e.status
    db().execute("UPDATE access_requests SET status='approved', decided_by=?, decided_by_id=?, decided_at=?, "
                 "decision_note=?, job_id=? WHERE id=?",
                 (who(), u["id"], time.time(), str(body.get("note") or "").strip()[:300], jid, rid))
    audit("ssh_access_approved", r["client_id"], request=rid, title=plan["title"], requested_by=r["requested_by"],
          job=jid)
    return jsonify(job=jid, servers=len(plan["steps"]))


@app.post("/api/access-requests/<rid>/reject")
@need("admin")
def reject_access_request(rid):
    r = pending_access_request(rid)
    if r["jira_key"]:
        return jsonify(error=f"Reject it in Jira ({r['jira_key']}), or withdraw it here."), 409
    note = str((request.get_json(silent=True) or {}).get("note") or "").strip()[:300]
    db().execute("UPDATE access_requests SET status='rejected', decided_by=?, decided_by_id=?, decided_at=?, "
                 "decision_note=? WHERE id=?", (who(), current_user()["id"], time.time(), note, rid))
    audit("ssh_access_rejected", r["client_id"], request=rid, title=r["summary"], requested_by=r["requested_by"],
          note=note)
    return jsonify(ok=True)


@app.post("/api/access-requests/<rid>/withdraw")
@need("operator")
def withdraw_access_request(rid):
    r = pending_access_request(rid)
    u = current_user()
    if r["requested_by_id"] != u["id"] and u["role"] != "admin":
        return jsonify(error="Only the requester or an admin can withdraw it."), 403
    db().execute("UPDATE access_requests SET status='withdrawn', decided_by=?, decided_by_id=?, decided_at=? "
                 "WHERE id=?", (who(), u["id"], time.time(), rid))
    if r["jira_key"]:
        jira_later(r["client_id"], r["jira_key"], f"Withdrawn in Pegasus by {who()} on {now_text()}. Nothing was "
                                                  "changed on the servers.")
    audit("ssh_access_withdrawn", r["client_id"], request=rid, title=r["summary"])
    return jsonify(ok=True)


def access_uses_jira(cid):
    """SSH access changes are approved in Jira when the client has Jira change approval switched on."""
    return bool(access_approval_required(cid) and jiramod.config(get_setting(cid, "jira", {}))["enabled"])


def raise_access_ticket(cid, plan):
    """Raise a Jira ticket describing the SSH access change exactly. Returns (key, url). Raises JiraError."""
    jcfg = jiramod.config(get_setting(cid, "jira", {}))
    extra = dict(jcfg.get("extra_fields") or {})
    if isinstance(extra.get("labels"), list):
        extra["labels"] = [x for x in extra["labels"] if x != "cpu-patching"] + ["ssh-access"]
    jcfg["extra_fields"] = extra
    client = db().execute("SELECT name FROM clients WHERE id=?", (cid,)).fetchone()
    key_ = plan["key"]
    servers = sorted({(st.get("environment"), st["target"].get("host") or st["target"].get("ip")) for st in plan["steps"]})
    verb = {"add": "Give SSH access", "remove": "Remove SSH access"}[plan["mode"]]
    summary = (f"[Pegasus] {verb}: {key_['comment'] or key_['fingerprint'][:24]}"
               + (f" ({plan['account']})" if plan["account"] else "") + f" on {', '.join(plan['envs'])}")
    lines = [f"Requested in Pegasus by {who()} on {now_text()} for {client['name'] if client else cid}.", "",
             f"*Change:* {verb.lower()} for the key below"
             + (f" on account {plan['account']}" if plan["account"] else " on the connector's SSH account") + ".",
             f"*Who and why:* {plan['note']}",
             f"*Key:* {key_['type']} {key_['comment'] or ''} (fingerprint {key_['fingerprint']})"]
    if plan["mode"] == "add":
        lines.append(f"*Access ends:* {plan['expires_on']} (Pegasus removes the key automatically after this date)"
                     if plan["expires_on"] else "*Access ends:* not set (until removed)")
    lines += ["", f"*Servers ({len(servers)}):*"] + [f"* {env}: {host}" for env, host in servers]
    lines += ["", "When this ticket is approved by someone other than the account that raised it, Pegasus makes "
                  "the change on these servers by itself and comments here with the result."]
    jc = jiramod.Jira(jcfg, box().open(get_setting(cid, "jira_token", "")))
    key = jc.create(summary, "\n".join(lines))
    try:
        jc.transition(key, jcfg["submit_transition"])
    except jiramod.JiraError:
        pass
    return key, jc.browse(key)


_access_jira_checked = {"at": 0.0}


def check_access_jira(cid=None, now=None, force=False):
    """Ask Jira about pending SSH access tickets. Approved: make the change. Rejected: close the request."""
    now = now or time.time()
    if not force and now - _access_jira_checked["at"] < 120:
        return
    _access_jira_checked["at"] = now
    q = "SELECT * FROM access_requests WHERE status='pending' AND jira_key IS NOT NULL"
    rows = db().execute(q + (" AND client_id=?" if cid else ""), (cid,) if cid else ()).fetchall()
    clients = {}
    for r in rows:
        c = r["client_id"]
        try:
            if c not in clients:
                clients[c] = jiramod.Jira(jiramod.config(get_setting(c, "jira", {})),
                                          box().open(get_setting(c, "jira_token", "")))
            state, jstatus, approver = clients[c].approval_state(r["jira_key"])
        except jiramod.JiraError as e:
            db().execute("UPDATE access_requests SET jira_status=?, checked_at=? WHERE id=?",
                         (f"couldn't check: {e}"[:200], now, r["id"]))
            continue
        db().execute("UPDATE access_requests SET jira_status=?, checked_at=? WHERE id=?",
                     (jstatus + (" (approved by the account Pegasus uses; someone else has to approve it)"
                                 if state == "self_approved" else ""), now, r["id"]))
        if state == "rejected":
            db().execute("UPDATE access_requests SET status='rejected', decided_by=?, decided_at=?, decision_note=? "
                         "WHERE id=?", (f"Jira ({r['jira_key']})", now, f"Jira status: {jstatus}", r["id"]))
            audit("ssh_access_rejected", c, actor="jira", request=r["id"], ticket=r["jira_key"], status=jstatus)
        elif state == "approved":
            try:
                plan = access_plan(c, jload(r["body"], {}) or {})
                jid = queue_access(c, plan, created_by=f"{r['requested_by']} (approved in Jira by "
                                                       f"{approver or 'Jira'})", request_id=r["id"])
            except (AccessProblem, JobRefused) as e:
                db().execute("UPDATE access_requests SET jira_status=? WHERE id=?",
                             (f"{jstatus}; waiting to run: {e}"[:200], r["id"]))
                continue
            db().execute("UPDATE access_requests SET status='approved', decided_by=?, decided_at=?, job_id=? "
                         "WHERE id=?", (f"{approver or 'Jira'} (in Jira)", now, jid, r["id"]))
            audit("ssh_access_approved", c, actor=approver or "jira", request=r["id"], ticket=r["jira_key"], job=jid)
            jira_later(c, r["jira_key"], f"Approved. Pegasus started the change on {now_text()} (job {jid}).",
                       "start_transition")


@app.post("/api/clients/<cid>/access-requests/check")
@need("viewer")
def check_access_requests_now(cid):
    get_client(cid)
    check_access_jira(cid, force=True)
    return access_requests(cid)


@app.put("/api/clients/<cid>/access-settings")
@need("admin")
def put_access_settings(cid):
    get_client(cid)
    on = bool((request.get_json(silent=True) or {}).get("approval"))
    put_setting(cid, "access_approval", on)
    audit("ssh_approval_changed", cid, approval="required" if on else "not required")
    return jsonify(approval=on)


def expire_access(today=None):
    """Remove keys whose end date has passed (the end date was approved with the access, so this needs no new
    approval). Each removal is an ordinary job, retried on the next round if it can't run yet."""
    today = (today or dt.date.today()).isoformat()
    rows = db().execute("SELECT * FROM access_keys WHERE expires_on IS NOT NULL AND expires_on < ?", (today,)).fetchall()
    for rec in rows:
        busy = db().execute("SELECT 1 FROM jobs WHERE client_id=? AND kind='access.remove' AND status IN "
                            "('queued','signed','running') AND meta LIKE ?",
                            (rec["client_id"], f'%"expired": "{rec["rid"]}"%')).fetchone()
        if busy:
            continue
        try:
            plan = access_plan(rec["client_id"], {"action": "remove", "record": rec["rid"]})
            plan["title"] = f"Remove expired SSH key {rec['comment'] or rec['fingerprint'][:20]}"
            meta = {"mode": "remove", "line": rec["line"], "account": rec["account"] or "", "note": "",
                    "expired": rec["rid"]}
            jid = queue_job(rec["client_id"], None, "access.remove", plan["title"], plan["steps"],
                            stop_on_failure=True, meta=meta, created_by="pegasus (access ended)")
        except (AccessProblem, JobRefused) as e:
            app.logger.info("couldn't remove expired key %s yet: %s", rec["rid"], e)
            continue
        audit("ssh_access_expired", rec["client_id"], actor="pegasus", fingerprint=rec["fingerprint"],
              account=rec["account"] or "", ended=rec["expires_on"], job=jid)


# ---------------------------------------------------------------- connector API (called by connectors only)
def denied(why):
    g.auth_error = why
    return None


def unauthorized():
    return jsonify(error=g.get("auth_error") or "Unknown connector."), 401


def connector_auth():
    """The calling connector, from a signed request (certificate) or, for one registered before certificates, its
    shared secret. Sets g.auth_kind. None (and g.auth_error) if it isn't accepted."""
    now = time.time()
    sig = request.headers.get("X-Pegasus-Signature")
    if sig:
        cid = request.headers.get("X-Pegasus-Connector", "")
        c = db().execute("SELECT * FROM connectors WHERE id=?", (cid,)).fetchone()
        if not c or c["revoked"]:
            return denied("This connector has been removed in Pegasus.")
        if not c["public_key"]:
            return denied("This connector has no certificate yet.")
        if (c["cert_not_after"] or 0) < now:
            return denied("This connector's certificate has expired.")
        path = request.path + ("?" + request.query_string.decode("ascii", "replace") if request.query_string else "")
        body = request.get_data(cache=True)
        ts, nonce = request.headers.get("X-Pegasus-Timestamp"), request.headers.get("X-Pegasus-Nonce", "")
        keys = [c["public_key"]]
        if c["prev_public_key"] and (c["prev_until"] or 0) > now:
            keys.append(c["prev_public_key"])       # requests already on their way when the key was renewed
        problem = None
        for k in keys:
            try:
                protocol.verify_request(k, request.method, path, body, ts, nonce, sig, now)
                problem = None
                break
            except ValueError as e:
                problem = str(e)
        if problem:
            return denied(f"The request didn't check out: {problem}.")
        try:
            db().execute("INSERT INTO nonces (connector_id, nonce, at) VALUES (?,?,?)", (cid, nonce, now))
        except sqlite3.IntegrityError:
            return denied("That request was already received once.")
        if secrets.randbelow(200) == 0:
            db().execute("DELETE FROM nonces WHERE at<?", (now - 2 * protocol.REQUEST_SKEW - 60,))
        g.auth_kind = "certificate"
    else:
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer ") or "." not in h:
            return denied("Unknown connector.")
        cid, _, secret = h[7:].partition(".")
        c = db().execute("SELECT * FROM connectors WHERE id=? AND revoked=0", (cid,)).fetchone()
        if not c or not hmac.compare_digest(c["secret_hash"], sha(secret)):
            return denied("Unknown connector.")
        if c["public_key"]:
            return denied("This connector signs in with its certificate now; its old secret is no longer accepted.")
        g.auth_kind = "secret"
    db().execute("UPDATE connectors SET last_seen=?, version=? WHERE id=?",
                 (now, request.headers.get("X-Connector-Version", c["version"] or "")[:20], c["id"]))
    return db().execute("SELECT * FROM connectors WHERE id=?", (c["id"],)).fetchone()


def issue_certificate(c, con_id, client_id, public_key, previous=None):
    """Issue a certificate for public_key and record it. previous: the key it replaces, accepted 10 more minutes."""
    now = time.time()
    serial = "s_" + uuid.uuid4().hex[:16]
    cert, sig = protocol.issue_cert(signing_key(), con_id, client_id, public_key, serial, now)
    c.execute("UPDATE connectors SET public_key=?, cert_serial=?, cert_not_after=?, cert_issued_at=?, "
              "prev_public_key=?, prev_until=?, secret_hash='!' WHERE id=?",
              (cert["public_key"], serial, cert["not_after"], now, previous, now + 600 if previous else None, con_id))
    return {"certificate": cert, "certificate_signature": sig}


def body_public_key(body):
    try:
        return protocol.check_public_key(body.get("public_key"))
    except ValueError:
        return None


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
    pub = body_public_key(body) if body.get("public_key") else None
    if body.get("public_key") and not pub:
        c.execute("ROLLBACK")
        return jsonify(error="The connector's public key isn't a valid Ed25519 key."), 400
    clean = lambda k, n: re.sub(r"[^\x20-\x7e]", "", str(body.get(k) or ""))[:n]
    c.execute("INSERT INTO connectors (id, client_id, name, hostname, version, platform, secret_hash, created_at, "
              "last_seen) VALUES (?,?,?,?,?,?,?,?,?)",
              (con_id, t["client_id"], clean("name", 80), clean("hostname", 120), clean("version", 20),
               clean("platform", 120), "!" if pub else sha(secret), now, now))
    issued = issue_certificate(c, con_id, t["client_id"], pub) if pub else {}
    c.execute("UPDATE reg_tokens SET used_at=?, connector_id=? WHERE token_hash=?", (now, con_id, t["token_hash"]))
    c.execute("COMMIT")
    client = c.execute("SELECT name FROM clients WHERE id=?", (t["client_id"],)).fetchone()
    audit("connector_registered", t["client_id"], actor="connector", connector=con_id, name=clean("name", 80),
          certificate=issued["certificate"]["serial"] if issued else "none (shared secret)")
    out = dict(connector_id=con_id, tenant=t["client_id"], client_name=client["name"],
               signing_public_key=protocol.public_key_b64(signing_key()), **issued)
    if not pub:
        out["secret"] = secret                  # a connector from before certificates; it enrolls when it starts
    return jsonify(out)


@app.post("/api/connector/v1/certificate/enroll")
def connector_enroll():
    """A connector that registered with a shared secret trades it for a certificate on its own key."""
    con = connector_auth()
    if not con:
        return unauthorized()
    if g.auth_kind != "secret":
        return jsonify(error="This connector already has a certificate; renew it instead."), 409
    pub = body_public_key(request.get_json(silent=True) or {})
    if not pub:
        return jsonify(error="Send the connector's new Ed25519 public key."), 400
    out = issue_certificate(db(), con["id"], con["client_id"], pub)
    audit("connector_certificate_issued", con["client_id"], actor="connector", connector=con["id"], name=con["name"],
          certificate=out["certificate"]["serial"], note="replaced its shared secret")
    return jsonify(out)


@app.post("/api/connector/v1/certificate/renew")
def connector_renew():
    """A new certificate on a new key, asked for with the current key."""
    con = connector_auth()
    if not con:
        return unauthorized()
    if g.auth_kind != "certificate":
        return jsonify(error="Get a certificate first."), 409
    pub = body_public_key(request.get_json(silent=True) or {})
    if not pub or pub == con["public_key"]:
        return jsonify(error="Send a new Ed25519 public key."), 400
    if time.time() - (con["cert_issued_at"] or 0) < 60:
        return jsonify(error="This connector's certificate was renewed less than a minute ago."), 429
    out = issue_certificate(db(), con["id"], con["client_id"], pub, previous=con["public_key"])
    audit("connector_certificate_renewed", con["client_id"], actor="connector", connector=con["id"],
          name=con["name"], certificate=out["certificate"]["serial"], replaces=con["cert_serial"])
    return jsonify(out)


UPDATE_STATES = ("installing", "restarting", "failed", "refused")


@app.post("/api/connector/v1/heartbeat")
def connector_heartbeat():
    con = connector_auth()
    if not con:
        return unauthorized()
    body = request.get_json(silent=True) or {}
    now = time.time()
    up = body.get("update") if isinstance(body.get("update"), dict) else None
    can = 1 if body.get("can_update") else 0 if "can_update" in body else None
    db().execute("UPDATE connectors SET can_update=COALESCE(?, can_update) WHERE id=?", (can, con["id"]))
    if up and up.get("state") in UPDATE_STATES:
        state, version = up["state"], str(up.get("version") or "")[:20]
        detail = re.sub(r"[^\x20-\x7e]", "", str(up.get("detail") or ""))[:300]
        if (state, version) != (con["update_state"], con["update_version"]) and state in ("failed", "refused"):
            audit("connector_update_" + state, con["client_id"], actor="connector", connector=con["id"],
                  name=con["name"], version=version, reason=detail)
        db().execute("UPDATE connectors SET update_state=?, update_version=?, update_detail=?, update_at=? WHERE id=?",
                     (state, version, detail, now, con["id"]))
    if con["update_version"] and con["version"] == con["update_version"] and con["update_state"] != "updated":
        db().execute("UPDATE connectors SET update_state='updated', update_detail='', update_at=?, update_to=NULL "
                     "WHERE id=?", (now, con["id"]))
        audit("connector_updated", con["client_id"], actor="connector", connector=con["id"], name=con["name"],
              version=con["version"])
    elif con["update_to"] and con["version"] and not is_newer(con["update_to"], con["version"]):
        db().execute("UPDATE connectors SET update_to=NULL WHERE id=?", (con["id"],))
    con = db().execute("SELECT * FROM connectors WHERE id=?", (con["id"],)).fetchone()
    return jsonify(ok=True, update=update_offer(con))


# ---------------------------------------------------------------- connector releases
_releases = {"stamp": None, "list": []}


def is_newer(a, b):
    try:
        return protocol.version_tuple(a) > protocol.version_tuple(b or "0")
    except ValueError:
        return False


def load_release(d):
    """A release folder's description, if it's complete and correctly signed. (Connectors check again themselves.)"""
    env = json.loads((d / "release.json").read_text(encoding="utf-8"))
    m, sig, key = env.get("manifest") or {}, env.get("signature"), env.get("key")
    if m.get("product") != "pegasus-connector" or m.get("version") != d.name:
        raise ValueError("the description doesn't match its folder")
    protocol.verify_release(m, sig, RELEASE_KEYS or [key])
    bundle = d / "bundle.zip"
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != m.get("bundle_sha256"):
        raise ValueError("bundle.zip doesn't match the signed checksum")
    return {"version": m["version"], "created_at": m.get("created_at"), "notes": m.get("notes") or "",
            "key_fingerprint": protocol.fingerprint(key), "size": bundle.stat().st_size, "dir": d,
            "files": len(m.get("files") or {})}


def releases():
    """Every valid release in PEGASUS_DATA/releases, newest first (re-read when the folder changes)."""
    if not RELEASES_DIR.is_dir():
        return []
    dirs = [d for d in RELEASES_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    stamp = tuple(sorted((d.name, (d / "release.json").stat().st_mtime if (d / "release.json").exists() else 0,
                          (d / "bundle.zip").stat().st_mtime if (d / "bundle.zip").exists() else 0) for d in dirs))
    if stamp != _releases["stamp"]:
        out = []
        for d in dirs:
            try:
                protocol.version_tuple(d.name)
                out.append(load_release(d))
            except (OSError, ValueError, KeyError, TypeError) as e:
                print(f"Ignoring connector release {d.name}: {e}")
        _releases.update(stamp=stamp, list=sorted(out, key=lambda r: protocol.version_tuple(r["version"]), reverse=True))
    return _releases["list"]


def latest_release():
    rs = releases()
    return rs[0] if rs else None


def release_view(r):
    return {k: r[k] for k in ("version", "created_at", "notes", "key_fingerprint", "size", "files")}


def find_release(version):
    for r in releases():
        if r["version"] == version:
            return r
    return None


def update_offer(con):
    """The update to offer this connector now, if any."""
    rel = latest_release()
    if not rel or not is_newer(rel["version"], con["version"]):
        return None
    if con["update_state"] in ("failed", "refused") and con["update_version"] == rel["version"] \
            and con["update_to"] != rel["version"]:
        return None                       # it said no to this one; an admin can ask again with Update now
    if con["update_to"] == rel["version"]:          # someone clicked Update now; each click is a new request
        return {"version": rel["version"], "request": f"r{int(con['update_requested_at'] or 0)}"}
    if get_setting(con["client_id"], "connector_updates", "manual") == "auto":
        return {"version": rel["version"], "request": "auto"}
    return None


@app.get("/api/connector/v1/releases/<version>/release")
def connector_release(version):
    if not connector_auth():
        return unauthorized()
    r = find_release(version)
    if not r:
        return jsonify(error="No such release."), 404
    return send_file(r["dir"] / "release.json", mimetype="application/json")


@app.get("/api/connector/v1/releases/<version>/bundle")
def connector_bundle(version):
    if not connector_auth():
        return unauthorized()
    r = find_release(version)
    if not r:
        return jsonify(error="No such release."), 404
    return send_file(r["dir"] / "bundle.zip", mimetype="application/zip")


@app.get("/api/releases")
@need("viewer")
def list_releases():
    if not staff():
        return jsonify(error="Only Astute staff see connector releases."), 403
    return jsonify(releases=[release_view(r) for r in releases()])


@app.post("/api/connectors/<con_id>/update")
@need("admin")
def request_connector_update(con_id):
    c = db().execute("SELECT * FROM connectors WHERE id=? AND revoked=0", (con_id,)).fetchone()
    if not c:
        return jsonify(error="No such connector."), 404
    get_client(c["client_id"])
    rel = latest_release()
    if not rel or not is_newer(rel["version"], c["version"]):
        return jsonify(error="This connector already runs the newest release."), 409
    db().execute("UPDATE connectors SET update_to=?, update_requested_at=?, update_state=NULL, update_version=NULL, "
                 "update_detail=NULL WHERE id=?", (rel["version"], time.time(), con_id))
    audit("connector_update_requested", c["client_id"], connector=con_id, name=c["name"], version=rel["version"])
    return jsonify(ok=True, version=rel["version"])


@app.put("/api/clients/<cid>/connector-updates")
@need("admin")
def put_connector_updates(cid):
    get_client(cid)
    mode = (request.get_json(silent=True) or {}).get("mode")
    if mode not in ("manual", "auto"):
        return jsonify(error="Choose manual or automatic updates."), 400
    put_setting(cid, "connector_updates", mode)
    audit("connector_updates_changed", cid, mode=mode)
    return jsonify(mode=mode)


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
        return unauthorized()
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
        return unauthorized()
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
                     (status, time.time(), json.dumps(results)[:2000000], jid))
        finalize_pending()
    return jsonify(ok=True)


# ---------------------------------------------------------------- page
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found."), 404
    return e


@app.errorhandler(409)
def conflict(e):
    return jsonify(error=e.description or "That conflicts with the current state."), 409


@app.errorhandler(405)
def not_allowed(e):
    return jsonify(error="That method isn't allowed here."), 405


@app.get("/favicon.ico")
def favicon():
    return "", 204


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


def main():
    init_db()
    signing_key()
    c = connect()
    users = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    c.close()
    host, port = os.environ.get("PEGASUS_HOST", "127.0.0.1"), int(os.environ.get("PEGASUS_PORT", "8443"))
    print(f"Pegasus control plane {__version__} on http://{host}:{port} "
          f"(signing key {protocol.fingerprint(protocol.public_key_b64(signing_key()))})")
    if not users:
        print("No accounts yet: open the page to create the first admin"
              + (" (you'll need PEGASUS_ADMIN_PASSWORD)." if ADMIN_PASSWORD else " (from this machine)."))
    if STATUS_EVERY:
        threading.Thread(target=auto_status_loop, daemon=True).start()
        print(f"Checking every domain's status every {STATUS_EVERY // 60} minutes (PEGASUS_STATUS_EVERY=0 turns it off)")
    threading.Thread(target=schedule_loop, daemon=True).start()
    threading.Thread(target=advisory_loop, daemon=True).start()
    try:
        from waitress import serve
    except ImportError:
        print("waitress isn't installed, so this runs on Flask's development server (fine on a laptop).")
        app.run(host=host, port=port, threaded=True)
        return
    serve(app, host=host, port=port, threads=THREADS, channel_timeout=120, ident="Pegasus")


init_db()
app.secret_key = session_secret()
if TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

if __name__ == "__main__":
    main()
