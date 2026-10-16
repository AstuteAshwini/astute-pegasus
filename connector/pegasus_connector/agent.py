"""The connector's outbound loop: ask the control plane for work, check it, run it, stream the output back.

The connector only ever makes outbound HTTPS requests. Nothing connects to it.

Identity: at registration the connector creates its own Ed25519 key and the control plane issues a certificate for
it (protocol.py). Every request is signed with that key, so nothing secret travels over the wire. The certificate is
renewed automatically, with a fresh key, well before it expires. A connector registered before certificates existed
(a shared secret in config.json) swaps the secret for a certificate the first time it starts.
"""
import collections
import json
import os
import platform
import socket
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

from . import __version__, patching, policy as local_policy, protocol, updater
from .operations import OperationError, SSHRunner, build, check_target, parse_levels

API = "/api/connector/v1"
RESTART_FOR_UPDATE = updater.RESTART
FAILED_UPDATE_RETRY = 6 * 3600          # seconds before an update that failed is offered again


def default_config_dir():
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "PegasusConnector"
    if os.geteuid() == 0:
        return Path("/etc/pegasus-connector")
    return Path.home() / ".pegasus-connector"


def check_url(url):
    u = urlparse(url)
    if u.scheme == "https":
        return url.rstrip("/")
    if u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1", "::1"):
        return url.rstrip("/")          # local development only
    raise ValueError("The control plane URL must start with https:// (plain http is only allowed for localhost).")


def save_config(path, cfg):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def checked_cert(j, signing_key, connector_id, private_key):
    """The certificate in a control plane reply, checked against the pinned signing key and our own key."""
    cert, sig = j.get("certificate"), j.get("certificate_signature")
    protocol.verify_cert(cert, sig, signing_key)
    if cert["connector"] != connector_id or cert["public_key"] != protocol.public_key_of(private_key):
        raise ValueError("the control plane returned a certificate for a different key")
    return cert, sig


def register(url, token, config_path, ssh_user, key_path, name=None, session=None):
    """Trade a one-time registration token for a certificate on this connector's own key."""
    url = check_url(url)
    s = session or requests.Session()
    key = protocol.new_private_key()
    r = s.post(f"{url}{API}/register", timeout=30, json={
        "token": token, "name": name or socket.gethostname(), "hostname": socket.gethostname(),
        "version": __version__, "platform": platform.platform(), "public_key": protocol.public_key_of(key)})
    if r.status_code != 200:
        raise RuntimeError(f"Registration failed ({r.status_code}): {_err(r)}")
    j = r.json()
    try:
        cert, sig = checked_cert(j, j["signing_public_key"], j["connector_id"], key)
    except (KeyError, ValueError) as e:
        raise RuntimeError(f"Registration failed: the control plane's certificate didn't check out ({e}).")
    cfg = {"url": url, "connector_id": j["connector_id"], "tenant": j["tenant"],
           "client_name": j.get("client_name", ""), "signing_key": j["signing_public_key"],
           "key": protocol.private_key_pem(key), "certificate": cert, "certificate_signature": sig,
           "ssh": {"user": ssh_user, "key_path": key_path}}
    save_config(config_path, cfg)
    return cfg


class SignedAuth(requests.auth.AuthBase):
    """Signs each request with the connector's key: method, path and query, time, a nonce and the body's hash."""

    def __init__(self, connector_id, private_key):
        self.connector_id, self.key = connector_id, private_key

    def __call__(self, r):
        body = r.body or b""
        if isinstance(body, str):
            body = body.encode()
        r.headers.update(protocol.sign_request(self.key, r.method, r.path_url, body))
        r.headers["X-Pegasus-Connector"] = self.connector_id
        r.headers.pop("Authorization", None)
        return r


def _err(r):
    try:
        return r.json().get("error") or r.text[:200]
    except ValueError:
        return r.text[:200]


def _day(t):
    return time.strftime("%Y-%m-%d", time.localtime(t))


class EventSink:
    """Buffers job output and sends it to the control plane about once a second."""

    def __init__(self, agent, job_id):
        self.agent, self.job_id = agent, job_id
        self.buf, self.seq, self.lock = [], 0, threading.Lock()

    def __call__(self, text):
        with self.lock:
            self.buf.append(text)

    def flush(self, final=None):
        with self.lock:
            text, self.buf = "".join(self.buf), []
        if not text and final is None:
            return
        body = {"seq": self.seq, "text": text}
        if final:
            body.update(final)
        self.seq += 1
        for attempt in range(6):
            try:
                r = self.agent.post(f"/jobs/{self.job_id}/events", body)
                if r.status_code < 500:
                    return
            except requests.RequestException:
                pass
            time.sleep(min(2 ** attempt, 20))


class Agent:
    def __init__(self, config_path, runner=None, session=None, policy_path=None):
        self.config_path = Path(config_path)
        self.cfg = load_config(self.config_path)
        self.url = check_url(self.cfg["url"])
        self.policy_path = Path(policy_path) if policy_path else self.config_path.parent / "policy.json"
        ssh = self.cfg.get("ssh") or {}
        self.runner = runner or SSHRunner(ssh.get("user") or "opc", os.path.expanduser(ssh.get("key_path") or ""),
                                          passphrase=os.environ.get("PEGASUS_SSH_PASSPHRASE"))
        self.s = session or requests.Session()
        self.s.headers["X-Connector-Version"] = __version__
        self.cfg_lock = threading.Lock()
        self._use_identity()
        self.seen = collections.deque(maxlen=5000)
        self.stop = threading.Event()
        self.cache_dir = Path(os.environ.get("PEGASUS_CACHE") or self.config_path.parent / "cache")
        self.poll_interval = float(os.environ.get("PEGASUS_APPLY_POLL", "5"))
        self.active, self.active_lock = 0, threading.Lock()
        self.offer = None                           # an update the control plane offered, if any
        self.update_state = None                    # what we last did about it, reported in each heartbeat
        self.failed_updates = {}                    # (version, request) -> when it failed
        self.confirmed = False
        self.log = print

    # ---- identity
    def _use_identity(self):
        if self.cfg.get("key") and self.cfg.get("certificate"):
            self.key = protocol.load_private_key(self.cfg["key"])
            self.s.auth = SignedAuth(self.cfg["connector_id"], self.key)
            self.s.headers.pop("Authorization", None)
        else:                                        # registered before certificates: shared secret until enrolled
            self.key = None
            self.s.auth = None
            self.s.headers["Authorization"] = f"Bearer {self.cfg['connector_id']}.{self.cfg['secret']}"

    @property
    def has_certificate(self):
        return self.key is not None

    def cert_days_left(self, now=None):
        if not self.has_certificate:
            return None
        return (self.cfg["certificate"]["not_after"] - (now or time.time())) / 86400

    def _take_certificate(self, r, new_key, what):
        if r.status_code != 200:
            raise RuntimeError(f"{what} failed ({r.status_code}): {_err(r)}")
        cert, sig = checked_cert(r.json(), self.cfg["signing_key"], self.cfg["connector_id"], new_key)
        with self.cfg_lock:
            cfg = dict(self.cfg, key=protocol.private_key_pem(new_key), certificate=cert, certificate_signature=sig)
            cfg.pop("secret", None)
            save_config(self.config_path, cfg)     # saved before use, so a crash can't strand the new key
            self.cfg = cfg
            self._use_identity()
        return cert

    def enroll(self):
        """Swap the shared secret this connector registered with for a certificate on a new key of its own."""
        key = protocol.new_private_key()
        r = self.post("/certificate/enroll", {"public_key": protocol.public_key_of(key)})
        return self._take_certificate(r, key, "Getting a certificate")

    def renew(self):
        """A new key and certificate, requested with (and signed by) the current key."""
        key = protocol.new_private_key()
        r = self.post("/certificate/renew", {"public_key": protocol.public_key_of(key)})
        return self._take_certificate(r, key, "Renewing the certificate")

    def ensure_identity(self, now=None):
        """Enroll if still on a shared secret; renew if the certificate is due. Never fatal: retried later."""
        try:
            if not self.has_certificate:
                cert = self.enroll()
                self.log(f"This connector now signs in with a certificate (valid until {_day(cert['not_after'])}). "
                         "The shared secret it used before has been removed.")
            elif self.cert_days_left(now) < protocol.RENEW_DAYS:
                cert = self.renew()
                self.log(f"Renewed this connector's certificate with a new key (valid until {_day(cert['not_after'])}).")
        except (requests.RequestException, RuntimeError, ValueError, KeyError) as e:
            self.log(f"Couldn't update this connector's certificate yet: {e}")

    # ---- HTTP
    def get(self, path, **kw):
        return self.s.get(f"{self.url}{API}{path}", timeout=kw.pop("timeout", 40), **kw)

    def post(self, path, body):
        return self.s.post(f"{self.url}{API}{path}", json=body, timeout=30)

    def fetch(self, wait=25):
        """One long-poll. Returns (job, signature) or None."""
        r = self.get("/jobs/next", params={"wait": wait}, timeout=wait + 15)
        if r.status_code == 204:
            self._reached()
            return None
        if r.status_code == 401:
            raise PermissionError(f"The control plane no longer accepts this connector ({_err(r)}). "
                                  "Register it again with a new token from Pegasus.")
        r.raise_for_status()
        self._reached()
        j = r.json()
        return j["job"], j["signature"]

    def _reached(self):
        """First successful contact: tell a supervising older version that this one works."""
        if not self.confirmed:
            self.confirmed = True
            updater.confirm()

    def poll_once(self, wait=25):
        """One long-poll, handling any job in this thread. Returns True if a job was handled."""
        got = self.fetch(wait)
        if not got:
            return False
        self.handle(*got)
        return True

    def handle(self, job, signature):
        sink = EventSink(self, job.get("id", "unknown"))
        try:
            protocol.verify(job, signature, self.cfg["signing_key"], self.cfg["connector_id"])
            if job["id"] in self.seen:
                raise ValueError("job was already received once")
            self.seen.append(job["id"])
            local_policy.check(local_policy.load(self.policy_path), job)
            steps = job["params"].get("steps") or []
            if not steps:
                raise ValueError("job has no steps")
            plans = []                                  # validate everything before running anything
            for st in steps:
                if st.get("op") in patching.HANDLED:
                    plans.append(("handler", patching.validate(st["op"], st, self.runner.user)))
                else:
                    plans.append(("command", build(st["op"], st, self.runner.user)))
        except (ValueError, OperationError, KeyError, TypeError, AttributeError) as e:
            sink(f"Refused by the connector: {e}\n")
            sink.flush({"done": True, "status": "rejected", "results": []})
            return
        results, ok, failed_at = [], True, None
        stop_on_failure = bool(job["params"].get("stop_on_failure"))
        ctx = patching.Context(self.runner, self.config_path, self.cache_dir, job["id"], self.poll_interval)
        flusher_stop = threading.Event()

        def flusher():
            while not flusher_stop.wait(1.0):
                sink.flush()

        threading.Thread(target=flusher, daemon=True).start()
        try:
            for n, (st, (kind, plan)) in enumerate(zip(steps, plans), start=1):
                t = st.get("target") or {}
                where = f" on {t.get('host') or t.get('ip')}" if t else ""
                if failed_at is not None and not st.get("always"):
                    continue                              # skipped after an earlier failure
                sink(f"\n--- [{n}/{len(steps)}] {st.get('label') or st['op']}{where}\n")
                started, captured, data = time.time(), [], None

                def out(text, captured=captured):
                    captured.append(text)
                    sink(text)
                try:
                    if kind == "handler":
                        code, data = patching.run(st["op"], plan, ctx, out)
                    else:
                        cmd, stdin = plan
                        code = self.runner.run(check_target(st["target"]), cmd, stdin, on_output=out)
                        if st["op"] == "levels":
                            data = parse_levels("".join(captured))
                except Exception as e:                            # connection refused, auth failure, timeout...
                    code = None
                    out(f"Error: {e}\n")
                r = {"step": n - 1, "exit_code": code, "seconds": round(time.time() - started, 1),
                     "output": "".join(captured)[-8000:]}
                if data is not None:
                    r["data"] = data
                results.append(r)
                if code != 0 and not st.get("ignore_failure"):
                    ok = False
                    if stop_on_failure and failed_at is None and not st.get("independent"):
                        failed_at = n
                        if any(x.get("always") for x in steps[n:]):
                            sink("That step failed. Skipping the rest, except the steps that always run.\n")
                        else:
                            sink("Stopping here because that step failed.\n")
        finally:
            flusher_stop.set()
        sink.flush({"done": True, "status": "succeeded" if ok else "failed", "results": results})

    # ---- heartbeat and updates
    def heartbeat(self):
        """Report version, certificate and update state; take any update the control plane offers."""
        body = {"version": __version__, "update": self.update_state,
                "certificate_days_left": round(self.cert_days_left() or 0, 1),
                "can_update": bool(updater.RELEASE_KEYS)}
        r = self.post("/heartbeat", body)
        if r.status_code != 200:
            return
        self._reached()
        offer = (r.json() or {}).get("update")
        if not offer or not isinstance(offer, dict) or not offer.get("version"):
            self.offer = None
            return
        v, req = str(offer["version"]), str(offer.get("request") or "")
        failed = self.failed_updates.get((v, req))
        if failed and time.time() - failed < FAILED_UPDATE_RETRY:
            self.offer = None
            return
        if not local_policy.load(self.policy_path).get("auto_update", True):
            self.offer = None
            self.update_state = {"state": "refused", "version": v,
                                 "detail": "updates are turned off in this connector's local policy"}
            return
        self.offer = {"version": v, "request": req}

    def _heartbeat(self):
        last_identity = time.time()
        while not self.stop.wait(30):
            try:
                self.heartbeat()
            except requests.RequestException:
                pass
            if time.time() - last_identity > 3600:          # look at the certificate about once an hour
                last_identity = time.time()
                self.ensure_identity()

    def try_update(self):
        """Install the offered update. True if it's installed and the connector should restart into it."""
        v = self.offer["version"]
        self.update_state = {"state": "installing", "version": v}
        self.log(f"Installing connector update {v}")
        try:
            path = updater.install(self.get, self.config_path, v)
        except (updater.UpdateError, requests.RequestException, ValueError, OSError) as e:
            self.failed_updates[(v, self.offer.get("request") or "")] = time.time()
            self.offer = None
            self.update_state = {"state": "failed", "version": v, "detail": str(e)[:300]}
            self.log(f"Update {v} wasn't installed: {e}")
            try:
                self.heartbeat()
            except requests.RequestException:
                pass
            return False
        self.update_state = {"state": "restarting", "version": v}
        try:
            self.heartbeat()
        except requests.RequestException:
            pass
        self.log(f"Update {v} is verified and installed in {path}. Restarting into it.")
        return True

    def _work_started(self):
        with self.active_lock:
            self.active += 1

    def _work_done(self):
        with self.active_lock:
            self.active -= 1

    def run_forever(self, log=print):
        """Run until stopped. Returns 0 (stopped), 2 (no longer accepted) or RESTART_FOR_UPDATE."""
        try:
            return self._run(log)
        finally:
            self.stop.set()                    # stops the heartbeat thread too, so a replaced version goes quiet

    def _run(self, log):
        self.log = log
        log(f"Pegasus connector {__version__} for {self.cfg.get('client_name') or self.cfg['tenant']} "
            f"-> {self.url} (key {protocol.fingerprint(self.cfg['signing_key'])})")
        self.ensure_identity()
        if self.has_certificate:
            log(f"Signing in with certificate {self.cfg['certificate']['serial']}, "
                f"valid until {_day(self.cfg['certificate']['not_after'])}")
        try:
            self.heartbeat()
        except requests.RequestException:
            pass
        threading.Thread(target=self._heartbeat, daemon=True).start()
        workers = max(1, int(os.environ.get("PEGASUS_WORKERS", "4")))
        slots = threading.BoundedSemaphore(workers)   # several jobs at once, e.g. a status check during a download

        def work(job, sig):
            try:
                self.handle(job, sig)
            finally:
                self._work_done()
                slots.release()
        backoff, waiting_said = 1, False
        while not self.stop.is_set():
            if self.offer:                     # an update: take no new work, wait for running jobs, then install
                if self.active:
                    if not waiting_said:
                        log(f"Update {self.offer['version']} is waiting for {self.active} running job(s) to finish")
                        waiting_said = True
                    self.stop.wait(1)
                    continue
                waiting_said = False
                if self.try_update():
                    return RESTART_FOR_UPDATE
                continue
            if not slots.acquire(timeout=1):
                continue                       # every worker is busy
            try:
                got = self.fetch()
            except PermissionError as e:
                slots.release()
                log(str(e))
                return 2
            except requests.RequestException as e:
                slots.release()
                log(f"Can't reach the control plane ({e.__class__.__name__}); retrying in {backoff}s")
                self.stop.wait(backoff)
                backoff = min(backoff * 2, 60)
                continue
            backoff = 1
            if got:
                self._work_started()
                threading.Thread(target=work, args=got, daemon=True).start()
            else:
                slots.release()
        return 0

