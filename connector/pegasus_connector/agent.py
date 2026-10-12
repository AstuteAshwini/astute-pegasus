"""The connector's outbound loop: ask the control plane for work, check it, run it, stream the output back.

The connector only ever makes outbound HTTPS requests. Nothing connects to it.
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

from . import __version__, patching, policy as local_policy, protocol
from .operations import OperationError, SSHRunner, build, check_target, parse_levels

API = "/api/connector/v1"


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


def register(url, token, config_path, ssh_user, key_path, name=None, session=None):
    """Trade a one-time registration token for this connector's identity and the control plane's signing key."""
    url = check_url(url)
    s = session or requests.Session()
    r = s.post(f"{url}{API}/register", timeout=30, json={
        "token": token, "name": name or socket.gethostname(), "hostname": socket.gethostname(),
        "version": __version__, "platform": platform.platform()})
    if r.status_code != 200:
        raise RuntimeError(f"Registration failed ({r.status_code}): {_err(r)}")
    j = r.json()
    cfg = {"url": url, "connector_id": j["connector_id"], "secret": j["secret"], "tenant": j["tenant"],
           "client_name": j.get("client_name", ""), "signing_key": j["signing_public_key"],
           "ssh": {"user": ssh_user, "key_path": key_path}}
    save_config(config_path, cfg)
    return cfg


def _err(r):
    try:
        return r.json().get("error") or r.text[:200]
    except ValueError:
        return r.text[:200]


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
        self.s.headers.update({"Authorization": f"Bearer {self.cfg['connector_id']}.{self.cfg['secret']}",
                               "X-Connector-Version": __version__})
        self.seen = collections.deque(maxlen=5000)
        self.stop = threading.Event()
        self.cache_dir = Path(os.environ.get("PEGASUS_CACHE") or self.config_path.parent / "cache")
        self.poll_interval = float(os.environ.get("PEGASUS_APPLY_POLL", "5"))

    def get(self, path, **kw):
        return self.s.get(f"{self.url}{API}{path}", timeout=kw.pop("timeout", 40), **kw)

    def post(self, path, body):
        return self.s.post(f"{self.url}{API}{path}", json=body, timeout=30)

    def fetch(self, wait=25):
        """One long-poll. Returns (job, signature) or None."""
        r = self.get("/jobs/next", params={"wait": wait}, timeout=wait + 15)
        if r.status_code == 204:
            return None
        if r.status_code == 401:
            raise PermissionError("The control plane no longer accepts this connector. Register it again.")
        r.raise_for_status()
        j = r.json()
        return j["job"], j["signature"]

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

    def _heartbeat(self):
        while not self.stop.wait(30):
            try:
                self.post("/heartbeat", {"version": __version__})
            except requests.RequestException:
                pass

    def run_forever(self, log=print):
        log(f"Pegasus connector {__version__} for {self.cfg.get('client_name') or self.cfg['tenant']} "
            f"-> {self.url} (key {protocol.fingerprint(self.cfg['signing_key'])})")
        threading.Thread(target=self._heartbeat, daemon=True).start()
        workers = max(1, int(os.environ.get("PEGASUS_WORKERS", "4")))
        slots = threading.BoundedSemaphore(workers)   # several jobs at once, e.g. a status check during a download

        def work(job, sig):
            try:
                self.handle(job, sig)
            finally:
                slots.release()
        backoff = 1
        while not self.stop.is_set():
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
                threading.Thread(target=work, args=got, daemon=True).start()
            else:
                slots.release()
        return 0

