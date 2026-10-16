"""Connector auto-update: signed releases, offers, install and verification, refusals, the supervisor, and a real
restart into an installed version. Uses its own client so its connectors don't pick up other tests' jobs."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import ROOT
from fakes import FakeServers
from pegasus_cloud import app as cp
from pegasus_connector import agent as ag, protocol, updater

sys.path.insert(0, str(ROOT / "scripts"))
import connector_release as rel  # noqa: E402

RELEASE_KEY = protocol.new_private_key()
PUB = protocol.public_key_b64(RELEASE_KEY)
DATA = os.environ["PEGASUS_DATA"]


def files_for(version):
    """The connector's own code, as release <version>."""
    files = rel.package_files()
    files["pegasus_connector/__init__.py"] = f'__version__ = "{version}"\n'.encode()
    return files


@pytest.fixture(scope="module")
def up(env, tmp_path_factory):
    cid = env["admin"].post(env["url"] + "/api/clients", json={"name": "Update Test College"}).json()["id"]
    agents = []

    def new_agent(name):
        tok = env["admin"].post(env["url"] + f"/api/clients/{cid}/tokens").json()["token"]
        path = tmp_path_factory.mktemp(name) / "config.json"
        ag.register(env["url"], tok, str(path), "opc", "/k", name=name)
        a = ag.Agent(path, runner=FakeServers())
        a.log = lambda *_: None
        agents.append(a)
        return a
    rel.build_release(RELEASE_KEY, DATA, "9.0.0", files_for("9.0.0"), notes="test release")
    yield {"cid": cid, "new_agent": new_agent}


@pytest.fixture(autouse=True)
def trust_release_key(monkeypatch):
    monkeypatch.setattr(updater, "RELEASE_KEYS", [PUB])


def connector(env, cid, con_id):
    d = env["admin"].get(env["url"] + f"/api/clients/{cid}").json()
    return d, [c for c in d["connectors"] if c["id"] == con_id][0]


def test_manual_mode_offers_only_after_update_now(env, up):
    a = up["new_agent"]("manual")
    a.heartbeat()
    assert a.offer is None
    d, c = connector(env, up["cid"], a.cfg["connector_id"])
    assert d["latest_release"]["version"] == "9.0.0" and d["latest_release"]["key_fingerprint"] == protocol.fingerprint(PUB)
    assert c["update_available"] == "9.0.0" and c["can_update"] and d["connector_updates"] == "manual"
    assert env["admin"].post(env["url"] + f"/api/connectors/{a.cfg['connector_id']}/update", json={}).ok
    a.heartbeat()
    assert a.offer["version"] == "9.0.0"


def test_install_verifies_and_reports(env, up):
    a = up["new_agent"]("install")
    env["admin"].post(env["url"] + f"/api/connectors/{a.cfg['connector_id']}/update", json={})
    a.heartbeat()
    assert a.try_update()
    d = updater.versions_dir(a.config_path) / "9.0.0"
    assert (d / "pegasus_connector" / "agent.py").exists() and (d / "release.json").exists()
    assert updater.best_installed(a.config_path) == d
    _, c = connector(env, up["cid"], a.cfg["connector_id"])
    assert c["update"]["state"] == "restarting" and c["update"]["version"] == "9.0.0"
    # someone edits the installed code: it no longer verifies, and isn't used
    p = d / "pegasus_connector" / "operations.py"
    p.write_text(p.read_text() + "\nimport os; os.system('evil')\n")
    assert updater.best_installed(a.config_path, log=lambda *_: None) is None
    assert "operations.py has been changed" in (d / "BAD").read_text()


def test_a_release_signed_with_another_key_is_refused(env, up, monkeypatch):
    a = up["new_agent"]("wrongkey")
    monkeypatch.setattr(updater, "RELEASE_KEYS", [protocol.public_key_b64(protocol.new_private_key())])
    env["admin"].post(env["url"] + f"/api/connectors/{a.cfg['connector_id']}/update", json={})
    a.heartbeat()
    assert not a.try_update()
    assert not (updater.versions_dir(a.config_path) / "9.0.0").exists()
    _, c = connector(env, up["cid"], a.cfg["connector_id"])
    assert c["update"]["state"] == "failed" and "trusted Astute release key" in c["update"]["detail"]
    ev = cp.connect().execute("SELECT * FROM audit WHERE event='connector_update_failed' ORDER BY id DESC").fetchone()
    assert "9.0.0" in ev["detail"]
    a.heartbeat()                                   # it failed: not offered again for this request
    assert a.offer is None


def test_no_release_key_means_no_updates(env, up, monkeypatch):
    monkeypatch.setattr(updater, "RELEASE_KEYS", [])
    a = up["new_agent"]("nokey")
    a.heartbeat()
    _, c = connector(env, up["cid"], a.cfg["connector_id"])
    assert not c["can_update"]
    with pytest.raises(updater.UpdateError, match="no Astute release key"):
        updater.install(a.get, a.config_path, "9.0.0")


def test_tampered_bundle_is_refused(env, up):
    rdir = Path(DATA) / "releases" / "9.0.0"
    good = (rdir / "bundle.zip").read_bytes()
    a = up["new_agent"]("tamper")

    class Fake:
        def __init__(self, status, content=b"", js=None):
            self.status_code, self.content, self._js = status, content, js

        def json(self):
            return self._js

    env_json = json.loads((rdir / "release.json").read_text())

    def get(path, **kw):
        if path.endswith("/release"):
            return Fake(200, js=env_json)
        return Fake(200, content=good[:-10] + b"0123456789")
    with pytest.raises(updater.UpdateError, match="doesn't match its signed checksum"):
        updater.install(get, a.config_path, "9.0.0")
    with pytest.raises(updater.UpdateError, match="isn't newer"):
        updater.install(get, a.config_path, "0.1.0")


def test_local_policy_can_refuse_updates(env, up):
    a = up["new_agent"]("policy")
    a.policy_path.write_text(json.dumps({"auto_update": False}))
    env["admin"].post(env["url"] + f"/api/connectors/{a.cfg['connector_id']}/update", json={})
    a.heartbeat()
    assert a.offer is None and a.update_state["state"] == "refused"
    a.heartbeat()
    _, c = connector(env, up["cid"], a.cfg["connector_id"])
    assert c["update"]["state"] == "refused" and "local policy" in c["update"]["detail"]


def test_automatic_mode_and_waiting_for_jobs(env, up):
    a = up["new_agent"]("auto")
    r = env["admin"].put(env["url"] + f"/api/clients/{up['cid']}/connector-updates", json={"mode": "auto"})
    assert r.json()["mode"] == "auto"
    a.heartbeat()
    assert a.offer["version"] == "9.0.0"
    # with a job running, the loop takes no new work and doesn't install
    a.active = 1
    a.stop.clear()
    import threading
    t = threading.Thread(target=lambda: setattr(a, "code", a.run_forever(log=lambda *_: None)), daemon=True)
    t.start()
    time.sleep(1.5)
    assert t.is_alive() and not (updater.versions_dir(a.config_path) / "9.0.0").exists()
    a.active = 0
    t.join(20)
    assert a.code == updater.RESTART and (updater.versions_dir(a.config_path) / "9.0.0").exists()
    assert a.stop.is_set()                  # its heartbeat thread stops too, so the old version goes quiet
    env["admin"].put(env["url"] + f"/api/clients/{up['cid']}/connector-updates", json={"mode": "manual"})


def test_supervisor_falls_back_when_an_update_wont_start(tmp_path):
    cfg = tmp_path / "config.json"
    d = tmp_path / "versions" / "9.0.0"
    d.mkdir(parents=True)
    calls = []

    class P:
        def __init__(self, code, confirm=False):
            self.code, self.confirm = code, confirm

        def wait(self, timeout=None):
            if self.confirm:
                (d / "CONFIRMED").touch()
            return self.code
    results = [P(1)]
    ok = {"v": True}
    orig = updater.verify_installed
    updater.verify_installed = lambda dd, keys=None: ok["v"]
    try:
        code = updater.supervise(cfg, lambda: calls.append("in-process") or 0, log=lambda *_: None,
                                 popen=lambda *a, **k: results.pop(0))
    finally:
        updater.verify_installed = orig
    assert code == 0 and calls == ["in-process"] and "before it reached" in (d / "BAD").read_text()


def test_supervisor_restarts_into_the_newest_after_an_update(tmp_path):
    cfg = tmp_path / "config.json"
    started = []

    def run_in_process():
        started.append("in-process")
        if len(started) == 1:
            (tmp_path / "versions" / "9.0.0").mkdir(parents=True)
            return updater.RESTART                     # installed an update
        return 0

    class P:
        def __init__(self, args, cwd, env):
            started.append(Path(cwd).name)

        def wait(self, timeout=None):
            return 0
    orig = updater.verify_installed
    updater.verify_installed = lambda d, keys=None: True
    try:
        assert updater.supervise(cfg, run_in_process, log=lambda *_: None, popen=P) == 0
    finally:
        updater.verify_installed = orig
    assert started == ["in-process", "9.0.0"]


def test_the_installed_version_really_runs_and_reports_in(env, up):
    """Start versions/9.0.0 the way the supervisor does, as a separate process, and watch it check in as 9.0.0."""
    a = up["new_agent"]("real")
    env["admin"].post(env["url"] + f"/api/connectors/{a.cfg['connector_id']}/update", json={})
    a.heartbeat()
    assert a.try_update()
    d = updater.versions_dir(a.config_path) / "9.0.0"
    child_env = dict(os.environ, PEGASUS_VERSION_DIR=str(d))
    child_env.pop("PYTHONPATH", None)
    p = subprocess.Popen([sys.executable, "-m", "pegasus_connector", "--config", str(a.config_path), "run", "--child"],
                         cwd=str(d), env=child_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(100):
            if (d / "CONFIRMED").exists():
                break
            time.sleep(0.2)
        assert (d / "CONFIRMED").exists(), "the new version never reached the control plane"
        for _ in range(50):
            _, c = connector(env, up["cid"], a.cfg["connector_id"])
            if c["version"] == "9.0.0" and (c["update"] or {}).get("state") == "updated":
                break
            time.sleep(0.2)
        assert c["version"] == "9.0.0" and c["update"]["state"] == "updated" and not c["update_available"]
        assert cp.connect().execute("SELECT COUNT(*) FROM audit WHERE event='connector_updated'").fetchone()[0] >= 1
    finally:
        p.terminate()
        out = p.communicate(timeout=20)[0]
    assert "Pegasus connector 9.0.0" in out, out
