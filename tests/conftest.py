"""A real control plane (HTTP, its own data folder) and a real connector loop against simulated servers."""
import os
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp()
os.environ.update(PEGASUS_DATA=TMP + "/cp", PEGASUS_ADMIN_PASSWORD="setup-pw", PEGASUS_COOKIE_SECURE="false",
                  PEGASUS_CACHE=TMP + "/cache", PEGASUS_APPLY_POLL="0")
sys.path[:0] = [str(ROOT / "control-plane"), str(ROOT / "connector"), str(ROOT / "tests")]

import pytest  # noqa: E402
import requests  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from fakes import FakeServers  # noqa: E402
from pegasus_cloud import app as cp, auth  # noqa: E402
from pegasus_connector import agent as ag  # noqa: E402

INVENTORY = """environment,tier,host,ip,role,os_user,domain,env_script
HRDEV,DEV,hrdevweb01,10.0.1.11,web,psadm2,peoplesoft,/u01/pt/psconfig.sh
HRDEV,DEV,hrdevapp01,10.0.1.21,app,psadm2,HRDEV,/u01/pt/psconfig.sh
HRDEV,DEV,hrdevapp01,10.0.1.21,prcs,psadm2,PRCSDOM,/u01/pt/psconfig.sh
HRPRD,PRD,hrprdapp01,10.0.9.21,app,psadm2,HRPRD,/u01/pt/psconfig.sh
"""
ADMIN = {"email": "ashwini@beastute.com", "name": "Ashwini", "password": "correct horse battery 42"}


def session():
    s = requests.Session()
    s.headers["X-Requested-With"] = "pegasus"
    return s


def sign_in(url, email, password, secret=None):
    """Password, then MFA (enrolling on first sign-in). Returns (session, totp secret, recovery codes)."""
    s = session()
    r = s.post(url + "/api/login", json={"email": email, "password": password})
    assert r.ok, r.text
    codes = None
    if r.json()["next"] == "enroll":
        secret = r.json()["secret"]
        r = s.post(url + "/api/mfa/enroll", json={"code": auth.totp_now(secret)})
        assert r.ok, r.text
        codes = r.json()["recovery_codes"]
    else:
        import time
        used = cp.connect().execute("SELECT totp_last FROM users WHERE email=?", (email,)).fetchone()[0]
        # a code can't be used twice, so take the next step nobody has used yet (one step of drift is accepted)
        step = max(used + 1, int(time.time() // 30) - 1)
        r = s.post(url + "/api/login/mfa", json={"code": auth.totp_at(secret, step)})
        assert r.ok, r.text
    return s, secret, codes


@pytest.fixture(scope="session")
def env():
    srv = make_server("127.0.0.1", 0, cp.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}"
    assert session().post(url + "/api/setup", json=dict(ADMIN, setup_password="setup-pw")).ok
    admin, secret, codes = sign_in(url, ADMIN["email"], ADMIN["password"])
    cid = admin.post(url + "/api/clients", json={"name": "MiraCosta College"}).json()["id"]
    assert admin.put(url + f"/api/clients/{cid}/inventory", json={"csv": INVENTORY}).json()["servers"] == 4
    tok = admin.post(url + f"/api/clients/{cid}/tokens").json()
    cfg_path = TMP + "/conn/config.json"
    key = Path(TMP + "/id_rsa")
    key.write_text("x")
    cfg = ag.register(url, tok["token"], cfg_path, "opc", str(key))
    fake = FakeServers()
    agent = ag.Agent(cfg_path, runner=fake)
    yield {"url": url, "admin": admin, "cid": cid, "agent": agent, "fake": fake, "cfg": cfg, "token": tok,
           "secret": secret, "recovery": codes, "tmp": TMP}
    srv.shutdown()


def wait_job(e, jid, session_=None):
    import time
    s = session_ or e["admin"]
    for _ in range(100):
        j = s.get(e["url"] + f"/api/jobs/{jid}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.05)
    raise AssertionError(f"job {jid} didn't finish: {j}")


def drain(e):
    """Let the connector pick up and run everything queued (follow-up jobs included)."""
    n = 0
    while e["agent"].poll_once(wait=0.5):
        n += 1
    return n
