"""End to end: real control plane (HTTP) + real connector loop, with simulated PeopleSoft servers instead of SSH."""
import filecmp
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = tempfile.mkdtemp()
os.environ.update(PEGASUS_DATA=TMP + "/cp", PEGASUS_ADMIN_PASSWORD="pw", PEGASUS_COOKIE_SECURE="false")
sys.path[:0] = [str(ROOT / "control-plane"), str(ROOT / "connector")]

import pytest  # noqa: E402
import requests  # noqa: E402
from werkzeug.serving import make_server  # noqa: E402

from pegasus_cloud import app as cp  # noqa: E402
from pegasus_connector import agent as ag, protocol  # noqa: E402
from pegasus_connector.operations import OperationError, build  # noqa: E402

INVENTORY = """environment,tier,host,ip,role,os_user,domain,env_script
HRDEV,DEV,hrdevweb01,10.0.1.11,web,psadm2,peoplesoft,/u01/pt/psconfig.sh
HRDEV,DEV,hrdevapp01,10.0.1.21,app,psadm2,HRDEV,/u01/pt/psconfig.sh
HRDEV,DEV,hrdevapp01,10.0.1.21,prcs,psadm2,PRCSDOM,/u01/pt/psconfig.sh
HRPRD,PRD,hrprdapp01,10.0.9.21,app,psadm2,HRPRD,/u01/pt/psconfig.sh
"""


class FakeServers:
    """Pretends to be the PeopleSoft servers: answers psadmin and the levels script."""
    def __init__(self):
        self.user = "opc"
        self.calls = []
        self.state = {}

    def run(self, target, command, stdin=None, on_output=None, timeout=900):
        self.calls.append((target["host"], command))
        out, code = "", 0
        if "hostname" in command and "uptime" in command:
            out = f"{target['host']}\nopc\n 10:00 up 3 days\n"
        elif "sstatus" in command or "-p status" in command or "-w status" in command:
            up = self.state.get(target["domain"], True)
            out = ("BBL  ( IDLE )\nPSAPPSRV ( IDLE )\n" if target["role"] == "app" else
                   "started\n" if up else "is not started\n") if up else "is not started\n"
        elif " boot " in command or "-p start" in command or "-w start" in command:
            self.state[target["domain"]] = True
            out = "started\n"
        elif "shutdown" in command or "-p stop" in command:
            self.state[target["domain"]] = False
            out = "stopped\n"
        elif command.endswith("bash -s"):
            out = "PL|pt|8.62.12\nPL|jdk|21.0.12|/u01/pt/jdk\n"
        else:
            out, code = "unexpected command\n", 1
        if on_output:
            on_output(out)
        return code


@pytest.fixture(scope="module")
def env():
    srv = make_server("127.0.0.1", 0, cp.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}"
    admin = requests.Session()
    admin.headers["X-Requested-With"] = "pegasus"
    assert admin.post(url + "/api/login", json={"password": "pw", "name": "ashwini"}).ok
    cid = admin.post(url + "/api/clients", json={"name": "MiraCosta College"}).json()["id"]
    assert admin.put(url + f"/api/clients/{cid}/inventory", json={"csv": INVENTORY}).json()["servers"] == 4
    tok = admin.post(url + f"/api/clients/{cid}/tokens").json()
    cfg_path = TMP + "/conn/config.json"
    key = Path(TMP + "/id_rsa"); key.write_text("x")
    cfg = ag.register(url, tok["token"], cfg_path, "opc", str(key))
    fake = FakeServers()
    agent = ag.Agent(cfg_path, runner=fake)
    yield {"url": url, "admin": admin, "cid": cid, "agent": agent, "fake": fake, "cfg": cfg, "token": tok}
    srv.shutdown()


def run_job(e, body):
    r = e["admin"].post(e["url"] + f"/api/clients/{e['cid']}/run", json=body)
    assert r.status_code == 200, r.text
    jid = r.json()["job"]
    assert e["agent"].poll_once(wait=2)
    for _ in range(50):
        j = e["admin"].get(e["url"] + f"/api/jobs/{jid}").json()
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.1)
    raise AssertionError("job didn't finish")


def test_protocol_files_identical():
    assert filecmp.cmp(ROOT / "connector/pegasus_connector/protocol.py",
                       ROOT / "control-plane/pegasus_cloud/protocol.py", shallow=False)


def test_registration_token_is_single_use(env):
    with pytest.raises(RuntimeError, match="isn't valid"):
        ag.register(env["url"], env["token"]["token"], TMP + "/other.json", "opc", "/k")
    assert env["cfg"]["client_name"] == "MiraCosta College"
    assert protocol.fingerprint(env["cfg"]["signing_key"]) == env["token"]["fingerprint"]
    assert os.stat(TMP + "/conn/config.json").st_mode & 0o077 == 0


def test_connector_shows_online(env):
    d = env["admin"].get(env["url"] + f"/api/clients/{env['cid']}").json()
    assert d["connectors"][0]["online"] and len(d["environments"]) == 2


def test_status_reads_domain_states(env):
    j = run_job(env, {"environment": "HRDEV", "action": "status"})
    assert j["status"] == "succeeded"
    assert [s["state"] for s in j["steps"]] == ["running", "running", "running"]
    assert "BBL" in j["text"]


def test_stop_and_start_use_the_right_order(env):
    env["fake"].calls.clear()
    j = run_job(env, {"environment": "HRDEV", "action": "stop"})
    assert j["status"] == "succeeded"
    assert [h for h, _ in env["fake"].calls] == ["hrdevweb01", "hrdevapp01", "hrdevapp01"]
    assert "psadmin -w shutdown" in env["fake"].calls[0][1] and "sudo -n -iu psadm2" in env["fake"].calls[0][1]
    j = run_job(env, {"environment": "HRDEV", "action": "status"})
    assert all(s["state"] == "stopped" for s in j["steps"])
    env["fake"].calls.clear()
    run_job(env, {"environment": "HRDEV", "action": "start"})
    assert ["psadmin -c boot" in c for _, c in env["fake"].calls] == [True, False, False]


def test_prd_needs_typed_confirmation(env):
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRPRD", "action": "stop"})
    assert r.status_code == 409 and r.json()["need_confirm"]
    j = run_job(env, {"environment": "HRPRD", "action": "stop", "confirm": "hrprd"})
    assert j["status"] == "succeeded"


def test_levels_and_ping(env):
    j = run_job(env, {"environment": "HRDEV", "action": "levels"})
    assert j["status"] == "succeeded" and len(j["steps"]) == 2 and "PL|pt|8.62.12" in j["text"]
    j = run_job(env, {"environment": "HRDEV", "action": "ping", "host": "hrdevweb01"})
    assert len(j["steps"]) == 1 and "hrdevweb01" in j["text"]


def test_inventory_rejects_unsafe_values(env):
    bad = INVENTORY + "HRDEV,DEV,x,1.2.3.4,app,psadm2,HR;rm -rf /,/x\n"
    r = env["admin"].put(env["url"] + f"/api/clients/{env['cid']}/inventory", json={"csv": bad})
    assert r.status_code == 400 and "domain" in r.json()["error"]


def signed(e, steps, **over):
    now = int(time.time())
    job = {"v": 1, "id": "j_test" + str(time.time_ns()), "tenant": e["cid"], "connector": e["cfg"]["connector_id"],
           "op": "run", "params": {"steps": steps, "stop_on_failure": True}, "issued_at": now, "expires_at": now + 600}
    job.update(over)
    return job, protocol.sign(job, cp.signing_key())


def handle_and_capture(e, job, sig):
    posted = []
    orig = e["agent"].post
    e["agent"].post = lambda path, body: posted.append(body) or type("R", (), {"status_code": 200})()
    try:
        e["agent"].handle(job, sig)
    finally:
        e["agent"].post = orig
    return posted[-1]


TARGET = {"host": "hrdevapp01", "ip": "10.0.1.21", "role": "app", "os_user": "psadm2", "domain": "HRDEV",
          "env_script": "/u01/pt/psconfig.sh"}


def test_connector_refuses_tampered_expired_and_foreign_jobs(env):
    job, sig = signed(env, [{"op": "domain.status", "target": TARGET}])
    job["params"]["steps"][0]["op"] = "domain.stop"                    # changed after signing
    assert handle_and_capture(env, job, sig)["status"] == "rejected"
    job, sig = signed(env, [{"op": "domain.status", "target": TARGET}], expires_at=int(time.time()) - 5)
    assert "expired" in handle_and_capture(env, job, sig)["text"]
    job, sig = signed(env, [{"op": "domain.status", "target": TARGET}], connector="k_someoneelse")
    assert "different connector" in handle_and_capture(env, job, sig)["text"]
    job, sig = signed(env, [{"op": "domain.status", "target": TARGET}])
    assert handle_and_capture(env, job, sig)["status"] == "succeeded"
    assert "already received" in handle_and_capture(env, job, sig)["text"]          # replay


def test_connector_refuses_commands_even_when_signed(env):
    for step in ({"op": "shell", "target": TARGET},
                 {"op": "domain.stop", "target": dict(TARGET, domain="HR; rm -rf /")},
                 {"op": "domain.stop", "target": dict(TARGET, os_user="root$(id)")},
                 {"op": "levels", "target": dict(TARGET, java_home="relative/path")}):
        job, sig = signed(env, [step])
        assert handle_and_capture(env, job, sig)["status"] == "rejected", step
    with pytest.raises(OperationError):
        build("domain.status", {"target": dict(TARGET, ip="10.0.0.1 -oProxyCommand=x")}, "opc")


def test_local_policy_read_only_and_blocked_hosts(env):
    pol = Path(TMP + "/conn/policy.json")
    pol.write_text(json.dumps({"read_only": True}))
    job, sig = signed(env, [{"op": "domain.stop", "target": TARGET}])
    assert "read-only" in handle_and_capture(env, job, sig)["text"]
    job, sig = signed(env, [{"op": "domain.status", "target": TARGET}])
    assert handle_and_capture(env, job, sig)["status"] == "succeeded"
    pol.write_text(json.dumps({"blocked_hosts": ["hrdevapp01"]}))
    job, sig = signed(env, [{"op": "domain.status", "target": TARGET}])
    assert "blocked" in handle_and_capture(env, job, sig)["text"]
    pol.write_text(json.dumps({"paused": True}))
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV", "action": "status"})
    env["agent"].poll_once(wait=2)
    time.sleep(0.3)
    j = env["admin"].get(env["url"] + f"/api/jobs/{r.json()['job']}").json()
    assert j["status"] == "rejected" and "paused" in j["text"]
    pol.unlink()


def test_one_job_at_a_time_per_environment(env):
    a = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV", "action": "status"})
    b = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV", "action": "status"})
    assert a.ok and b.status_code == 409
    env["agent"].poll_once(wait=2)


def test_revoked_connector_is_cut_off(env):
    assert env["admin"].delete(env["url"] + f"/api/connectors/{env['cfg']['connector_id']}").ok
    assert env["agent"].run_forever(log=lambda *_: None) == 2


def test_admin_api_needs_sign_in(env):
    assert requests.get(env["url"] + "/api/clients").status_code == 401
    assert requests.get(env["url"] + "/api/connector/v1/jobs/next",
                        headers={"Authorization": "Bearer k_x.y"}).status_code == 401
