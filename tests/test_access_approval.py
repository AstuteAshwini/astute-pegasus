"""SSH access needs a second person: an operator asks, another admin approves, then it runs. Production needs an end
date, and keys are removed by themselves once it passes."""
import datetime as dt
import time
import uuid

import pytest

from conftest import drain, sign_in, wait_job
from pegasus_cloud import app as cp, auth
from test_patching import ed25519_key


def url(env, path):
    return env["url"] + path.format(cid=env["cid"])


def make_user(env, role, email=None):
    email = email or f"{role}-{uuid.uuid4().hex[:6]}@beastute.com"
    pw = "long enough password 4 tests"
    cp.connect().execute("INSERT INTO users (id, email, name, pw_hash, role, created_at) VALUES (?,?,?,?,?,?)",
                         ("u_" + uuid.uuid4().hex[:12], email, role.title(), auth.hash_password(pw), role, time.time()))
    return sign_in(env["url"], email, pw)[0]


@pytest.fixture(scope="module")
def people(env):
    yield {"op": make_user(env, "operator", "ssh-op@beastute.com"), "admin2": make_user(env, "admin", "ssh-admin2@beastute.com")}
    cp.connect().execute("DELETE FROM users WHERE email IN ('ssh-op@beastute.com', 'ssh-admin2@beastute.com')")


def test_request_approve_and_run(env, people):
    op, admin2, admin = people["op"], people["admin2"], env["admin"]
    key = ed25519_key("sam@laptop")
    body = {"action": "add", "key": key, "account": "psadm2", "environments": ["HRDEV"]}
    r = op.post(url(env, "/api/clients/{cid}/access"), json=body)
    assert r.status_code == 400 and "who this is for" in r.json()["error"]
    r = op.post(url(env, "/api/clients/{cid}/access"), json=dict(body, note="Sam, new PS admin, CHG-9"))
    assert r.ok and r.json()["pending"] and r.json()["servers"] == 2
    rid = r.json()["request"]
    assert not cp.connect().execute("SELECT 1 FROM jobs WHERE kind='access.add' AND status='queued'").fetchone()
    reqs = op.get(url(env, "/api/clients/{cid}/access-requests")).json()["requests"]
    mine = [x for x in reqs if x["id"] == rid][0]
    assert mine["status"] == "pending" and mine["mine"] and not mine["can_decide"] and mine["can_withdraw"]
    # the operator can't approve (not an admin); nor could an admin approve their own request
    assert op.post(url(env, f"/api/access-requests/{rid}/approve"), json={}).status_code == 403
    r = admin.post(url(env, f"/api/access-requests/{rid}/approve"), json={"note": "ok"})
    assert r.ok, r.text
    drain(env)
    j = wait_job(env, r.json()["job"])
    assert j["status"] == "succeeded" and "approved by" in j["created_by"]
    v = [x for x in admin.get(url(env, "/api/clients/{cid}/access-requests")).json()["requests"] if x["id"] == rid][0]
    assert v["status"] == "done" and v["decided_by"] and v["job"] == r.json()["job"]
    assert admin.post(url(env, f"/api/access-requests/{rid}/approve"), json={}).status_code == 409   # only once
    events = [e[0] for e in cp.connect().execute("SELECT event FROM audit WHERE detail LIKE ?", (f"%{rid}%",))]
    assert events[:2] == ["ssh_access_requested", "ssh_access_approved"]

    # an admin's own request needs another admin
    reg = admin.get(url(env, "/api/clients/{cid}/access")).json()["keys"]
    rec = [k for k in reg if k["comment"] == "sam@laptop"][0]
    r = admin.post(url(env, "/api/clients/{cid}/access"), json={"action": "remove", "record": rec["id"],
                                                               "note": "Sam left"})
    rid2 = r.json()["request"]
    assert admin.post(url(env, f"/api/access-requests/{rid2}/approve"), json={}).status_code == 403
    r = admin2.post(url(env, f"/api/access-requests/{rid2}/approve"), json={})
    assert r.ok, r.text
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded"
    assert not [k for k in admin.get(url(env, "/api/clients/{cid}/access")).json()["keys"] if k["id"] == rec["id"]]


def test_reject_withdraw_and_checks_run_directly(env, people):
    op, admin = people["op"], env["admin"]
    key = ed25519_key("kim@laptop")
    body = {"action": "add", "key": key, "environments": ["HRDEV"], "note": "Kim"}
    rid = op.post(url(env, "/api/clients/{cid}/access"), json=body).json()["request"]
    assert admin.post(url(env, f"/api/access-requests/{rid}/reject"), json={"note": "use the shared account"}).ok
    v = [x for x in op.get(url(env, "/api/clients/{cid}/access-requests")).json()["requests"] if x["id"] == rid][0]
    assert v["status"] == "rejected" and v["decision_note"] == "use the shared account"
    rid = op.post(url(env, "/api/clients/{cid}/access"), json=body).json()["request"]
    assert op.post(url(env, f"/api/access-requests/{rid}/withdraw"), json={}).ok
    r = op.post(url(env, "/api/clients/{cid}/access"), json=dict(body, action="check"))
    assert r.ok and r.json()["job"]                                  # a check changes nothing: no approval
    drain(env)


def test_production_needs_an_end_date_and_expires(env, people):
    op, admin = people["op"], env["admin"]
    key = ed25519_key("temp@laptop")
    body = {"action": "add", "key": key, "environments": ["HRPRD"], "note": "Temp, go-live support"}
    r = op.post(url(env, "/api/clients/{cid}/access"), json=body)
    assert r.status_code == 400 and "end date" in r.json()["error"]
    past = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    assert "passed" in op.post(url(env, "/api/clients/{cid}/access"), json=dict(body, expires_on=past)).json()["error"]
    end = (dt.date.today() + dt.timedelta(days=3)).isoformat()
    rid = op.post(url(env, "/api/clients/{cid}/access"), json=dict(body, expires_on=end)).json()["request"]
    r = admin.post(url(env, f"/api/access-requests/{rid}/approve"), json={})
    assert r.status_code == 409 and r.json()["need_confirm"]           # production: typed confirmation
    r = admin.post(url(env, f"/api/access-requests/{rid}/approve"), json={"confirm": "HRPRD"})
    assert r.ok, r.text
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded"
    rec = [k for k in admin.get(url(env, "/api/clients/{cid}/access")).json()["keys"] if k["comment"] == "temp@laptop"][0]
    assert rec["expires_on"] == end
    with cp.app.app_context():
        cp.expire_access(today=dt.date.today() + dt.timedelta(days=2))     # not yet
        assert not cp.connect().execute("SELECT 1 FROM jobs WHERE created_by='pegasus (access ended)'").fetchone()
        cp.expire_access(today=dt.date.today() + dt.timedelta(days=4))
        cp.expire_access(today=dt.date.today() + dt.timedelta(days=4))     # no second job while one is queued
    jobs = cp.connect().execute("SELECT id FROM jobs WHERE created_by='pegasus (access ended)'").fetchall()
    assert len(jobs) == 1
    drain(env)
    assert wait_job(env, jobs[0]["id"])["status"] == "succeeded"
    assert not [k for k in admin.get(url(env, "/api/clients/{cid}/access")).json()["keys"] if k["comment"] == "temp@laptop"]


def test_with_jira_the_manager_approves_in_jira(env, people):
    """With the client's Jira change approval on, an SSH request raises a ticket; once someone other than the
    Pegasus account approves it in Jira, Pegasus makes the change by itself and reports back on the ticket."""
    from pegasus_cloud import jira as jiramod
    from test_patching import FakeJira, enable_jira
    real = jiramod.Jira
    jiramod.Jira = FakeJira
    try:
        enable_jira(env)
        op, admin = people["op"], env["admin"]
        body = {"action": "add", "key": ed25519_key("lee@laptop"), "account": "psadm2", "environments": ["HRDEV"],
                "note": "Lee, contractor, CHG-77", "expires_on": (dt.date.today() + dt.timedelta(days=10)).isoformat()}
        r = op.post(url(env, "/api/clients/{cid}/access"), json=body)
        assert r.ok and r.json()["pending"] and r.json()["jira_key"], r.text
        rid, key = r.json()["request"], r.json()["jira_key"]
        t = FakeJira.tickets[key]
        assert "Give SSH access" in t["summary"] and "Lee, contractor" in t["description"]
        assert "hrdevapp01" in t["description"] and "removes the key automatically" in t["description"]
        v = [x for x in admin.get(url(env, "/api/clients/{cid}/access-requests")).json()["requests"] if x["id"] == rid][0]
        assert v["jira_key"] == key and not v["can_decide"]          # decided in Jira, not with a button here
        assert admin.post(url(env, f"/api/access-requests/{rid}/approve"), json={}).status_code == 409
        # still waiting: nothing runs
        assert op.post(url(env, "/api/clients/{cid}/access-requests/check"), json={}).ok
        assert not cp.connect().execute("SELECT 1 FROM jobs WHERE kind='access.add' AND status='queued'").fetchone()
        # the manager approves in Jira
        t.update(state="approved", approver="Arvind Rajan")
        reqs = op.post(url(env, "/api/clients/{cid}/access-requests/check"), json={}).json()["requests"]
        v = [x for x in reqs if x["id"] == rid][0]
        assert v["status"] == "approved" and "Arvind Rajan" in v["decided_by"] and v["job"]
        drain(env)
        j = wait_job(env, v["job"])
        assert j["status"] == "succeeded" and "approved in Jira by Arvind Rajan" in j["created_by"]
        time.sleep(0.3)                                               # Jira comments are posted in the background
        said = [c for k, c in FakeJira.comments if k == key]
        assert any("started the change" in c for c in said) and any("SUCCEEDED" in c for c in said)
        rec = [k for k in admin.get(url(env, "/api/clients/{cid}/access")).json()["keys"] if k["comment"] == "lee@laptop"]
        assert rec and rec[0]["expires_on"] == body["expires_on"]
        # rejected in Jira: the request closes and nothing runs
        r = op.post(url(env, "/api/clients/{cid}/access"), json=dict(body, key=ed25519_key("max@laptop")))
        rid2, key2 = r.json()["request"], r.json()["jira_key"]
        FakeJira.tickets[key2]["state"] = "rejected"
        with cp.app.app_context():
            cp.check_access_jira(force=True)
        v = [x for x in admin.get(url(env, "/api/clients/{cid}/access-requests")).json()["requests"] if x["id"] == rid2][0]
        assert v["status"] == "rejected" and not v["job"]
    finally:
        cp.connect().execute("DELETE FROM access_keys WHERE comment='lee@laptop'")    # keep later tests' register clean
        env["admin"].put(url(env, "/api/clients/{cid}/jira"), json={"enabled": False})
        jiramod.Jira = real
