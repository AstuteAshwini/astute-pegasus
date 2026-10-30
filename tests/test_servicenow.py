"""ServiceNow change approval, against a simulated ServiceNow Table API (the HTTP layer is faked; everything else
is real: the control plane, the approval gate, the connector and its jobs)."""
import json
import re
import time
from urllib.parse import unquote

import pytest

from conftest import drain, wait_job
from pegasus_cloud import app as cp, servicenow as sn
from test_patching import outstanding_again, url, patching  # noqa: F401  (shared helpers)
from test_patching import fake_oracle  # noqa: F401  (fixture: Oracle replaced with fakes)


class Resp:
    def __init__(self, code, body):
        self.status_code, self._body, self.reason = code, body, "x"
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeSN:
    """change_request, sysapproval_approver, sys_user and sys_user_group tables in memory."""
    changes, approvals, n = {}, [], 0
    users = {"svc_pegasus": "u_bot", "cm.jones": "u_jones"}
    calls = []

    def __init__(self):
        self.headers, self.auth = {}, None

    def request(self, method, u, json=None, params=None, timeout=None):
        FakeSN.calls.append((method, u, json, params))
        assert self.auth == ("svc_pegasus", "sn-secret"), "signs in as the integration user"
        path = u.split("/api/now/", 1)[1]
        q = unquote((params or {}).get("sysparm_query", ""))
        if path == "table/sys_user":
            name = q.split("=", 1)[1]
            return Resp(200, {"result": [{"sys_id": FakeSN.users[name], "name": name}] if name in FakeSN.users else []})
        if path == "table/sys_user_group":
            return Resp(200, {"result": [{"sys_id": "g_ps"}] if q == "name=PeopleSoft Admins" else []})
        if path == "table/change_request" and method == "POST":
            FakeSN.n += 1
            num, sid = f"CHG00300{FakeSN.n:02d}", f"sys{FakeSN.n}"
            FakeSN.changes[sid] = dict(json, number=num, sys_id=sid, state="-5", approval="not requested",
                                       opened_by="u_bot", work_notes=[])
            return Resp(201, {"result": {"number": num, "sys_id": sid}})
        if path == "table/change_request" and method == "GET":
            if not q:
                return Resp(200, {"result": []})
            num = q.split("=", 1)[1]
            rec = next((c for c in FakeSN.changes.values() if c["number"] == num), None)
            names = {v: k.title() for k, v in sn.STATES.items()}
            return Resp(200, {"result": [] if not rec else [{
                "sys_id": {"value": rec["sys_id"]}, "number": {"value": num},
                "state": {"value": rec["state"], "display_value": names[rec["state"]]},
                "approval": {"value": rec["approval"]}, "opened_by": {"value": rec["opened_by"]}}]})
        m = re.match(r"table/change_request/(\w+)$", path)
        if m and method == "PATCH":
            rec = FakeSN.changes[m.group(1)]
            if "work_notes" in json:
                rec["work_notes"].append(json["work_notes"])
            if "state" in json:
                rec["state"] = json["state"]
                if json["state"] == "-4":
                    rec["approval"] = "requested"
            return Resp(200, {"result": {}})
        if path == "table/sysapproval_approver":
            sid = re.search(r"sysapproval=(\w+)", q).group(1)
            return Resp(200, {"result": [{"approver": {"value": a, "display_value": a.replace("u_", "").title()},
                                          "state": {"value": "approved"}} for s, a in FakeSN.approvals if s == sid]})
        return Resp(404, {"error": {"message": f"no route {method} {path}"}})


@pytest.fixture()
def snow(env, monkeypatch):
    monkeypatch.setattr(sn.requests, "Session", FakeSN)
    db = cp.connect()                     # tickets other tests left open in Jira would block switching systems
    db.execute("UPDATE change_requests SET status='withdrawn' WHERE status IN ('pending','approved','applying')")
    db.execute("UPDATE access_requests SET status='withdrawn' WHERE status='pending'")
    FakeSN.changes.clear(), FakeSN.approvals.clear(), FakeSN.calls.clear()
    yield FakeSN
    env["admin"].put(url(env, "/api/clients/{cid}/servicenow"), json={"enabled": False})
    env["admin"].put(url(env, "/api/clients/{cid}/ticketing"), json={"system": "jira"})


def approve(change, who="u_jones"):
    change.update(approval="approved", state="-2")
    FakeSN.approvals.append((change["sys_id"], who))


def test_servicenow_change_approval_end_to_end(env, snow):
    base = url(env, "/api/clients/{cid}")
    assert env["admin"].put(base + "/ticketing", json={"system": "remedy"}).status_code == 400
    assert env["admin"].put(base + "/ticketing", json={"system": "servicenow"}).json()["system"] == "servicenow"
    r = env["admin"].put(base + "/servicenow", json={"enabled": True, "url": "https://astute.service-now.com",
                                                     "user": "svc_pegasus", "assignment_group": "PeopleSoft Admins",
                                                     "start_transition": "Teleport"})
    assert r.status_code == 400 and "isn't a change request state" in r.json()["error"]
    r = env["admin"].put(base + "/servicenow", json={"enabled": True, "url": "https://astute.service-now.com",
                                                     "user": "svc_pegasus", "assignment_group": "PeopleSoft Admins",
                                                     "token": "sn-secret"})
    assert r.ok, r.text
    t = env["admin"].post(base + "/servicenow/test", json={}).json()
    assert t["ok"] and t["user"] == "svc_pegasus"
    outstanding_again(env)
    v = patching(env)
    assert v["approval"]["required"] and v["approval"]["system"] == "ServiceNow"
    r = env["admin"].post(base + "/change-requests", json={
        "environment": "HRDEV", "scope": "all", "notes": "November CPU",
        "window": {"start": "2026-11-07T22:00", "end": "2026-11-08T07:00", "tz": "America/Los_Angeles"}})
    assert r.ok, r.text
    cr = r.json()["request"]
    ch = next(iter(snow.changes.values()))
    assert cr["jira_key"] == ch["number"] and "service-now.com/change_request.do" in cr["url"]
    assert ch["assignment_group"] == "g_ps" and ch["type"] == "normal" and ch["state"] == "-4"     # sent to Assess
    assert ch["start_date"] == "2026-11-08 06:00:00" and ch["end_date"] == "2026-11-08 15:00:00"   # UTC
    assert "WHAT WILL CHANGE" in ch["description"] and "h3." not in ch["description"] and "||" not in ch["description"]
    apply = lambda: env["admin"].post(base + "/patching/apply", json={"environment": "HRDEV", "scope": "all",
                                                                       "change_request": cr["id"]})
    assert apply().status_code == 409                                   # not approved yet
    approve(ch, who="u_bot")                                            # approved by the account Pegasus uses
    r = apply()
    assert r.status_code == 409 and "someone else" in r.json()["error"]
    FakeSN.approvals.clear()
    approve(ch)
    r = apply()
    assert r.ok, r.text
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded"
    for _ in range(60):
        if any("SUCCEEDED" in w for w in ch["work_notes"]):
            break
        time.sleep(0.05)
    assert any("queued this change" in w and "Approved by Jones" in w for w in ch["work_notes"])
    assert any("SUCCEEDED" in w and "{noformat}" not in w for w in ch["work_notes"])
    assert ch["state"] == "0"                                           # moved to Review when it succeeded


def test_switching_systems_waits_for_open_tickets(env, snow):
    base = url(env, "/api/clients/{cid}")
    env["admin"].put(base + "/ticketing", json={"system": "servicenow"})
    env["admin"].put(base + "/servicenow", json={"enabled": True, "url": "https://astute.service-now.com",
                                                 "user": "svc_pegasus", "token": "sn-secret"})
    outstanding_again(env)
    assert env["admin"].post(base + "/change-requests", json={"environment": "HRDEV", "scope": "all"}).ok
    r = env["admin"].put(base + "/ticketing", json={"system": "jira"})
    assert r.status_code == 409 and "open tickets in ServiceNow" in r.json()["error"]
    cp.connect().execute("UPDATE change_requests SET status='withdrawn' WHERE status IN ('pending','approved')")


def test_rejected_and_wiki_text():
    cfg = sn.config({})
    rec = {"state": {"value": "4", "display_value": "Canceled"}, "approval": {"value": "requested"}}
    assert sn.status(cfg, rec)[0] == "rejected"
    rec = {"state": {"value": "-4", "display_value": "Assess"}, "approval": {"value": "rejected"}}
    assert sn.status(cfg, rec)[0] == "rejected"
    rec = {"state": {"value": "-4", "display_value": "Assess"}, "approval": {"value": "requested"}}
    assert sn.status(cfg, rec)[0] == "pending"
    text = sn.wiki_to_text("h3. Security fixes\n||Component||Update||\n|JDK|21.0.8|\n"
                           "* [CVE-2026-1|https://www.cve.org/CVERecord?id=CVE-2026-1] CVSS 9.8\n"
                           "{panel}Pegasus applies exactly this plan.{panel}\nAmerica/Los\\_Angeles")
    assert "SECURITY FIXES" in text and "Component | Update" in text and "JDK | 21.0.8" in text
    assert "CVE-2026-1 (https://www.cve.org/CVERecord?id=CVE-2026-1)" in text
    assert "Pegasus applies exactly this plan." in text and "Los_Angeles" in text and "{panel}" not in text
