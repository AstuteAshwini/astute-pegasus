"""Patching end to end: read levels, look up Oracle's latest, download and stage, Jira approval, apply, and SSH keys.

Oracle (Java releases, Oracle Support) and Jira are replaced with in-memory fakes; everything else is real: the
control plane over HTTP, signed jobs, the connector's validation, and its scripts run against simulated servers."""
import base64
import os
import time
from pathlib import Path

import pytest

from conftest import drain, wait_job
from pegasus_cloud import app as cp, jira as jiramod
from pegasus_connector import oracle, protocol
from pegasus_connector.operations import parse_levels

CATALOG = {
    "java": {"21": {"version": "21.0.8", "date": "2025-07-15"}},
    "java_dates": {"21.0.5": "2024-10-15"},
    "oracle": {"weblogic": {"stamp": "251015", "psu_patch": "38000001", "spb_patch": "38000002",
                            "released": "2025-10-21", "released_by_stamp": {"250705": "2025-07-15",
                                                                            "251015": "2025-10-21"}}},
}


@pytest.fixture(scope="module", autouse=True)
def fake_oracle():
    real = (oracle.catalog, oracle.download_patch, oracle.download_jdk)

    def catalog(config_path, cache_dir, majors, versions, refresh=False, log=print):
        assert majors == ["21"] and "21.0.5" in versions
        return dict(CATALOG, checked="2025-10-22T00:00:00+00:00")

    def download_patch(config_path, cache_dir, patch, platform, filt, log, mos=None):
        d = Path(cache_dir) / patch
        d.mkdir(parents=True, exist_ok=True)
        (d / f"p{patch}_141200_Generic.zip").write_bytes(b"zip " + patch.encode())
        log(f"Patch {patch}: downloaded\n")
        return sorted(d.iterdir()), mos

    def download_jdk(config_path, cache_dir, version, log):
        d = Path(cache_dir) / f"jdk-{version}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"jdk-{version}_linux-x64_bin.tar.gz").write_bytes(b"tar " + version.encode())
        return sorted(d.iterdir())

    oracle.catalog, oracle.download_patch, oracle.download_jdk = catalog, download_patch, download_jdk
    yield
    oracle.catalog, oracle.download_patch, oracle.download_jdk = real


class FakeJira:
    """Stands in for jira.Jira: tickets live in a dict; tests set their status and approver."""
    tickets, comments, transitions, n = {}, [], [], 0

    def __init__(self, cfg, token):
        assert token == "jira-secret-token"
        self.cfg = cfg

    def browse(self, key):
        return f"https://example.atlassian.net/browse/{key}"

    def create(self, summary, description, window=None):
        FakeJira.n += 1
        key = f"CHG-{FakeJira.n}"
        FakeJira.tickets[key] = {"summary": summary, "description": description, "state": "pending", "approver": ""}
        return key

    def transition(self, key, name):
        if name:
            FakeJira.transitions.append((key, name))

    def approval_state(self, key):
        t = FakeJira.tickets[key]
        return t["state"], {"approved": "Approved", "rejected": "Declined"}.get(t["state"], "Waiting for approval"), \
            t["approver"]

    def comment(self, key, text):
        FakeJira.comments.append((key, text))

    def myself(self):
        return {"displayName": "Pegasus bot"}

    def project(self):
        return {"name": "Change management", "issueTypes": [{"name": "Change"}]}

    def create_meta(self):
        return {"change type": {"name": "Change type", "fieldId": "customfield_1", "schema": {"type": "option"},
                                "allowedValues": [{"value": "Normal"}]}}

    def change_fields(self, meta, window):
        return {"customfield_1": {"value": "Normal"}}


@pytest.fixture(scope="module")
def jira(env):
    real = jiramod.Jira
    jiramod.Jira = FakeJira
    yield FakeJira
    jiramod.Jira = real


def url(e, path):
    return e["url"] + path.replace("{cid}", e["cid"])


def patching(e, refresh=False):
    r = e["admin"].get(url(e, "/api/clients/{cid}/patching"), params={"environment": "HRDEV", "refresh": refresh or ""})
    assert r.ok, r.text
    return r.json()


def item(view, host, comp):
    h = next(h for h in view["hosts"] if h["host"] == host)
    return next(i for i in h["items"] if i["component"] == comp)


def test_parse_levels_reads_owners_and_patches():
    from fakes import levels_output
    lv = parse_levels("noise from .bashrc\n" + levels_output())
    assert lv["jdk"] == {"version": "21.0.5", "home": "/u01/pt/jdk"}
    assert lv["weblogic"]["patches"][0]["id"] == "37000001"
    assert lv["owners"]["/u01/pt/bea"] == "psadm1"


def test_check_levels_then_catalog_marks_updates_needed(env):
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/check"), json={"environment": "HRDEV"})
    assert r.ok, r.text
    assert drain(env) == 2                          # the levels job, then the follow-up Oracle lookup
    j = wait_job(env, r.json()["job"])
    assert j["status"] == "succeeded" and j["followup"]
    assert wait_job(env, j["followup"])["status"] == "succeeded"
    v = patching(env)
    assert [h["host"] for h in v["hosts"]] == ["hrdevweb01", "hrdevapp01"]
    jdk, wls = item(v, "hrdevapp01", "jdk"), item(v, "hrdevapp01", "weblogic")
    assert jdk["status"] == "needed" and jdk["key"] == "21.0.8|java|" and "Oct2024 CPU" in jdk["installed"]
    assert wls["status"] == "needed" and wls["key"] == "38000002|2000P|" and "Jul2025" in wls["installed"]
    assert v["outstanding"] == 2 and not v["approval"]["required"]


def test_stage_downloads_once_and_copies_to_every_server(env):
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/stage"), json={"environment": "HRDEV", "all": True})
    assert r.ok, r.text
    drain(env)
    j = wait_job(env, r.json()["job"])
    assert j["status"] == "succeeded", j["text"]
    assert "staged and verified" in j["text"]
    staged = [k for k in env["fake"].files if k[1].startswith("/u01/app/oracle/staging/cpu/")]
    assert len(staged) == 4                         # 2 updates x 2 servers
    v = patching(env)
    assert item(v, "hrdevweb01", "weblogic")["staged"]["dir"] == "/u01/app/oracle/staging/cpu/p38000002"
    # a second run finds the files already there and skips the copy
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/stage"), json={"environment": "HRDEV", "all": True})
    drain(env)
    assert "already staged" in wait_job(env, r.json()["job"])["text"]


def enable_jira(env):
    r = env["admin"].put(url(env, "/api/clients/{cid}/jira"), json={
        "enabled": True, "url": "https://example.atlassian.net", "user": "bot@beastute.com", "project": "CHG",
        "token": "jira-secret-token", "require": "all"})
    assert r.ok, r.text
    raw = cp.connect().execute("SELECT value FROM settings WHERE key='jira_token'").fetchone()[0]
    assert "jira-secret-token" not in raw          # stored encrypted


def test_apply_needs_an_approved_ticket_from_someone_else(env, jira):
    enable_jira(env)
    v = patching(env)
    assert v["approval"]["required"]
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"), json={"environment": "HRDEV", "scope": "all"})
    assert r.status_code == 409 and r.json()["need_approval"]
    r = env["admin"].post(url(env, "/api/clients/{cid}/change-requests"),
                          json={"environment": "HRDEV", "scope": "all", "notes": "October CPU"})
    assert r.ok, r.text
    cr = r.json()["request"]
    ticket = jira.tickets[cr["jira_key"]]
    assert "hrdevweb01" in ticket["description"] and "WebLogic" in ticket["summary"]
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                          json={"environment": "HRDEV", "scope": "all", "change_request": cr["id"]})
    assert r.status_code == 409 and "isn't approved yet" in r.json()["error"]
    ticket.update(state="self_approved")
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                          json={"environment": "HRDEV", "scope": "all", "change_request": cr["id"]})
    assert r.status_code == 409 and "someone else" in r.json()["error"]
    ticket.update(state="approved", approver="Change Manager")
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                          json={"environment": "HRDEV", "scope": "all", "change_request": cr["id"]})
    assert r.ok, r.text
    jid = r.json()["job"]
    # the approval is used up: a second apply with the same ticket is refused
    r2 = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                           json={"environment": "HRDEV", "scope": "all", "change_request": cr["id"]})
    assert r2.status_code == 409
    env["fake"].calls.clear()
    drain(env)
    j = wait_job(env, jid)
    assert j["status"] == "succeeded", j["text"]
    ops = [s["op"] for s in j["steps"]]
    assert ops.index("domain.stop") < ops.index("host.idle") < ops.index("patch.apply") < ops.index("domain.start")
    labels = [s["label"] for s in j["steps"] if s["op"] == "patch.apply"]
    assert labels[0].startswith("Apply JDK") and labels[-1].startswith("Apply WebLogic")   # JDK first
    v = patching(env)
    assert item(v, "hrdevapp01", "jdk")["status"] == "ok" and item(v, "hrdevapp01", "weblogic")["status"] == "ok"
    for _ in range(50):
        if any("SUCCEEDED" in c for _, c in jira.comments):
            break
        time.sleep(0.05)
    assert any(k == cr["jira_key"] and "SUCCEEDED" in c for k, c in jira.comments)
    crs = {c["jira_key"]: c for c in v["change_requests"]}
    assert crs[cr["jira_key"]]["status"] == "applied"


def test_failed_apply_still_starts_domains(env, jira):
    for k in [k for k in env["fake"].applied]:
        env["fake"].applied.discard(k)
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/check"), json={"environment": "HRDEV"})
    drain(env)
    assert patching(env)["outstanding"] == 2
    r = env["admin"].post(url(env, "/api/clients/{cid}/change-requests"), json={"environment": "HRDEV", "scope": "all"})
    cr = r.json()["request"]
    jira.tickets[cr["jira_key"]].update(state="approved", approver="Change Manager")
    env["fake"].fail_apply = True
    try:
        r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                              json={"environment": "HRDEV", "scope": "all", "change_request": cr["id"]})
        assert r.ok, r.text
        env["fake"].calls.clear()
        drain(env)
        j = wait_job(env, r.json()["job"])
    finally:
        env["fake"].fail_apply = False
    assert j["status"] == "failed"
    applies = [s for s in j["steps"] if s["op"] == "patch.apply"]
    assert applies[0]["done"] and not any(s["done"] for s in applies[1:])      # stopped at the first failure
    starts = [s for s in j["steps"] if s["op"] == "domain.start"]
    assert starts and all(s["done"] for s in starts)                            # domains started again anyway
    assert patching(env)["change_requests"][0]["status"] == "failed"


def test_plan_change_after_approval_needs_a_new_ticket(env, jira):
    env["fake"].applied.add(("hrdevweb01", "jdk"))                       # web is already on the new JDK
    env["admin"].post(url(env, "/api/clients/{cid}/patching/check"), json={"environment": "HRDEV"})
    drain(env)
    assert item(patching(env), "hrdevweb01", "jdk")["status"] == "ok"
    r = env["admin"].post(url(env, "/api/clients/{cid}/change-requests"),
                          json={"environment": "HRDEV", "scope": "jdk~21.0.8|java|"})
    assert r.ok, r.text
    cr = r.json()["request"]
    assert cr["hosts"] == ["hrdevapp01"]
    jira.tickets[cr["jira_key"]].update(state="approved", approver="Change Manager")
    env["fake"].applied.discard(("hrdevweb01", "jdk"))                   # web needs it again: the plan grows
    env["admin"].post(url(env, "/api/clients/{cid}/patching/check"), json={"environment": "HRDEV"})
    drain(env)
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                          json={"environment": "HRDEV", "scope": "jdk~21.0.8|java|", "change_request": cr["id"]})
    assert r.status_code == 409 and "plan has changed" in r.json()["error"]
    cp.connect().execute("DELETE FROM staged WHERE host_key='10.0.1.11'")
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                          json={"environment": "HRDEV", "scope": "jdk~21.0.8|java|", "change_request": cr["id"]})
    assert r.status_code == 409 and "Download these first" in r.json()["error"]


def test_connector_rejects_unsafe_apply_even_when_signed(env):
    from test_end_to_end import TARGET, handle_and_capture, signed
    base = {"op": "patch.apply", "target": TARGET, "component": "weblogic", "owner": "psadm1",
            "home": "/u01/pt/bea", "staged": {"dir": "/u01/app/oracle/staging/cpu/p1", "files": ["p1.zip"]}}
    for bad in ({"owner": "root"}, {"home": "/u01"}, {"home": "/u01/pt/bea; rm -rf /"},
                {"staged": {"dir": "/tmp/x", "files": ["../../etc/passwd"]}}, {"component": "kernel"}):
        job, sig = signed(env, [dict(base, **bad)])
        assert handle_and_capture(env, job, sig)["status"] == "rejected", bad
    job, sig = signed(env, [{"op": "patch.download", "keys": ["1234; curl evil|226P|"]}])
    assert handle_and_capture(env, job, sig)["status"] == "rejected"


def ed25519_key(comment="jane@laptop"):
    blob = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + os.urandom(32)
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


def test_ssh_access_add_check_remove(env):
    """Without the approval step (a client's admins can turn it off), changes run straight away."""
    key = ed25519_key()
    assert env["admin"].put(url(env, "/api/clients/{cid}/access-settings"), json={"approval": False}).ok
    r = env["admin"].post(url(env, "/api/clients/{cid}/access"),
                          json={"action": "add", "key": key, "account": "psadm2", "environments": ["HRDEV"],
                                "note": "Jane, DBA"})
    assert r.ok, r.text
    drain(env)
    j = wait_job(env, r.json()["job"])
    assert j["status"] == "succeeded" and j["text"].count("added") == 2
    reg = env["admin"].get(url(env, "/api/clients/{cid}/access")).json()["keys"]
    assert len(reg) == 1 and reg[0]["servers"] == ["hrdevapp01", "hrdevweb01"] and reg[0]["account"] == "psadm2"
    r = env["admin"].post(url(env, "/api/clients/{cid}/access"), json={"action": "remove", "record": reg[0]["id"]})
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded"
    assert env["admin"].get(url(env, "/api/clients/{cid}/access")).json()["keys"] == []
    r = env["admin"].post(url(env, "/api/clients/{cid}/access"),
                          json={"action": "add", "key": key, "account": "root", "environments": ["HRDEV"]})
    assert r.status_code == 400
    r = env["admin"].post(url(env, "/api/clients/{cid}/access"),
                          json={"action": "add", "key": key, "environments": ["HRPRD"]})
    assert r.status_code == 409 and r.json()["need_confirm"]
    assert env["admin"].put(url(env, "/api/clients/{cid}/access-settings"), json={"approval": True}).ok


def test_patch_settings_round_trip(env):
    base = url(env, "/api/clients/{cid}/patch-settings")
    assert env["admin"].get(base).json()["staging_root"] == "/u01/app/oracle/staging/cpu"
    r = env["admin"].put(base, json={"targets": [{"component": "tuxedo", "applies_to": "12.2.2", "target": "RP110",
                                                  "patch_number": "35000001"}]})
    assert r.ok, r.text
    assert env["admin"].put(base, json={"staging_root": "/u01"}).status_code == 400          # too general
    assert env["admin"].put(base, json={"targets": [{"component": "jdk", "target": "21; rm"}]}).status_code == 400
    assert env["admin"].get(base).json()["targets"][0]["target"] == "RP110"
    env["admin"].put(base, json={"targets": []})


def test_protocol_version_unchanged():
    assert protocol.PROTOCOL_VERSION == 1


def test_patch_watch_checks_and_stages_nonprod_only(env):
    """Every day Pegasus re-reads levels and Oracle's latest by itself, then stages what's outstanding where allowed
    (non-production by default). Nothing is installed."""
    cid = env["cid"]
    view = env["admin"].get(url(env, "/api/clients/{cid}/patch-watch")).json()
    assert view["settings"] == {"check": True, "stage": "nonprod"}
    c = cp.connect()
    c.execute("DELETE FROM staged WHERE client_id=?", (cid,))
    c.execute("DELETE FROM settings WHERE client_id=? AND key='patch_watch_state'", (cid,))
    with cp.app.app_context():
        cp.run_patch_watch()
    st = env["admin"].get(url(env, "/api/clients/{cid}/patch-watch")).json()
    assert st["phase"] == "checking"
    queued = [r["environment"] for r in c.execute("SELECT environment FROM jobs WHERE client_id=? AND kind='levels' "
                                                  "AND status='queued' AND created_by='pegasus (patch watch)'", (cid,))]
    assert sorted(queued) == ["HRDEV", "HRPRD"]
    drain(env)                                     # levels, then the catalog lookup that follows
    with cp.app.app_context():
        cp.run_patch_watch()
    st = env["admin"].get(url(env, "/api/clients/{cid}/patch-watch")).json()
    assert st["phase"] == "idle" and st["outstanding"].get("HRDEV")
    stage = c.execute("SELECT environment, created_by FROM jobs WHERE client_id=? AND kind='stage' AND status='queued'",
                      (cid,)).fetchall()
    assert [(r["environment"], r["created_by"]) for r in stage] == [("HRDEV", "pegasus (patch watch)")]
    drain(env)
    assert all(i["staged"] for h in patching(env)["hosts"] for i in h["items"] if i["status"] == "needed")
    # not due again until the interval passes; admins can turn staging off
    with cp.app.app_context():
        cp.run_patch_watch()
    assert env["admin"].get(url(env, "/api/clients/{cid}/patch-watch")).json()["phase"] == "idle"
    r = env["admin"].put(url(env, "/api/clients/{cid}/patch-watch"), json={"stage": "off"})
    assert r.ok and r.json()["settings"]["stage"] == "off"
    assert env["admin"].put(url(env, "/api/clients/{cid}/patch-watch"), json={"stage": "sometimes"}).status_code == 400
    env["admin"].put(url(env, "/api/clients/{cid}/patch-watch"), json={"stage": "nonprod"})



def test_os_updates_in_one_window_with_reboot_when_needed(env):
    """yum update is part of the same maintenance window: stop everything, OS updates, middleware patches, reboot
    only where Linux says so, then start everything once."""
    fake = env["fake"]
    env["admin"].put(url(env, "/api/clients/{cid}/jira"), json={"enabled": False})
    fake.os_updates, fake.os_kernel = True, True
    fake.applied = {x for x in fake.applied if x[1] != "os"}
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/check"), json={"environment": "HRDEV"})
    drain(env)
    wait_job(env, r.json()["job"])
    os_item = item(patching(env), "hrdevapp01", "os")
    assert os_item["status"] == "needed" and os_item["key"] == "os|yum|3" and os_item["kernel_update"]
    assert os_item["security"]["critical"] == 1 and "Oracle Linux Server 8.10" in os_item["installed"]
    assert "a new kernel (needs a reboot)" in os_item["detail"]
    # downloading ahead of the window: yum update --downloadonly on each server
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/stage"),
                          json={"environment": "HRDEV", "items": [{"host_key": h["host_key"], "key": "os|yum|3"}
                                                                  for h in patching(env)["hosts"]]})
    assert r.ok, r.text
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded" and len(fake.os_downloaded) == 2
    assert item(patching(env), "hrdevapp01", "os")["staged"]
    # apply everything outstanding in one window
    fake.calls.clear()
    fake.rebooted = []
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"), json={"environment": "HRDEV", "scope": "all"})
    assert r.ok, r.text
    jid = r.json()["job"]
    steps = [s["op"] for s in cp.connect().execute("SELECT params FROM jobs WHERE id=?", (jid,)).fetchone()
             and __import__("json").loads(cp.connect().execute("SELECT params FROM jobs WHERE id=?", (jid,))
                                          .fetchone()["params"])["steps"]]
    first_start = steps.index("domain.start")
    assert steps.index("os.update") > max(i for i, op in enumerate(steps) if op == "domain.stop")
    assert all(i < first_start for i, op in enumerate(steps) if op in ("os.update", "patch.apply", "host.reboot"))
    assert max(i for i, op in enumerate(steps) if op in ("os.update", "patch.apply")) < steps.index("host.reboot")
    assert steps.count("domain.start") == 3                     # everything is started once, at the end
    drain(env)
    j = wait_job(env, jid)
    assert j["status"] == "succeeded", j["text"][-800:]
    assert sorted(fake.rebooted) == ["hrdevapp01", "hrdevweb01"] and "back up after the reboot" in j["text"]
    v = patching(env)
    assert item(v, "hrdevapp01", "os")["status"] == "ok"
    # without a reboot: the job doesn't reboot, and the reboot shows as pending
    fake.applied.discard(("hrdevapp01", "os"))
    fake.applied.discard(("hrdevweb01", "os"))
    fake.rebooted = []
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/check"), json={"environment": "HRDEV"})
    drain(env)
    wait_job(env, r.json()["job"])
    r = env["admin"].post(url(env, "/api/clients/{cid}/patching/apply"),
                          json={"environment": "HRDEV", "scope": "os~os|yum|3", "reboot": False})
    assert r.ok, r.text
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded" and fake.rebooted == []
    after = item(patching(env), "hrdevapp01", "os")
    assert after["status"] == "ok" and after["reboot_pending"] and "reboot is pending" in after["detail"]
    fake.os_updates = False
    fake.reboot_needed.clear()
