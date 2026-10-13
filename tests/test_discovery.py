"""Add servers by IP: the connector scans them for PeopleSoft domains, unknown host keys are trusted first."""
from conftest import drain, wait_job


def scan(env, targets, users=""):
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/discover", json={"targets": targets, "users": users})
    assert r.ok, r.text
    drain(env)
    j = wait_job(env, r.json()["job"])
    return j, env["admin"].get(env["url"] + f"/api/jobs/{r.json()['job']}/discovery").json()["results"]


def test_unknown_server_needs_trust_then_scans(env):
    j, res = scan(env, "10.0.5.40")
    assert res[0]["needs_trust"] and res[0]["fingerprint"] == env["fake"].host_fp
    assert not any("INNER=" in c for h, c in env["fake"].calls if h == "10.0.5.40")     # nothing ran before trust
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/trust-host",
                          json={"target": "10.0.5.40", "fingerprint": "SHA256:" + "B" * 43})
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "failed"                          # wrong fingerprint
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/trust-host",
                          json={"target": "10.0.5.40", "fingerprint": res[0]["fingerprint"]})
    drain(env)
    assert wait_job(env, r.json()["job"])["status"] == "succeeded"
    j, res = scan(env, "10.0.5.40")
    rows = res[0]["rows"]
    assert res[0]["host"] == "fsdev01"
    assert [(x["role"], x["domain"], x["use"]) for x in rows] == [
        ("web", "peoplesoft", True), ("app", "FSDEV", True), ("app", "FSCOPY", False), ("prcs", "PRCSDOM", True)]
    assert rows[0]["os_user"] == "psadm2" and rows[0]["env_script"] == "/u01/pt/ps_home8.62.12/psconfig.sh"


def test_add_found_domains_keeps_other_environments(env):
    _, res = scan(env, "10.0.5.40")
    rows = [x for x in res[0]["rows"] if x["use"]]
    base = env["url"] + f"/api/clients/{env['cid']}"
    r = env["admin"].post(base + "/inventory/add", json={"environment": "FSDEV", "tier": "DEV", "rows": rows})
    assert r.ok and r.json()["added"] == 3, r.text
    r = env["admin"].post(base + "/inventory/add", json={"environment": "FSDEV", "tier": "DEV", "rows": rows})
    assert r.json() == {"ok": True, "added": 0, "updated": 3}                          # no duplicates
    envs = {e["name"]: e for e in env["admin"].get(base).json()["environments"]}
    assert {"HRDEV", "HRPRD", "FSDEV"} <= set(envs) and len(envs["FSDEV"]["servers"]) == 3
    bad = dict(rows[0], domain="X; rm -rf /")
    assert env["admin"].post(base + "/inventory/add", json={"environment": "FSDEV", "rows": [bad]}).status_code == 400
    assert env["admin"].delete(base + "/environments/FSDEV").ok
    assert "FSDEV" not in {e["name"] for e in env["admin"].get(base).json()["environments"]}


def test_scan_input_is_checked(env):
    base = env["url"] + f"/api/clients/{env['cid']}/discover"
    assert env["admin"].post(base, json={"targets": "10.0.0.1 -oProxyCommand=x"}).status_code == 400
    assert env["admin"].post(base, json={"targets": "10.0.0.1", "users": "root"}).status_code == 400
    assert env["admin"].post(base, json={"targets": ""}).status_code == 400
