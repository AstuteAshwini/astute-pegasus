"""Clear cache and restart: the order of the steps, that domains always come back, refusing connectors too old for
it, and production confirmation."""
from conftest import drain
from pegasus_cloud import app as cp
from test_end_to_end import run_job


def test_plan_stops_clears_then_always_starts():
    servers = [{"host": "w", "ip": "1", "role": "web", "domain": "peoplesoft", "os_user": "", "env_script": "",
                "ssh_port": 22},
               {"host": "a", "ip": "2", "role": "app", "domain": "HRDEV", "os_user": "", "env_script": "", "ssh_port": 22},
               {"host": "a", "ip": "2", "role": "prcs", "domain": "PRCSDOM", "os_user": "", "env_script": "",
                "ssh_port": 22}]
    steps, stop_on_failure = cp.plan_steps(servers, "clearcache")
    assert stop_on_failure
    assert [(s["op"].split(".")[1], s["target"]["role"]) for s in steps] == [
        ("stop", "web"), ("stop", "prcs"), ("stop", "app"),
        ("clearcache", "web"), ("clearcache", "prcs"), ("clearcache", "app"),
        ("start", "app"), ("start", "prcs"), ("start", "web")]
    assert all(s.get("always") for s in steps if s["op"] == "domain.start")
    assert not any(s.get("always") for s in steps if s["op"] != "domain.start")


def test_clear_cache_and_restart_an_environment(env):
    env["fake"].cleared = []
    j = run_job(env, {"environment": "HRDEV", "action": "clearcache"})
    assert j["status"] == "succeeded" and j["title"] == "Clear cache and restart HRDEV"
    assert sorted(r for _, r, _ in env["fake"].cleared) == ["app", "prcs", "web"]
    assert "CC|cleared|" in j["text"]
    s = run_job(env, {"environment": "HRDEV", "action": "status"})
    assert all(x["state"] == "running" for x in s["steps"])


def test_one_domain_only(env):
    env["fake"].cleared = []
    j = run_job(env, {"environment": "HRDEV", "action": "clearcache", "host": "10.0.1.11", "role": "web",
                      "domain": "peoplesoft"})
    assert j["status"] == "succeeded" and env["fake"].cleared == [("hrdevweb01", "web", "peoplesoft")]


def test_domains_come_back_even_if_a_stop_fails(env):
    fake = env["fake"]
    fake.cleared = []
    fake.calls.clear()
    real = fake.run

    def stubborn(target, command, *a, **kw):            # the web server refuses to stop
        if target["role"] == "web" and "shutdown" in command:
            fake.calls.append((target["host"], command))
            kw.get("on_output", lambda _: None)("Error: shutdown timed out\n")
            return 1
        return real(target, command, *a, **kw)
    fake.run = stubborn
    try:
        j = run_job(env, {"environment": "HRDEV", "action": "clearcache"})
    finally:
        fake.run = real
    assert j["status"] == "failed"
    assert fake.cleared == []                          # nothing cleared after a failed stop
    started = [c for _, c in fake.calls if " boot " in c or "-p start" in c or "-w start" in c]
    assert len(started) == 3                           # but every domain was started again


def test_old_connectors_and_production(env):
    con = env["cfg"]["connector_id"]
    cp.connect().execute("UPDATE connectors SET version='0.3.0' WHERE id=?", (con,))
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV",
                                                                            "action": "clearcache"})
    assert r.status_code == 409 and "connector 0.4.0" in r.json()["error"]
    cp.connect().execute("UPDATE connectors SET version='0.4.0' WHERE id=?", (con,))
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRPRD",
                                                                            "action": "clearcache"})
    assert r.status_code == 409 and r.json()["need_confirm"]
    drain(env)
