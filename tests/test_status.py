"""Every domain's last known state, from jobs and from automatic checks."""
from conftest import drain, wait_job
from pegasus_cloud import app as cp


def states(env, now=False):
    return env["admin"].get(env["url"] + f"/api/clients/{env['cid']}/states" + ("?now=1" if now else "")).json()


def test_stop_and_start_are_remembered(env):
    base = env["url"] + f"/api/clients/{env['cid']}/run"
    r = env["admin"].post(base, json={"environment": "HRDEV", "action": "stop"})
    drain(env)
    wait_job(env, r.json()["job"])
    s = states(env)["states"]
    assert s["HRDEV|10.0.1.21|app|HRDEV"]["state"] == "stopped"
    assert s["HRDEV|10.0.1.11|web|peoplesoft"]["state"] == "stopped"
    r = env["admin"].post(base, json={"environment": "HRDEV", "action": "start"})
    drain(env)
    wait_job(env, r.json()["job"])
    assert states(env)["states"]["HRDEV|10.0.1.21|app|HRDEV"]["state"] == "running"


def test_automatic_check_covers_every_environment_and_stays_out_of_recent_jobs(env):
    env["fake"].state["HRPRD"] = False
    s = states(env, now=True)
    assert s["checking"] and s["online"]
    assert states(env, now=True)["checking"]                    # only one automatic check waits at a time
    drain(env)
    s = states(env)
    assert not s["checking"]
    assert s["states"]["HRPRD|10.0.9.21|app|HRPRD"]["state"] == "stopped"
    assert s["states"]["HRDEV|10.0.1.21|prcs|PRCSDOM"]["state"] == "running"
    d = env["admin"].get(env["url"] + f"/api/clients/{env['cid']}").json()
    assert all(j["kind"] != "status_auto" for j in d["jobs"])
    # automatic checks don't block what people do
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV",
                                                                              "action": "status"})
    states(env, now=True)
    assert r.ok
    drain(env)
    env["fake"].state["HRPRD"] = True


def test_interval_is_respected(env):
    old = cp.STATUS_EVERY
    cp.STATUS_EVERY = 3600
    try:
        states(env, now=True)
        drain(env)
        assert not states(env)["checking"]                      # one just ran, so no new one yet
    finally:
        cp.STATUS_EVERY = old


def test_one_domain_only(env):
    env["fake"].calls.clear()
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run",
                          json={"environment": "HRDEV", "action": "stop", "host": "10.0.1.21", "role": "prcs",
                                "domain": "PRCSDOM"})
    assert r.ok and r.json()["steps"] == 1, r.text
    drain(env)
    j = wait_job(env, r.json()["job"])
    assert j["status"] == "succeeded" and j["title"] == "stop HRDEV / 10.0.1.21 prcs PRCSDOM"
    assert len(env["fake"].calls) == 1 and "-p stop" in env["fake"].calls[0][1]
    s = states(env)["states"]
    assert s["HRDEV|10.0.1.21|prcs|PRCSDOM"]["state"] == "stopped"
    assert s["HRDEV|10.0.1.21|app|HRDEV"]["state"] == "running"            # the app domain on the same host untouched
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run",
                          json={"environment": "HRDEV", "action": "start", "domain": "NOPE"})
    assert r.status_code == 404
    r = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run",
                          json={"environment": "HRDEV", "action": "start", "role": "prcs", "domain": "PRCSDOM"})
    drain(env)
    wait_job(env, r.json()["job"])
