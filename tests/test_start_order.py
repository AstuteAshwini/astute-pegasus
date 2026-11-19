"""A client's own start order per environment (e.g. master scheduler first), used by every start, stop and apply."""
from conftest import drain, wait_job
from pegasus_cloud import app as cp


def u(env, path):
    return env["url"] + path.format(cid=env["cid"])


def servers(env, name="HRDEV"):
    d = env["admin"].get(u(env, "/api/clients/{cid}")).json()
    return next(e for e in d["environments"] if e["name"] == name)


def key(s):
    return f"{s['ip'] or s['host']}|{s['role']}|{s['domain']}"


def job_labels(env, jid):
    return [st["label"] for st in env["admin"].get(u(env, f"/api/jobs/{jid}")).json()["steps"]]


def test_custom_start_order(env):
    a, e = env["admin"], servers(env)
    by = {s["domain"]: s for s in e["servers"]}            # peoplesoft (web), HRDEV (app), PRCSDOM (prcs)
    path = "/api/clients/{cid}/environments/HRDEV/start-order"
    assert a.put(u(env, path), json={"stages": {"10.9.9.9|app|X": 1}}).status_code == 400
    assert a.put(u(env, path), json={"stages": {key(by["PRCSDOM"]): 0}}).status_code == 400
    r = a.put(u(env, path), json={"stages": {key(by["PRCSDOM"]): 1, key(by["peoplesoft"]): 2},
                                  "manual": ["Start PSNT process schedulers", " ", "Start Elasticsearch"]})
    assert r.ok, r.text
    e = servers(env)
    assert e["manual_steps"] == ["Start PSNT process schedulers", "Start Elasticsearch"]
    assert {s["domain"]: s["stage"] for s in e["servers"]} == {"PRCSDOM": 1, "peoplesoft": 2, "HRDEV": None}

    with cp.app.app_context():
        steps, _ = cp.plan_steps(cp.env_servers(env["cid"], "HRDEV"), "restart")
        labels = [s["label"] for s in steps]
        assert labels == ["Stop app HRDEV", "Stop web peoplesoft", "Stop prcs PRCSDOM",
                          "Start prcs PRCSDOM", "Start web peoplesoft", "Start app HRDEV"]
        phases = [st["phase"] for st in cp.add_lanes(steps)]
        assert len(set(phases[3:])) == 3                    # each start number is its own phase, run one after another

    r = a.post(u(env, "/api/clients/{cid}/run"), json={"environment": "HRDEV", "action": "start"})
    assert r.ok, r.text
    drain(env)
    wait_job(env, r.json()["job"])
    assert job_labels(env, r.json()["job"]) == ["Start prcs PRCSDOM", "Start web peoplesoft", "Start app HRDEV"]

    assert a.put(u(env, path), json={"stages": {}, "manual": []}).ok     # back to the usual order
    with cp.app.app_context():
        steps, _ = cp.plan_steps(cp.env_servers(env["cid"], "HRDEV"), "start")
    assert [s["label"] for s in steps] == ["Start app HRDEV", "Start prcs PRCSDOM", "Start web peoplesoft"]
    assert "manual_steps" in servers(env) and servers(env)["manual_steps"] == []
