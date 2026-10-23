"""Scheduled start/stop: next-run times (with daylight saving), validation, production confirmation, and what a
due schedule does: runs, skips when asked or busy, and refuses to run very late."""
import datetime as dt
import time
from zoneinfo import ZoneInfo

from conftest import drain
from pegasus_cloud import app as cp

LA = "America/Los_Angeles"


def utc(*a):
    return dt.datetime(*a, tzinfo=dt.timezone.utc).timestamp()


def sch(**kw):
    base = {"days": "0,1,2,3,4", "once_date": None, "at_time": "07:00", "tz": LA}
    base.update(kw)
    return base


def test_next_run_keeps_local_time_across_daylight_saving():
    # Fri 30 Oct 2026 is still daylight time (UTC-7); Mon 2 Nov is standard time (UTC-8), DST ended Sun 1 Nov.
    fri = cp.next_occurrence(sch(), utc(2026, 10, 30, 12, 0))
    assert fri == utc(2026, 10, 30, 14, 0)                   # 07:00 PDT
    mon = cp.next_occurrence(sch(), fri)
    assert mon == utc(2026, 11, 2, 15, 0)                    # 07:00 PST, skipping the weekend
    assert dt.datetime.fromtimestamp(mon, ZoneInfo(LA)).strftime("%a %H:%M") == "Mon 07:00"


def test_next_run_for_weekends_once_and_past():
    sat = cp.next_occurrence(sch(days="5,6", at_time="23:30"), utc(2026, 10, 23, 12, 0))
    assert dt.datetime.fromtimestamp(sat, ZoneInfo(LA)).strftime("%a %d %H:%M") == "Sat 24 23:30"
    once = sch(once_date="2026-12-24", at_time="18:00")
    assert cp.next_occurrence(once, utc(2026, 10, 23)) == utc(2026, 12, 25, 2, 0)
    assert cp.next_occurrence(once, utc(2026, 12, 26)) is None


def api(env, method, path, **kw):
    return env["admin"].request(method, env["url"] + path, **kw)


def add(env, **body):
    b = {"environment": "HRDEV", "action": "stop", "days": [0, 1, 2, 3, 4, 5, 6], "time": "19:00", "tz": LA}
    b.update(body)
    return api(env, "POST", f"/api/clients/{env['cid']}/schedules", json=b)


def test_validation_and_production_confirmation(env):
    assert add(env, environment="NOPE").status_code == 400
    assert "HH:MM" in add(env, time="7pm").json()["error"]
    assert add(env, days=[]).json()["error"] == "Pick at least one day."
    assert "time zone" in add(env, tz="Mars/Olympus").json()["error"]
    assert "passed" in add(env, days=None, once_date="2020-01-01").json()["error"]
    r = add(env, environment="HRPRD")
    assert r.status_code == 409 and r.json()["need_confirm"]
    r = add(env, environment="HRPRD", confirm="hrprd")
    assert r.status_code == 200 and r.json()["tier"] == "PRD"
    assert api(env, "DELETE", f"/api/schedules/{r.json()['id']}").ok


def set_due(sid, at):
    cp.connect().execute("UPDATE schedules SET next_run=? WHERE id=?", (at, sid))


def view(env, sid):
    return [s for s in api(env, "GET", f"/api/clients/{env['cid']}/schedules").json()["schedules"] if s["id"] == sid][0]


def test_a_due_schedule_runs_the_same_safe_stop(env):
    s = add(env, action="stop").json()
    assert s["next_run"] and s["days"] == [0, 1, 2, 3, 4, 5, 6]
    set_due(s["id"], time.time() - 5)
    with cp.app.app_context():
        cp.run_due_schedules()
    v = view(env, s["id"])
    assert v["last_status"] == "queued" and v["last_job"]
    assert cp.protocol.version_tuple("1") and v["next_run"] > v["last_run"]
    env["fake"].calls.clear()
    drain(env)
    j = env["admin"].get(env["url"] + f"/api/jobs/{v['last_job']}").json()
    assert j["status"] == "succeeded" and j["created_by"] == "schedule"
    assert [h for h, _ in env["fake"].calls] == ["hrdevweb01", "hrdevapp01", "hrdevapp01"]   # web, prcs, app
    assert view(env, s["id"])["last_job_status"] == "succeeded"
    ev = cp.connect().execute("SELECT * FROM audit WHERE event='schedule_ran' ORDER BY id DESC").fetchone()
    assert ev["actor"] == "schedule" and "stop HRDEV every day at 19:00" in ev["detail"]
    api(env, "DELETE", f"/api/schedules/{s['id']}")
    j = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV", "action": "start"})
    drain(env)


def test_skip_next_late_runs_and_busy_environments(env):
    s = add(env, action="restart").json()
    # skip once
    assert api(env, "PATCH", f"/api/schedules/{s['id']}", json={"skip_next": True}).json()["skip_next"]
    set_due(s["id"], time.time() - 5)
    with cp.app.app_context():
        cp.run_due_schedules()
    v = view(env, s["id"])
    assert v["last_status"] == "skipped" and "as requested" in v["last_detail"] and not v["skip_next"]
    assert not v["last_job"]
    # far too late (Pegasus was down): don't start an environment hours late
    set_due(s["id"], time.time() - 3 * 3600)
    with cp.app.app_context():
        cp.run_due_schedules()
    v = view(env, s["id"])
    assert v["last_status"] == "missed" and v["next_run"] > cp.iso(time.time())
    # something else already queued on the environment
    j = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/run", json={"environment": "HRDEV", "action": "status"})
    assert j.ok
    set_due(s["id"], time.time() - 5)
    with cp.app.app_context():
        cp.run_due_schedules()
    v = view(env, s["id"])
    assert v["last_status"] == "skipped" and "already running" in v["last_detail"]
    drain(env)
    # paused schedules don't run; resuming picks the next time from now
    assert not api(env, "PATCH", f"/api/schedules/{s['id']}", json={"enabled": False}).json()["enabled"]
    set_due(s["id"], time.time() - 5)
    with cp.app.app_context():
        cp.run_due_schedules()
    assert view(env, s["id"])["last_status"] == "skipped"            # unchanged: it didn't run
    r = api(env, "PATCH", f"/api/schedules/{s['id']}", json={"enabled": True}).json()
    assert r["enabled"] and r["next_run"] > cp.iso(time.time())
    api(env, "DELETE", f"/api/schedules/{s['id']}")


def test_a_one_off_schedule_finishes(env):
    tomorrow = (dt.datetime.now(ZoneInfo(LA)) + dt.timedelta(days=1)).date().isoformat()
    s = add(env, action="start", days=None, once_date=tomorrow, time="06:30").json()
    assert s["once_date"] == tomorrow
    at = cp.connect().execute("SELECT next_run FROM schedules WHERE id=?", (s["id"],)).fetchone()[0]
    assert dt.datetime.fromtimestamp(at, ZoneInfo(LA)).strftime("%Y-%m-%d %H:%M") == f"{tomorrow} 06:30"
    with cp.app.app_context():
        cp.run_due_schedules(now=at + 20)                    # as if the clock had reached it
    v = view(env, s["id"])
    assert v["last_status"] == "queued" and v["next_run"] is None
    drain(env)
    api(env, "DELETE", f"/api/schedules/{s['id']}")
