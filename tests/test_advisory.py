"""Risk scores from Oracle's quarterly advisory: highest CVSS per component Pegasus patches."""
from pegasus_cloud import advisory, app as cp

PAGE = """<html><body><h2>Critical Patch Update Advisory - October 2026</h2>
<h3 id="AppendixFMW">Oracle Fusion Middleware Risk Matrix</h3>
<table class="otable-w2"><thead><tr><th rowspan="2">CVE#</th><th rowspan="2">Product</th><th>Component</th>
<th>Protocol</th><th>Remote Exploit without Auth.?</th><th colspan="9">CVSS VERSION 3.1 RISK</th></tr>
<tr><th>Base Score</th><th>Attack Vector</th></tr></thead><tbody>
<tr><th>CVE-2026-21001</th><td>Oracle WebLogic Server</td><td>Core</td><td>T3, IIOP</td><td>Yes</td><td>9.8</td><td>Network</td></tr>
<tr><th>CVE-2026-21002</th><td>Oracle WebLogic Server</td><td>Web Container</td><td>HTTP</td><td>Yes</td><td>7.5</td><td>Network</td></tr>
<tr><th>CVE-2026-21010</th><td>Oracle Tuxedo</td><td>Core (OpenSSL)</td><td>TLS</td><td>Yes</td><td>5.9</td><td>Network</td></tr>
<tr><th>CVE-2026-21020</th><td>Oracle HTTP Server</td><td>Core</td><td>HTTPS</td><td>Yes</td><td>8.1</td><td>Network</td></tr>
</tbody></table>
<h3>Oracle Java SE Risk Matrix</h3><table><tbody>
<tr><th>CVE#</th><th>Product</th><th>Component</th><th>Protocol</th><th>Remote?</th><th>Base Score</th></tr>
<tr><td>CVE-2026-21100</td><td>Oracle Java SE, Oracle GraalVM for JDK</td><td>Hotspot</td><td>Multiple</td><td>Yes</td><td>7.4</td></tr>
<tr><td>CVE-2026-21101</td><td>Oracle Java SE</td><td>Libraries</td><td>Multiple</td><td>Yes</td><td>3.7</td></tr></tbody></table>
<h3>Oracle Database Server Risk Matrix</h3><table><tbody>
<tr><td>CVE-2026-21200</td><td>Java VM</td><td>Create Session</td><td>Oracle Net</td><td>No</td><td>6.5</td></tr></tbody></table>
<h3>Oracle PeopleSoft Risk Matrix</h3><table><tbody>
<tr><td>CVE-2026-21300</td><td>PeopleSoft Enterprise PeopleTools</td><td>Portal</td><td>HTTP</td><td>No</td><td>5.4</td></tr>
<tr><td>CVE-2026-21301</td><td>PeopleSoft Enterprise HCM</td><td>Payroll</td><td>HTTP</td><td>No</td><td>4.3</td></tr></tbody></table>
</body></html>"""


def test_parse_takes_the_highest_score_per_component():
    found = advisory.parse(PAGE)
    wl = found["weblogic"]
    assert (wl["max"], wl["cve"], wl["count"], wl["product"]) == (9.8, "CVE-2026-21001", 2, "Oracle WebLogic Server")
    assert [(x["cve"], x["score"], x["component"]) for x in wl["cves"]] == [("CVE-2026-21001", 9.8, "Core"),
                                                                          ("CVE-2026-21002", 7.5, "Web Container")]
    assert found["tuxedo"]["max"] == 5.9 and found["jdk"]["max"] == 7.4 and found["jdk"]["count"] == 2
    assert found["dbclient"]["max"] == 6.5 and found["peopletools"]["count"] == 1
    assert "Oracle HTTP Server" not in str(found)
    assert advisory.advisory_url("2026-10-20") == "https://www.oracle.com/security-alerts/cpuoct2026.html"
    assert [advisory.severity(x) for x in (9.8, 7.0, 5.9, 2.0)] == ["critical", "high", "medium", "low"]


def test_refresh_caches_and_shows_in_patching(env, monkeypatch):
    calls = []
    monkeypatch.setattr(cp, "fetch_advisory_page", lambda url: calls.append(url) or PAGE)
    with cp.app.app_context():
        a = cp.refresh_advisory(force=True)
        assert a["components"]["weblogic"]["max"] == 9.8 and not a["error"]
        cp.refresh_advisory()                                      # cached for a day: not fetched again
    assert len(calls) == 1
    r = env["admin"].get(env["url"] + f"/api/clients/{env['cid']}/patching", params={"environment": "HRDEV"})
    adv = r.json()["advisory"]
    assert adv["components"]["weblogic"]["severity"] == "critical" and adv["url"].startswith("https://www.oracle.com/")
    first = adv["components"]["weblogic"]["cves"][0]
    assert first["url"] == "https://www.cve.org/CVERecord?id=CVE-2026-21001" and first["severity"] == "critical"

    def broken(url):
        raise OSError("no route")
    monkeypatch.setattr(cp, "fetch_advisory_page", broken)
    with cp.app.app_context():
        a = cp.refresh_advisory(force=True)
    assert "no route" in a["error"] and a["components"]["weblogic"]["max"] == 9.8   # last good scores kept


def test_quarterly_clients_defer_releases_between_cpus():
    from pegasus_cloud import evaluate as ev
    assert ev.is_cpu_release("2026-10-20") and ev.is_cpu_release("2026-10-27")      # Oct 2026 CPU (and a late patch)
    assert not ev.is_cpu_release("2026-11-17") and not ev.is_cpu_release("2026-09-15")
    items = [{"component": "jdk", "status": "needed", "released": "2026-11-17", "latest_label": "21.0.13.0.4", "key": "k"},
             {"component": "weblogic", "status": "needed", "released": "2026-10-20", "key": "w"},
             {"component": "tuxedo", "status": "needed", "released": "2026-11-17", "source": "CPU target", "key": "t"}]
    ev.apply_cadence(items, "monthly")
    assert [i["status"] for i in items] == ["needed"] * 3
    ev.apply_cadence(items, "quarterly")
    assert [i["status"] for i in items] == ["deferred", "needed", "needed"]
    assert "next CPU" in items[0]["detail"]


def test_cadence_setting(env):
    base = env["url"] + f"/api/clients/{env['cid']}/patch-settings"
    assert env["admin"].get(base).json()["cadence"] == "monthly"
    assert env["admin"].put(base, json={"cadence": "quarterly"}).json()["cadence"] == "quarterly"
    assert env["admin"].put(base, json={"cadence": "weekly"}).status_code == 400
    env["admin"].put(base, json={"cadence": "monthly"})


def test_cve_listed_twice_counts_once_and_old_cache_refetches(env, monkeypatch):
    page = PAGE.replace("</tbody></table>\n<h3>Oracle Java SE",
                        "<tr><td>CVE-2026-21001</td><td>Oracle WebLogic Server</td><td>Console</td><td>HTTP</td>"
                        "<td>No</td><td>6.1</td></tr></tbody></table>\n<h3>Oracle Java SE", 1)
    wl = advisory.parse(page)["weblogic"]
    assert wl["count"] == 2 and wl["cves"][0]["score"] == 9.8
    monkeypatch.setattr(cp, "fetch_advisory_page", lambda url: PAGE)
    import time as t
    from pegasus_cloud import evaluate as ev
    with cp.app.app_context():                    # cached today, but from before CVE lists were kept
        cp.put_setting("_global", "cpu_advisory", {"cpu": ev.cpu_dates()["last"], "fetched": t.time(), "tried": t.time(),
                                                   "error": "", "components": {"weblogic": {"max": 9.8, "cve": "x",
                                                                                            "count": 1, "product": "p"}}})
        assert cp.refresh_advisory()["components"]["weblogic"]["cves"]


def test_jira_ticket_lists_the_cves():
    from pegasus_cloud import evaluate as ev
    found = advisory.parse(PAGE)
    plan = [{"component": "weblogic", "label": "14.1.2.0.251015", "host": "hrdevapp01"},
            {"component": "os", "label": "3 updates", "host": "hrdevapp01"}]
    text = ev.describe_plan("HRDEV", "MCC", "DEV", plan, "", "Ashwini", "today", None,
                            {"url": "https://www.oracle.com/security-alerts/cpuoct2026.html", "components": found})
    assert "h3. Security fixes" in text and "2 CVEs, highest CVSS 9.8" in text
    assert "[CVE-2026-21001|https://www.cve.org/CVERecord?id=CVE-2026-21001] CVSS 9.8" in text
    assert "CVE-2026-21100" not in text                         # the JDK isn't in this plan
    assert "Security fixes" not in ev.describe_plan("HRDEV", "MCC", "DEV", plan[1:], "", "A", "today")
