"""The per-client OCI Console link."""


def test_oci_console_link(env):
    u = env["url"] + f"/api/clients/{env['cid']}/oci-console"
    assert env["admin"].get(env["url"] + f"/api/clients/{env['cid']}").json()["oci_console"] is None
    r = env["admin"].put(u, json={"tenancy": "miracostaoci", "region": "us-phoenix-1"})
    assert r.ok and r.json()["oci_console"]["url"] == "https://cloud.oracle.com/?tenant=miracostaoci&region=us-phoenix-1"
    assert env["admin"].get(env["url"] + f"/api/clients/{env['cid']}").json()["oci_console"]["tenancy"] == "miracostaoci"
    assert "region identifier" in env["admin"].put(u, json={"tenancy": "x", "region": "Phoenix"}).json()["error"]
    assert env["admin"].put(u, json={"tenancy": "bad name\"><script>"}).status_code == 400
    assert env["admin"].put(u, json={"tenancy": ""}).json()["oci_console"] is None
