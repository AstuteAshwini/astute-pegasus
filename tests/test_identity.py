"""Connector certificates: registration, signed requests, replay and tamper checks, renewal, enrolling an old
connector, revocation and expiry. Each test uses its own connector so the shared one keeps working."""
import json
import time
from pathlib import Path

import pytest
import requests

from conftest import TMP
from fakes import FakeServers
from pegasus_cloud import app as cp
from pegasus_connector import agent as ag, protocol

N = {"n": 0}


def new_agent(env, legacy=False):
    N["n"] += 1
    tok = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/tokens").json()["token"]
    path = f"{TMP}/id{N['n']}/config.json"
    if legacy:                         # what a connector from before certificates did: no public key, gets a secret
        j = requests.post(env["url"] + "/api/connector/v1/register",
                          json={"token": tok, "name": f"old{N['n']}", "version": "0.2.1"}).json()
        assert j["secret"] and "certificate" not in j
        ag.save_config(path, {"url": env["url"], "connector_id": j["connector_id"], "secret": j["secret"],
                              "tenant": j["tenant"], "client_name": j["client_name"],
                              "signing_key": j["signing_public_key"], "ssh": {"user": "opc", "key_path": "/k"}})
    else:
        ag.register(env["url"], tok, path, "opc", "/k", name=f"id{N['n']}")
    a = ag.Agent(path, runner=FakeServers())
    a.log = lambda *_: None
    return a


def row(con_id):
    return cp.connect().execute("SELECT * FROM connectors WHERE id=?", (con_id,)).fetchone()


def test_registration_issues_a_certificate_and_no_secret(env):
    cfg = env["cfg"]
    assert "secret" not in cfg and cfg["key"].startswith("-----BEGIN PRIVATE KEY")
    protocol.verify_cert(cfg["certificate"], cfg["certificate_signature"], cfg["signing_key"])
    assert cfg["certificate"]["connector"] == cfg["connector_id"]
    assert 89 < (cfg["certificate"]["not_after"] - time.time()) / 86400 <= 90
    r = row(cfg["connector_id"])
    assert r["secret_hash"] == "!" and r["public_key"] == cfg["certificate"]["public_key"]
    d = env["admin"].get(env["url"] + f"/api/clients/{env['cid']}").json()
    c = [x for x in d["connectors"] if x["id"] == cfg["connector_id"]][0]
    assert c["auth"] == "certificate" and c["certificate"]["serial"] == cfg["certificate"]["serial"]


def test_signed_requests_work_and_replays_and_tampering_dont(env):
    a = new_agent(env)
    assert a.post("/heartbeat", {"version": "x"}).status_code == 200
    # capture one signed request and send the very same bytes again
    req = requests.Request("POST", env["url"] + "/api/connector/v1/heartbeat", json={"version": "x"})
    p = a.s.prepare_request(req)
    assert a.s.send(p).status_code == 200
    again = requests.Session().send(p)
    assert again.status_code == 401 and "already received" in again.json()["error"]
    # same headers, different body
    p2 = a.s.prepare_request(req)
    p2.body = json.dumps({"version": "evil"}).encode()
    p2.headers["Content-Length"] = str(len(p2.body))
    r = requests.Session().send(p2)
    assert r.status_code == 401 and "didn't check out" in r.json()["error"]
    # an old timestamp
    h = protocol.sign_request(a.key, "POST", "/api/connector/v1/heartbeat", b"{}", timestamp=time.time() - 900)
    h.update({"X-Pegasus-Connector": a.cfg["connector_id"], "Content-Type": "application/json"})
    r = requests.post(env["url"] + "/api/connector/v1/heartbeat", data=b"{}", headers=h)
    assert r.status_code == 401 and "clock" in r.json()["error"]
    # someone else's key
    other = protocol.new_private_key()
    h = protocol.sign_request(other, "POST", "/api/connector/v1/heartbeat", b"{}")
    h.update({"X-Pegasus-Connector": a.cfg["connector_id"], "Content-Type": "application/json"})
    assert requests.post(env["url"] + "/api/connector/v1/heartbeat", data=b"{}", headers=h).status_code == 401


def test_renewal_rotates_the_key_and_the_old_key_fades_out(env):
    a = new_agent(env)
    old_key, old_serial = a.cfg["certificate"]["public_key"], a.cfg["certificate"]["serial"]
    old_session_key = a.key
    a.ensure_identity(now=time.time())                    # not due yet: nothing happens
    assert a.cfg["certificate"]["serial"] == old_serial
    r = row(a.cfg["connector_id"])
    cp.connect().execute("UPDATE connectors SET cert_issued_at=? WHERE id=?", (time.time() - 3600, r["id"]))
    a.ensure_identity(now=time.time() + 31 * 86400)       # 59 days left: renew
    new = a.cfg["certificate"]
    assert new["serial"] != old_serial and new["public_key"] != old_key
    saved = ag.load_config(a.config_path)
    assert saved["certificate"]["serial"] == new["serial"] and saved["key"] == a.cfg["key"]
    assert a.post("/heartbeat", {}).status_code == 200
    # a request signed with the old key, already on its way during the renewal, is still accepted for a while
    h = protocol.sign_request(old_session_key, "POST", "/api/connector/v1/heartbeat", b"{}")
    h.update({"X-Pegasus-Connector": a.cfg["connector_id"], "Content-Type": "application/json"})
    assert requests.post(env["url"] + "/api/connector/v1/heartbeat", data=b"{}", headers=h).status_code == 200
    cp.connect().execute("UPDATE connectors SET prev_until=? WHERE id=?", (time.time() - 1, r["id"]))
    h = protocol.sign_request(old_session_key, "POST", "/api/connector/v1/heartbeat", b"{}")
    h.update({"X-Pegasus-Connector": a.cfg["connector_id"], "Content-Type": "application/json"})
    assert requests.post(env["url"] + "/api/connector/v1/heartbeat", data=b"{}", headers=h).status_code == 401
    ev = cp.connect().execute("SELECT detail FROM audit WHERE event='connector_certificate_renewed' "
                              "ORDER BY id DESC").fetchone()
    assert old_serial in ev["detail"]


def test_an_old_connector_swaps_its_secret_for_a_certificate(env):
    a = new_agent(env, legacy=True)
    assert not a.has_certificate
    secret_header = a.s.headers["Authorization"]
    assert a.post("/heartbeat", {}).status_code == 200      # the old way still works until it enrolls
    a.ensure_identity()
    assert a.has_certificate and "secret" not in ag.load_config(a.config_path)
    assert a.post("/heartbeat", {}).status_code == 200
    r = requests.post(env["url"] + "/api/connector/v1/heartbeat", json={}, headers={"Authorization": secret_header})
    assert r.status_code == 401                              # the old secret is gone for good
    # it can't enroll a second time
    r = a.post("/certificate/enroll", {"public_key": protocol.public_key_of(protocol.new_private_key())})
    assert r.status_code == 409


def test_removing_a_connector_revokes_its_certificate(env):
    a = new_agent(env)
    assert env["admin"].delete(env["url"] + f"/api/connectors/{a.cfg['connector_id']}").ok
    r = a.post("/heartbeat", {})
    assert r.status_code == 401 and "removed" in r.json()["error"]
    with pytest.raises(PermissionError, match="Register it again"):
        a.fetch(wait=0)


def test_an_expired_certificate_is_refused(env):
    a = new_agent(env)
    cp.connect().execute("UPDATE connectors SET cert_not_after=? WHERE id=?", (time.time() - 1, a.cfg["connector_id"]))
    r = a.post("/heartbeat", {})
    assert r.status_code == 401 and "expired" in r.json()["error"]


def test_a_certificate_from_another_control_plane_is_rejected_at_registration(env):
    tok = env["admin"].post(env["url"] + f"/api/clients/{env['cid']}/tokens").json()["token"]

    class Liar(requests.Session):                 # swaps in a certificate signed by some other key
        def post(self, *a, **k):
            r = super().post(*a, **k)
            j = r.json()
            cert, _ = protocol.issue_cert(protocol.new_private_key(), j["connector_id"], j["tenant"],
                                          j["certificate"]["public_key"], "s_fake")
            j["certificate"] = cert
            r._content = json.dumps(j).encode()
            return r
    with pytest.raises(RuntimeError, match="didn't check out"):
        ag.register(env["url"], tok, f"{TMP}/liar/config.json", "opc", "/k", session=Liar())
    assert not Path(f"{TMP}/liar/config.json").exists()
