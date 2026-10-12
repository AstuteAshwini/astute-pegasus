"""Accounts: first admin, MFA enrollment and sign-in, recovery codes, lockout, roles and per-client scoping."""
import requests

from conftest import ADMIN, session, sign_in
from pegasus_cloud import app as cp, auth
from pegasus_connector import oracle


def test_setup_works_only_once(env):
    r = session().post(env["url"] + "/api/setup", json=dict(ADMIN, email="other@x.com", setup_password="setup-pw"))
    assert r.status_code == 409


def test_password_alone_isnt_enough(env):
    s = session()
    r = s.post(env["url"] + "/api/login", json={"email": ADMIN["email"], "password": ADMIN["password"]})
    assert r.json()["next"] == "mfa"
    assert s.get(env["url"] + "/api/clients").status_code == 401        # half signed in: nothing works yet
    assert s.post(env["url"] + "/api/login/mfa", json={"code": "000000"}).status_code == 401


def test_recovery_code_works_once(env):
    code = env["recovery"][0]
    for expected in (200, 401):
        s = session()
        s.post(env["url"] + "/api/login", json={"email": ADMIN["email"], "password": ADMIN["password"]})
        assert s.post(env["url"] + "/api/login/mfa", json={"code": code}).status_code == expected


def test_totp_matches_rfc6238_vectors():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"          # base32 of "12345678901234567890"
    assert auth.totp_at(secret, 59 // 30) == "287082"
    assert auth.totp_at(secret, 1111111109 // 30) == "081804"


def test_new_user_must_change_password_and_enrol(env):
    r = env["admin"].post(env["url"] + "/api/users", json={"email": "op@beastute.com", "name": "Ops Person",
                                                          "role": "operator"})
    assert r.ok, r.text
    temp = r.json()["temporary_password"]
    s, secret, _ = sign_in(env["url"], "op@beastute.com", temp)
    r = s.get(env["url"] + "/api/clients")
    assert r.status_code == 403 and r.json()["must_change_password"]
    assert s.post(env["url"] + "/api/password", json={"current": temp, "new": "short"}).status_code == 400
    assert s.post(env["url"] + "/api/password", json={"current": temp, "new": "a much better passphrase 9"}).ok
    assert s.get(env["url"] + "/api/clients").ok
    # operators run jobs but can't change configuration
    assert s.post(env["url"] + "/api/clients", json={"name": "X"}).status_code == 403
    assert s.put(env["url"] + f"/api/clients/{env['cid']}/jira", json={}).status_code == 403


def test_client_user_sees_only_their_client(env):
    other = env["admin"].post(env["url"] + "/api/clients", json={"name": "Parker"}).json()["id"]
    r = env["admin"].post(env["url"] + "/api/users", json={"email": "viewer@parker.com", "name": "Parker Viewer",
                                                          "role": "viewer", "client_id": other})
    temp = r.json()["temporary_password"]
    s, _, _ = sign_in(env["url"], "viewer@parker.com", temp)
    s.post(env["url"] + "/api/password", json={"current": temp, "new": "blue river lantern 77"})
    assert [c["id"] for c in s.get(env["url"] + "/api/clients").json()["clients"]] == [other]
    assert s.get(env["url"] + f"/api/clients/{env['cid']}").status_code == 404
    assert s.post(env["url"] + f"/api/clients/{other}/run", json={"environment": "X", "action": "status"}).status_code == 403
    r = env["admin"].post(env["url"] + "/api/users", json={"email": "adm@parker.com", "name": "P", "role": "admin",
                                                          "client_id": other})
    assert r.status_code == 400                       # client users can't be admins


def test_lockout_after_repeated_failures(env):
    r = env["admin"].post(env["url"] + "/api/users", json={"email": "lock@beastute.com", "name": "Lock", "role": "viewer"})
    for _ in range(5):
        session().post(env["url"] + "/api/login", json={"email": "lock@beastute.com", "password": "wrong"})
    r = session().post(env["url"] + "/api/login", json={"email": "lock@beastute.com",
                                                       "password": r.json()["temporary_password"]})
    assert r.status_code == 429


def test_disabling_a_user_ends_their_session(env):
    r = env["admin"].post(env["url"] + "/api/users", json={"email": "gone@beastute.com", "name": "Gone",
                                                          "role": "viewer"})
    uid, temp = r.json()["user"]["id"], r.json()["temporary_password"]
    s, _, _ = sign_in(env["url"], "gone@beastute.com", temp)
    s.post(env["url"] + "/api/password", json={"current": temp, "new": "temporary viewer phrase 3"})
    assert s.get(env["url"] + "/api/clients").ok
    assert env["admin"].patch(env["url"] + f"/api/users/{uid}", json={"disabled": True}).ok
    assert s.get(env["url"] + "/api/clients").status_code == 401


def test_last_admin_cant_be_removed(env):
    me = next(u for u in env["admin"].get(env["url"] + "/api/users").json()["users"] if u["email"] == ADMIN["email"])
    r = env["admin"].patch(env["url"] + f"/api/users/{me['id']}", json={"role": "operator"})
    assert r.status_code == 409


def test_audit_records_sign_ins_and_jobs(env):
    events = {e["event"] for e in env["admin"].get(env["url"] + "/api/audit").json()["events"]}
    assert {"first_admin_created", "signed_in", "mfa_enrolled", "user_created", "sign_in_failed"} <= events


def test_requests_without_the_app_header_are_refused(env):
    r = requests.post(env["url"] + "/api/login", json={"email": ADMIN["email"], "password": ADMIN["password"]})
    assert r.status_code == 400


def test_oracle_support_search_parsing():
    page = ('<tr class="OraBGAccentVeryDark"><td>38000001</td><td>WLS PATCH SET UPDATE 14.1.2.0.251015</td>'
            '<td>14.1.2.0.0</td><td>21-OCT-2025</td><td>600 MB</td></tr>'
            '<tr class="OraBGAccentVeryDark"><td>38000002</td><td>WLS STACK PATCH BUNDLE 14.1.2.0.251015 (Patch)</td>'
            '<td>14.1.2.0.0</td><td>22-OCT-2025</td><td>1.2 GB</td></tr>'
            '<tr class="OraBGAccentVeryDark"><td>37000001</td><td>WLS PATCH SET UPDATE 14.1.2.0.250705</td>'
            '<td>14.1.2.0.0</td><td>15-JUL-2025</td><td>590 MB</td></tr>')
    w = oracle.latest_weblogic(oracle.parse_aru_rows(page))
    assert w["stamp"] == "251015" and w["psu_patch"] == "38000001" and w["spb_patch"] == "38000002"
    assert w["released_by_stamp"]["250705"] == "2025-07-15"


def test_secret_box_round_trip(tmp_path):
    b = auth.SecretBox(tmp_path / "k")
    sealed = b.seal("token-123")
    assert sealed != "token-123" and b.open(sealed) == "token-123"
    assert auth.SecretBox(tmp_path / "k").open(sealed) == "token-123"     # same key file, same result
    assert cp.DATA_DIR.joinpath("secret.key").stat().st_mode & 0o077 == 0
