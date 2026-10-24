"""Sign in with Google: only people with a Pegasus account get in, Google's answer is checked, and password sign-in
can be kept for admins only."""
import time
from urllib.parse import parse_qs, unquote, urlparse

import pytest

from conftest import ADMIN, session
from pegasus_cloud import app as cp


@pytest.fixture()
def google(env, monkeypatch):
    monkeypatch.setattr(cp, "GOOGLE_CLIENT_ID", "cid.apps.googleusercontent.com")
    monkeypatch.setattr(cp, "GOOGLE_CLIENT_SECRET", "s3cret")
    monkeypatch.setattr(cp, "GOOGLE_DOMAIN", "beastute.com")
    answer = {}

    def exchange(code, verifier):
        assert code == "good-code" and len(verifier) > 40
        return dict(answer)
    monkeypatch.setattr(cp, "google_exchange", exchange)
    return answer


def start(env):
    s = session()
    r = s.get(env["url"] + "/api/sso/google/start", allow_redirects=False)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["Location"]).query)
    assert q["client_id"] == ["cid.apps.googleusercontent.com"] and q["hd"] == ["beastute.com"]
    assert q["redirect_uri"][0].endswith("/api/sso/google/callback") and q["code_challenge_method"] == ["S256"]
    return s, q["state"][0], q["nonce"][0]


def claims(nonce, **kw):
    c = {"iss": "https://accounts.google.com", "aud": "cid.apps.googleusercontent.com", "exp": time.time() + 300,
         "nonce": nonce, "email": ADMIN["email"].upper(), "email_verified": True, "hd": "beastute.com"}
    c.update(kw)
    return c


def finish(env, s, state, code="good-code"):
    r = s.get(env["url"] + "/api/sso/google/callback", params={"state": state, "code": code}, allow_redirects=False)
    assert r.status_code == 302
    return unquote(r.headers["Location"])


def test_a_known_person_signs_in(env, google):
    s, state, nonce = start(env)
    google.update(claims(nonce))
    assert finish(env, s, state) == "/"
    me = s.get(env["url"] + "/api/session").json()
    assert me["auth"] and me["user"]["email"] == ADMIN["email"] and me["google"]
    ev = cp.connect().execute("SELECT event FROM audit ORDER BY id DESC LIMIT 1").fetchone()["event"]
    assert ev == "signed_in_with_google"


@pytest.mark.parametrize("bad,expect", [
    ({"email": "stranger@beastute.com"}, "doesn't have a Pegasus account"),
    ({"hd": "gmail.com"}, "Use your beastute.com Google account"),
    ({"aud": "someone-else"}, "audience"),
    ({"email_verified": False}, "unverified email"),
    ({"exp": time.time() - 10}, "expiry"),
])
def test_refused(env, google, bad, expect):
    s, state, nonce = start(env)
    google.update(claims(nonce, **bad))
    where = finish(env, s, state)
    assert where.startswith("/?sso_error=") and expect in where
    assert not s.get(env["url"] + "/api/session").json()["auth"]


def test_state_and_nonce_must_match(env, google):
    s, state, nonce = start(env)
    google.update(claims(nonce))
    assert "didn't match" in finish(env, s, "forged-state")
    s, state, nonce = start(env)
    google.update(claims("another-nonce"))
    assert "nonce" in finish(env, s, state)
    # a callback without the cookie from the start (e.g. a link someone was sent) goes nowhere
    assert "took too long" in finish(env, session(), state)


def test_password_signin_for_admins_only(env, google, monkeypatch):
    monkeypatch.setattr(cp, "PASSWORD_SIGNIN", "admins")
    a = env["admin"]
    r = a.post(env["url"] + "/api/users", json={"email": "g.operator@beastute.com", "name": "Op", "role": "operator"})
    assert r.ok, r.text
    pw = r.json()["temporary_password"]
    r = session().post(env["url"] + "/api/login", json={"email": "g.operator@beastute.com", "password": pw})
    assert r.status_code == 403 and "Google" in r.json()["error"]
    r = session().post(env["url"] + "/api/login", json={"email": ADMIN["email"], "password": ADMIN["password"]})
    assert r.ok                                                  # the admin still has a way in
    # the operator signs in with Google; the temporary password stops working
    s, state, nonce = start(env)
    google.update(claims(nonce, email="g.operator@beastute.com"))
    assert finish(env, s, state) == "/"
    assert s.get(env["url"] + "/api/clients").ok
    monkeypatch.setattr(cp, "PASSWORD_SIGNIN", "all")
    r = session().post(env["url"] + "/api/login", json={"email": "g.operator@beastute.com", "password": pw})
    assert r.status_code == 401
