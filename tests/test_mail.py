"""Sign-in links by email for new people and password resets, through a fake SMTP server."""
import re
import time

import pytest

from conftest import session
from pegasus_cloud import app as cp, auth, mailer


class FakeSMTP:
    sent, fail, logins = [], None, []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, pw):
        FakeSMTP.logins.append((user, pw))

    def send_message(self, msg):
        if FakeSMTP.fail:
            raise FakeSMTP.fail
        FakeSMTP.sent.append(msg)


@pytest.fixture()
def smtp(env, monkeypatch):
    monkeypatch.setattr(mailer.smtplib, "SMTP", FakeSMTP)
    FakeSMTP.sent.clear(), FakeSMTP.logins.clear()
    FakeSMTP.fail = None
    yield FakeSMTP
    env["admin"].put(env["url"] + "/api/mail", json={"enabled": False})


def link_in(msg):
    body = msg.get_body(("plain",)).get_content()
    return re.search(r"\?invite=([A-Za-z0-9_\-]+)", body).group(1), body


def test_new_person_gets_a_link_to_choose_a_password(env, smtp):
    a, base = env["admin"], env["url"]
    r = a.post(base + "/api/users", json={"name": "Before Mail", "email": "before@beastute.com", "role": "viewer"})
    assert r.ok and r.json()["temporary_password"] and "emailed" not in r.json()     # email off: as before
    assert a.put(base + "/api/mail", json={"enabled": True, "host": "smtp.example.com"}).status_code == 400
    r = a.put(base + "/api/mail", json={"enabled": True, "host": "smtp.email.us-phoenix-1.oci.oraclecloud.com",
                                        "port": 587, "user": "ocid1.user.oc1..smtp", "password": "smtp-secret",
                                        "from_email": "pegasus@beastute.com"})
    assert r.ok, r.text
    assert "smtp-secret" not in cp.connect().execute("SELECT value FROM settings WHERE key='mail_password'").fetchone()[0]
    assert a.post(base + "/api/mail/test", json={}).json()["ok"] and smtp.logins[-1] == ("ocid1.user.oc1..smtp", "smtp-secret")
    r = a.post(base + "/api/users", json={"name": "Gopi Samraj", "email": "gopi@beastute.com", "role": "operator"})
    j = r.json()
    assert r.ok and j["emailed"] and "temporary_password" not in j and j["user"]["invite_pending"]
    msg = smtp.sent[-1]
    assert msg["To"] == "gopi@beastute.com" and msg["Subject"] == "Your Pegasus account"
    token, body = link_in(msg)
    assert "Hi Gopi" in body and "3 days" in body
    s = session()
    assert s.get(base + "/api/invite", params={"token": token}).json()["email"] == "gopi@beastute.com"
    assert s.post(base + "/api/invite", json={"token": token, "password": "short"}).status_code == 400
    assert s.post(base + "/api/invite", json={"token": token, "password": "Correct-Horse-Battery-9"}).json()["ok"]
    assert s.post(base + "/api/invite", json={"token": token, "password": "Another-Horse-Battery-9"}).status_code == 404
    r = s.post(base + "/api/login", json={"email": "gopi@beastute.com", "password": "Correct-Horse-Battery-9"})
    assert r.ok and r.json()["next"] == "enroll"                      # straight on to the authenticator app


def test_reset_emails_a_new_link_and_sending_problems_fall_back(env, smtp):
    a, base = env["admin"], env["url"]
    a.put(base + "/api/mail", json={"enabled": True, "host": "smtp.example.com", "port": 587, "user": "",
                                    "from_email": "pegasus@beastute.com"})
    uid = a.post(base + "/api/users", json={"name": "Rujul P", "email": "rujul@beastute.com",
                                            "role": "viewer"}).json()["user"]["id"]
    first, _ = link_in(smtp.sent[-1])
    r = a.post(base + f"/api/users/{uid}/reset-password", json={})
    assert r.json()["emailed"] and smtp.sent[-1]["Subject"] == "Your Pegasus password"
    second, _ = link_in(smtp.sent[-1])
    assert session().get(base + "/api/invite", params={"token": first}).status_code == 404     # replaced
    smtp.fail = mailer.smtplib.SMTPRecipientsRefused({})
    r = a.post(base + f"/api/users/{uid}/reset-password", json={})
    j = r.json()
    assert r.ok and not j.get("emailed") and j["temporary_password"] and "refused to send" in j["email_error"]
    assert session().get(base + "/api/invite", params={"token": second}).status_code == 404    # cancelled
    smtp.fail = None
    r = a.post(base + "/api/users", json={"name": "No Mail", "email": "nomail@beastute.com", "role": "viewer",
                                          "email_link": False})
    assert r.json()["temporary_password"] and not smtp.sent[-1]["To"] == "nomail@beastute.com"


def test_links_expire(env, smtp):
    a, base = env["admin"], env["url"]
    a.put(base + "/api/mail", json={"enabled": True, "host": "smtp.example.com", "port": 587, "user": "",
                                    "from_email": "pegasus@beastute.com"})
    uid = a.post(base + "/api/users", json={"name": "Late Larry", "email": "larry@beastute.com",
                                            "role": "viewer"}).json()["user"]["id"]
    token, _ = link_in(smtp.sent[-1])
    cp.connect().execute("UPDATE users SET invite_expires=? WHERE id=?", (time.time() - 1, uid))
    assert session().get(base + "/api/invite", params={"token": token}).status_code == 404
