"""SSL certificate expiry: the connector reads each listed address's certificate; one ticket per client."""
import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from conftest import drain, wait_job
from pegasus_cloud import app as cp, jira as jiramod
from test_patching import FakeJira, enable_jira


def make_cert(tmp, name, days):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days, hours=12))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name), x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256()))
    cf, kf = f"{tmp}/{name}.crt", f"{tmp}/{name}.key"
    open(cf, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kf, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cf, kf


def tls_server(cf, kf):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cf, kf)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(20)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass
    threading.Thread(target=serve, daemon=True).start()
    return sock, sock.getsockname()[1]


@pytest.fixture(scope="module")
def servers(env):
    soon = tls_server(*make_cert(env["tmp"], "hr.example.edu", 10))
    later = tls_server(*make_cert(env["tmp"], "ib.example.edu", 200))
    yield soon[1], later[1]
    soon[0].close()
    later[0].close()


@pytest.fixture
def fake_jira(env):
    real = jiramod.Jira
    jiramod.Jira = FakeJira
    FakeJira.comments.clear()
    yield FakeJira
    jiramod.Jira = real
    c = cp.connect()
    c.execute("DELETE FROM settings WHERE client_id=? AND key IN ('jira','cert_urls','cert_warn_days','cert_ticket',"
              "'cert_results','cert_state')", (env["cid"],))
    c.commit()
    c.close()


def u(env, path):
    return env["url"] + path.format(cid=env["cid"])


def check(env):
    r = env["admin"].post(u(env, "/api/clients/{cid}/certs/check"), json={})
    assert r.ok, r.text
    drain(env)
    wait_job(env, r.json()["job"])
    with cp.app.app_context():
        cp.run_cert_watch()                  # keeps the ticket in step with the results
    return env["admin"].get(u(env, "/api/clients/{cid}/certs")).json()


def test_parse_cert_url():
    assert cp.parse_cert_url("https://HR.example.edu/psp/ps/?cmd=login") == \
        {"url": "https://HR.example.edu/psp/ps/?cmd=login", "host": "hr.example.edu", "port": 443}
    assert cp.parse_cert_url("ib.example.edu:8443")["port"] == 8443
    assert cp.parse_cert_url("10.0.1.11")["host"] == "10.0.1.11"
    for bad in ("", "https://", "host:99999", "a b c"):
        with pytest.raises(ValueError):
            cp.parse_cert_url(bad)


def test_certificates_are_checked_and_one_ticket_tracks_them(env, servers, fake_jira):
    soon, later = servers
    a = env["admin"]
    assert a.put(u(env, "/api/clients/{cid}/certs"), json={"urls": "not an address at all"}).status_code == 400
    r = a.put(u(env, "/api/clients/{cid}/certs"),
              json={"urls": f"https://localhost:{soon}/psp/ps\n127.0.0.1:{later}\n\nlocalhost:{soon}"})
    assert r.ok and len(r.json()["urls"]) == 2          # the duplicate address is dropped

    v = check(env)                                       # Jira is off: results only, no ticket
    by = {c["port"]: c for c in v["certs"]}
    assert by[soon]["subject"] == "hr.example.edu" and by[soon]["days_left"] == 10
    assert by[soon]["trusted"] is False                  # self-signed, but the expiry is still read
    assert by[later]["days_left"] == 200 and v["ticket"] is None

    enable_jira(env)
    v = check(env)
    key = v["ticket"]["key"]
    t = FakeJira.tickets[key]
    assert "hr.example.edu" in t["description"] and "ib.example.edu" not in t["description"]
    assert "10 days left" in t["description"]

    v = check(env)                                       # nothing new: no comment, same ticket
    assert v["ticket"]["key"] == key and not [c for c in FakeJira.comments if c[0] == key]

    assert a.put(u(env, "/api/clients/{cid}/certs"), json={"warn_days": 365}).ok
    v = check(env)                                       # the second one now comes due: comment, not a new ticket
    assert v["ticket"]["key"] == key
    note = [c for c in FakeJira.comments if c[0] == key][-1][1]
    assert "1 more certificate" in note and "ib.example.edu" in note and "Still to renew: 2" in note

    assert a.put(u(env, "/api/clients/{cid}/certs"), json={"warn_days": 5}).ok
    v = check(env)                                       # none within the window: closing comment, ticket cleared
    assert v["ticket"] is None
    assert "Closing" in [c for c in FakeJira.comments if c[0] == key][-1][1]

    a.put(u(env, "/api/clients/{cid}/certs"), json={"warn_days": 30})
    FakeJira.tickets[key]["state"] = "approved"
    v = check(env)                                       # comes due again: a fresh ticket
    assert v["ticket"]["key"] != key


def test_unreachable_address_is_reported(env, fake_jira):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                            # nothing listens here
    assert env["admin"].put(u(env, "/api/clients/{cid}/certs"), json={"urls": [f"127.0.0.1:{port}"]}).ok
    v = check(env)
    assert v["certs"][0]["error"].startswith("couldn't connect")
