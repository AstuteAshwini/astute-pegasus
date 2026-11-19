"""tls.check: read the certificate each listed address serves, from inside the client's network (read-only).

The control plane sends host names and ports only. The connector opens a TLS connection itself, reads the certificate
even when it's expired or not trusted (so the expiry date is always known), then separately checks whether it's
trusted and matches the name, the way a browser would.
"""
import datetime as dt
import ipaddress
import os
import re
import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from .operations import OperationError

HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}[A-Za-z0-9])?)*$")
MAX_ENDPOINTS = 50


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate(step):
    eps = []
    for e in step.get("endpoints") or []:
        host, port = str(e.get("host") or "").strip(), e.get("port", 443)
        try:
            port = int(port)
        except (TypeError, ValueError):
            raise OperationError("ports must be numbers") from None
        if not (HOST.match(host) or is_ip(host)) or not 0 < port < 65536:
            raise OperationError(f"'{host}:{port}' isn't a host name and port")
        eps.append({"host": host, "port": port})
    if not eps or len(eps) > MAX_ENDPOINTS:
        raise OperationError(f"give between 1 and {MAX_ENDPOINTS} addresses to check")
    return {"endpoints": eps}


def _utc(c, attr):
    v = getattr(c, attr + "_utc", None)
    if v is None:
        v = getattr(c, attr).replace(tzinfo=dt.timezone.utc)
    return v


def _name(name, oid):
    a = name.get_attributes_for_oid(oid)
    return a[0].value if a else ""


def describe(der):
    c = x509.load_der_x509_certificate(der)
    try:
        sans = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(
            x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    return {"subject": _name(c.subject, NameOID.COMMON_NAME) or c.subject.rfc4514_string(),
            "issuer": _name(c.issuer, NameOID.ORGANIZATION_NAME) or _name(c.issuer, NameOID.COMMON_NAME)
            or c.issuer.rfc4514_string(),
            "sans": sans[:20], "not_before": _utc(c, "not_valid_before").isoformat(),
            "not_after": _utc(c, "not_valid_after").isoformat(), "serial": format(c.serial_number, "x")}


def trust_context():
    ctx = ssl.create_default_context()
    extra = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    if extra and os.path.isfile(extra):
        ctx.load_verify_locations(cafile=extra)
    return ctx


def fetch(host, port, timeout=10):
    """The certificate the address serves (DER), without judging it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=None if is_ip(host) else host) as s:
            return s.getpeercert(binary_form=True)


def verify(host, port, timeout=10):
    """'' when a browser-style check passes, otherwise the reason it doesn't."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with trust_context().wrap_socket(sock, server_hostname=host):
                return ""
    except ssl.SSLCertVerificationError as e:
        return str(e.verify_message or e)[:200]
    except (ssl.SSLError, OSError) as e:
        return str(e)[:200]


def check_one(host, port, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    r = {"host": host, "port": port}
    try:
        der = fetch(host, port)
    except (OSError, ssl.SSLError) as e:
        r["error"] = f"couldn't connect: {e}"[:300]
        return r
    if not der:
        r["error"] = "the server didn't send a certificate"
        return r
    r.update(describe(der))
    r["days_left"] = int((dt.datetime.fromisoformat(r["not_after"]) - now).total_seconds() // 86400)
    problem = verify(host, port)
    r["trusted"] = not problem
    if problem:
        r["trust_problem"] = problem
    return r


def run(c, out):
    results = []
    for e in c["endpoints"]:
        r = check_one(e["host"], e["port"])
        results.append(r)
        where = f"{e['host']}:{e['port']}"
        if r.get("error"):
            out(f"{where}: {r['error']}\n")
        else:
            note = "" if r["trusted"] else f" (not trusted: {r['trust_problem']})"
            out(f"{where}: {r['subject']} expires {r['not_after'][:10]}, {r['days_left']} days left{note}\n")
    failed = sum(1 for r in results if r.get("error"))
    return (1 if failed == len(results) else 0), {"certs": results}
