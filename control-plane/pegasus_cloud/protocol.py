"""Signed job protocol shared by the Pegasus control plane and the connector.

The control plane signs every job with its Ed25519 key. The connector learns the matching public key once, when it
registers, and refuses any job whose signature, connector, or validity window doesn't check out. A compromised or
spoofed control plane therefore can't hand the connector work it didn't sign, and even signed work is limited to the
operations the connector itself allows (see operations.py and the local policy).

The same key also issues each connector's certificate: a short document binding the connector's own Ed25519 public
key to its id, client and validity window. The connector signs every request it makes with its private key (which
never leaves the machine), so no shared secret travels over the wire and a captured request can't be replayed.

Connector releases are signed with a separate release key that Astute keeps offline; connectors carry its public
key in their code (release_keys.py), so the control plane can hand out releases but can't forge one.

control-plane/pegasus_cloud/protocol.py is a copy of this file; tests check the two stay identical.
"""
import base64
import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PROTOCOL_VERSION = 1
JOB_FIELDS = ("v", "id", "tenant", "connector", "op", "params", "issued_at", "expires_at")
MAX_CLOCK_SKEW = 120        # seconds a job may appear to be issued in the future


def canonical(job):
    """The exact bytes that are signed: the job fields only, keys sorted, no whitespace."""
    return json.dumps({k: job[k] for k in JOB_FIELDS}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def new_private_key():
    return Ed25519PrivateKey.generate()


def private_key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def load_private_key(pem):
    return serialization.load_pem_private_key(pem.encode(), password=None)


def public_key_b64(key):
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def fingerprint(public_b64):
    """Short, human-comparable form of the signing key (shown on both sides at registration)."""
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(public_b64)).digest()).decode().rstrip("=")[:22]


def sign(job, private_key):
    return base64.b64encode(private_key.sign(canonical(job))).decode()


def verify(job, signature, public_b64, connector_id, now=None):
    """Raise ValueError with a plain reason if the job must not run."""
    now = now or time.time()
    if not isinstance(job, dict) or any(k not in job for k in JOB_FIELDS):
        raise ValueError("job is missing required fields")
    if job["v"] != PROTOCOL_VERSION:
        raise ValueError(f"unsupported protocol version {job['v']}")
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(
            base64.b64decode(signature or ""), canonical(job))
    except (InvalidSignature, ValueError, TypeError):
        raise ValueError("signature doesn't match the control plane's key")
    if job["connector"] != connector_id:
        raise ValueError("job was issued to a different connector")
    if job["issued_at"] > now + MAX_CLOCK_SKEW:
        raise ValueError("job is dated in the future (check this machine's clock)")
    if job["expires_at"] < now:
        raise ValueError("job has expired")


# ---------------------------------------------------------------- connector certificates
CERT_VERSION = 1
CERT_FIELDS = ("v", "serial", "connector", "tenant", "public_key", "not_before", "not_after")
CERT_DAYS = 90              # a certificate is valid this long
RENEW_DAYS = 60             # the connector renews once fewer than this many days are left (so about monthly)
REQUEST_SKEW = 300          # seconds a signed request may be early or late
_CERT_TAG = b"pegasus-cert-v1\n"
_REQ_TAG = b"pegasus-request-v1\n"
_REL_TAG = b"pegasus-release-v1\n"


def public_key_of(private_key):
    return public_key_b64(private_key)


def check_public_key(public_b64):
    """The raw Ed25519 public key as base64, or ValueError."""
    try:
        raw = base64.b64decode(str(public_b64), validate=True)
        Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError):
        raise ValueError("not an Ed25519 public key")
    return base64.b64encode(raw).decode()


def _verify(public_b64, signature, message):
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64)).verify(
            base64.b64decode(signature or ""), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def cert_canonical(cert):
    return _CERT_TAG + json.dumps({k: cert[k] for k in CERT_FIELDS}, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True).encode()


def issue_cert(signing_private_key, connector_id, tenant, public_b64, serial, now=None, days=CERT_DAYS):
    now = int(now or time.time())
    cert = {"v": CERT_VERSION, "serial": serial, "connector": connector_id, "tenant": tenant,
            "public_key": check_public_key(public_b64), "not_before": now - 60, "not_after": now + days * 86400}
    return cert, base64.b64encode(signing_private_key.sign(cert_canonical(cert))).decode()


def verify_cert(cert, signature, signing_public_b64, now=None):
    """Raise ValueError if the certificate wasn't issued by this control plane or isn't valid now."""
    now = now or time.time()
    if not isinstance(cert, dict) or any(k not in cert for k in CERT_FIELDS) or cert["v"] != CERT_VERSION:
        raise ValueError("certificate is malformed")
    if not _verify(signing_public_b64, signature, cert_canonical(cert)):
        raise ValueError("certificate isn't signed by the control plane's key")
    if cert["not_before"] > now + MAX_CLOCK_SKEW:
        raise ValueError("certificate isn't valid yet (check this machine's clock)")
    if cert["not_after"] < now:
        raise ValueError("certificate has expired")


def request_message(method, path, timestamp, nonce, body):
    """What a connector signs for one HTTP request: method, path with query, time, a one-off nonce, the body's hash."""
    return _REQ_TAG + "\n".join([method.upper(), path, str(timestamp), nonce,
                                 hashlib.sha256(body or b"").hexdigest()]).encode()


def sign_request(private_key, method, path, body, timestamp=None, nonce=None):
    """Headers for a signed request."""
    import secrets
    timestamp = int(timestamp or time.time())
    nonce = nonce or secrets.token_urlsafe(16)
    sig = base64.b64encode(private_key.sign(request_message(method, path, timestamp, nonce, body))).decode()
    return {"X-Pegasus-Timestamp": str(timestamp), "X-Pegasus-Nonce": nonce, "X-Pegasus-Signature": sig}


def verify_request(public_b64, method, path, body, timestamp, nonce, signature, now=None):
    """Raise ValueError if a signed request doesn't check out. (Nonce reuse is checked by the caller.)"""
    now = now or time.time()
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        raise ValueError("request has no valid timestamp")
    if abs(now - ts) > REQUEST_SKEW:
        raise ValueError("request time is too far from the control plane's clock (check the connector's clock)")
    if not nonce or len(nonce) > 64:
        raise ValueError("request has no valid nonce")
    if not _verify(public_b64, signature, request_message(method, path, ts, nonce, body)):
        raise ValueError("request signature doesn't match the connector's certificate")


# ---------------------------------------------------------------- connector releases
def version_tuple(v):
    """'0.3.10' -> (0, 3, 10). ValueError for anything else."""
    parts = str(v).split(".")
    if not 1 <= len(parts) <= 4 or not all(p.isdigit() and len(p) <= 6 for p in parts):
        raise ValueError(f"not a version number: {v!r}")
    return tuple(int(p) for p in parts)


def release_canonical(manifest):
    return _REL_TAG + json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sign_release(release_private_key, manifest):
    return base64.b64encode(release_private_key.sign(release_canonical(manifest))).decode()


def verify_release(manifest, signature, trusted_public_keys):
    """The public key that signed the manifest, if it's one of the trusted keys; else ValueError."""
    for k in trusted_public_keys or ():
        if _verify(k, signature, release_canonical(manifest)):
            return k
    raise ValueError("release isn't signed by a trusted Astute release key")
