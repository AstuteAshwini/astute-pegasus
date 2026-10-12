"""Signed job protocol shared by the Pegasus control plane and the connector.

The control plane signs every job with its Ed25519 key. The connector learns the matching public key once, when it
registers, and refuses any job whose signature, connector, or validity window doesn't check out. A compromised or
spoofed control plane therefore can't hand the connector work it didn't sign, and even signed work is limited to the
operations the connector itself allows (see operations.py and the local policy).

control-plane/pegasus_cloud/protocol.py is a copy of this file; tests check the two stay identical.
"""
import base64
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
