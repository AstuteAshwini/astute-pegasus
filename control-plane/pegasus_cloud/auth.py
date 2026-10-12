"""Sign-in building blocks: password hashing, TOTP multi-factor codes, recovery codes, and encryption of the secrets
the control plane has to keep (Jira API tokens).

No extra dependencies: scrypt and HMAC come from the standard library, encryption from `cryptography`'s Fernet.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken

ROLES = ("admin", "operator", "viewer")
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}
MIN_PASSWORD = 12
EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$")


# ---------------------------------------------------------------- passwords
def hash_password(pw):
    salt = os.urandom(16)
    n, r, p = 2 ** 14, 8, 1
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"


def check_password(pw, stored):
    try:
        kind, n, r, p, salt, h = (stored or "").split("$")
        if kind != "scrypt":
            return False
        got = hashlib.scrypt(str(pw).encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(got, base64.b64decode(h))
    except (ValueError, TypeError):
        return False


def password_problem(pw, email="", name=""):
    pw = str(pw or "")
    if len(pw) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if len(pw) > 200:
        return "That password is too long."
    low = pw.lower()
    for part in (email.split("@")[0] if email else "", name):
        if part and len(part) >= 4 and part.lower() in low:
            return "Don't include your name or email in the password."
    if len(set(pw)) < 6:
        return "That password repeats too few characters."
    return None


def temporary_password():
    words = secrets.token_urlsafe(12).replace("-", "x").replace("_", "y")
    return f"{words[:6]}-{words[6:12]}-{words[12:16]}"


# ---------------------------------------------------------------- TOTP (RFC 6238, the codes authenticator apps show)
def new_totp_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def totp_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def totp_now(secret, at=None):
    return totp_at(secret, int((at or time.time()) // 30))


def verify_totp(secret, code, last_step=0, at=None):
    """The time step the code matched (one step of clock drift either way), or None. A step at or before `last_step`
    was already used and is refused, so a code can't be replayed."""
    code = re.sub(r"\s", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code) or not secret:
        return None
    now = int((at or time.time()) // 30)
    for step in (now - 1, now, now + 1):
        if step > (last_step or 0) and hmac.compare_digest(totp_at(secret, step), code):
            return step
    return None


def otpauth_uri(secret, email, issuer="Pegasus"):
    return (f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits=6&period=30")


def new_recovery_codes(n=10):
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]
    return codes, [hashlib.sha256(c.encode()).hexdigest() for c in codes]


def use_recovery_code(code, hashes):
    """Remaining hashes if the code matched one (it's used up), else None."""
    h = hashlib.sha256(re.sub(r"\s", "", str(code or "")).lower().encode()).hexdigest()
    if h in hashes:
        return [x for x in hashes if x != h]
    return None


# ---------------------------------------------------------------- encryption of stored secrets
class SecretBox:
    """Encrypts secrets at rest with a key kept beside the database (PEGASUS_DATA/secret.key, owner-only).
    In production the key belongs in OCI Vault; set PEGASUS_SECRET_KEY to supply it from there."""

    def __init__(self, key_path):
        key = os.environ.get("PEGASUS_SECRET_KEY", "").encode()
        if not key:
            if key_path.exists():
                key = key_path.read_bytes().strip()
            else:
                key_path.parent.mkdir(parents=True, exist_ok=True)
                key = Fernet.generate_key()
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(key)
        self.f = Fernet(key)

    def seal(self, text):
        return self.f.encrypt(str(text).encode()).decode() if text else ""

    def open(self, token):
        if not token:
            return ""
        try:
            return self.f.decrypt(token.encode()).decode()
        except InvalidToken:
            return ""
