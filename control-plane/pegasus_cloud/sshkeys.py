"""OpenSSH public key checks for the SSH access register. The connector checks every key again before using it."""
import base64
import hashlib
import re

KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
PUBKEY_RE = re.compile(r"^(\S+) ([A-Za-z0-9+/]+={0,3})(?: (.*))?$")


def parse(text):
    """(key dict, None) or (None, error)."""
    text = str(text or "").replace("\r", "").strip()
    if "PRIVATE KEY" in text:
        return None, "That's a private key. Never share it. Ask the person for their public key (the .pub file)."
    lines = [l.strip() for l in text.split("\n") if l.strip() and not l.strip().startswith("#")]
    if not lines:
        return None, "Paste the public key, or choose the .pub file."
    if lines[0].startswith("---- BEGIN SSH2 PUBLIC KEY"):
        return None, ("That's a PuTTY/SSH2-format key. Convert it to OpenSSH format first: in PuTTYgen, load the key "
                      "and copy the box 'Public key for pasting into OpenSSH authorized_keys file'.")
    if len(lines) > 1:
        joined = "".join(lines)
        if PUBKEY_RE.match(lines[0]) and not PUBKEY_RE.match(joined):
            return None, "Paste one key at a time."
        lines = [joined]
    if re.match(r"^(from|command|environment|permitopen|permitlisten|principals|tunnel|no-|restrict|cert-authority)",
                lines[0]):
        return None, "Paste the key without authorized_keys options (from=, command= and so on)."
    m = PUBKEY_RE.match(re.sub(r"\s+", " ", lines[0]))
    if not m:
        return None, "That doesn't look like an OpenSSH public key (it should start with ssh-ed25519, ssh-rsa or ecdsa-)."
    kind, b64, comment = m.group(1), m.group(2), (m.group(3) or "").strip()
    if kind not in KEY_TYPES:
        return None, f"'{kind[:40]}' isn't a supported key type. Use ssh-ed25519, ssh-rsa or ecdsa."
    try:
        blob = base64.b64decode(b64, validate=True)
        parts, i = [], 0
        while i < len(blob):
            n = int.from_bytes(blob[i:i + 4], "big")
            if len(blob[i:i + 4]) < 4 or i + 4 + n > len(blob):
                raise ValueError
            parts.append(blob[i + 4:i + 4 + n])
            i += 4 + n
        need = {"ssh-ed25519": 2, "ssh-rsa": 3, "sk-ssh-ed25519@openssh.com": 3}.get(kind, 3)
        if not parts or parts[0].decode() != kind or len(parts) < need or (kind == "ssh-ed25519" and len(parts[1]) != 32):
            raise ValueError
    except Exception:
        return None, "The key data is damaged (it may have been cut short when it was copied)."
    bits = None
    if kind == "ssh-rsa":
        bits = int.from_bytes(parts[2], "big").bit_length()
        if bits < 2048:
            return None, f"That RSA key is only {bits} bits. Ask for an ed25519 key, or RSA of at least 2048 bits."
    comment = re.sub(r"[^\x20-\x7e]", "", comment)[:120]
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    line = f"{kind} {b64}" + (f" {comment}" if comment else "")
    return {"type": kind, "bits": bits, "comment": comment, "fingerprint": fp, "body": b64, "line": line}, None
