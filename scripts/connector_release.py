"""Build and sign a connector release, and manage the release key.

  python scripts/connector_release.py keygen            # once: create the release key, add its public key to the code
  python scripts/connector_release.py build             # each release: sign connector/pegasus_connector as a bundle
  python scripts/connector_release.py list

The release key is what connectors trust for updates, so keep it off the control plane: on the machine that builds
releases only, with a backup somewhere safe (a password manager or an offline drive). Its default place is
~/.pegasus-release/release_key.pem, or set PEGASUS_RELEASE_KEY.

`build` writes PEGASUS_DATA/releases/<version>/ (default control-plane/data/releases/), which the control plane
offers to connectors. Bump __version__ in connector/pegasus_connector/__init__.py before each build: a version can
only be released once, and connectors only take versions newer than their own.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "connector" / "pegasus_connector"
KEYS_FILE = PKG / "release_keys.py"
sys.path.insert(0, str(ROOT / "connector"))

from pegasus_connector import protocol  # noqa: E402

REQUIRES = ["requests", "paramiko", "cryptography"]
MIN_PYTHON = "3.8"
FIXED_TIME = (2020, 1, 1, 0, 0, 0)          # zip entries get a fixed date so the same code gives the same bundle


def key_path(arg):
    return Path(arg or os.environ.get("PEGASUS_RELEASE_KEY") or Path.home() / ".pegasus-release" / "release_key.pem")


def data_dir(arg):
    return Path(arg or os.environ.get("PEGASUS_DATA") or ROOT / "control-plane" / "data")


def built_in_keys():
    ns = {}
    exec(KEYS_FILE.read_text(encoding="utf-8"), ns)
    return list(ns["RELEASE_KEYS"])


def write_keys(keys):
    text = KEYS_FILE.read_text(encoding="utf-8")
    body = "RELEASE_KEYS = [\n" + "".join(f'    "{k}",\n' for k in keys) + "]\n"
    text = re.sub(r"RELEASE_KEYS = \[.*?\]\n", body, text, flags=re.S)
    KEYS_FILE.write_text(text, encoding="utf-8")


def load_key(path):
    if not path.exists():
        sys.exit(f"No release key at {path}. Create one with: python scripts/connector_release.py keygen")
    return protocol.load_private_key(path.read_text())


def keygen(a):
    path = key_path(a.key)
    if path.exists():
        sys.exit(f"{path} already exists. Pegasus won't overwrite a release key.")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = protocol.new_private_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(protocol.private_key_pem(key))
    pub = protocol.public_key_b64(key)
    keys = built_in_keys()
    if pub not in keys:
        write_keys(keys + [pub])
    print(f"Created the release key: {path}")
    print(f"Fingerprint: {protocol.fingerprint(pub)}")
    print(f"Added its public key to {KEYS_FILE.relative_to(ROOT)}.")
    print("Back up the key file somewhere safe, commit release_keys.py, and update each connector by hand once")
    print("(git pull) so it carries the key. From then on, connectors can update themselves.")


def package_files():
    files = {}
    for p in sorted(PKG.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        files["pegasus_connector/" + p.relative_to(PKG).as_posix()] = p.read_bytes()
    return files


def version_of():
    m = re.search(r'__version__\s*=\s*"([^"]+)"', (PKG / "__init__.py").read_text(encoding="utf-8"))
    return m.group(1)


def build_release(key, data, version, files, notes=""):
    """Sign files ({"pegasus_connector/x.py": bytes}) as release <version> in <data>/releases/. Returns its folder."""
    pub = protocol.public_key_b64(key)
    protocol.version_tuple(version)
    out = Path(data) / "releases" / version
    if out.exists():
        raise FileExistsError(f"Release {version} already exists in {out.parent}. Bump __version__ in "
                              f"{(PKG / '__init__.py').relative_to(ROOT)} first.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in sorted(files.items()):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, content)
    bundle = buf.getvalue()
    manifest = {"product": "pegasus-connector", "version": version,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "files": {n: hashlib.sha256(c).hexdigest() for n, c in files.items()},
                "bundle_sha256": hashlib.sha256(bundle).hexdigest(), "requires": REQUIRES,
                "min_python": MIN_PYTHON, "notes": notes or ""}
    env = {"manifest": manifest, "signature": protocol.sign_release(key, manifest), "key": pub}
    protocol.verify_release(manifest, env["signature"], [pub])
    tmp = out.with_name("." + version + ".tmp")
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "bundle.zip").write_bytes(bundle)
    (tmp / "release.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    os.replace(tmp, out)
    return out


def build(a):
    key = load_key(key_path(a.key))
    pub = protocol.public_key_b64(key)
    if pub not in built_in_keys():
        sys.exit("This release key isn't in release_keys.py, so connectors running this code wouldn't accept the "
                 "next release. Add it (keygen does this) before building.")
    version, files = version_of(), package_files()
    try:
        out = build_release(key, data_dir(a.data), version, files, a.notes)
    except (FileExistsError, ValueError) as e:
        sys.exit(str(e))
    size = (out / "bundle.zip").stat().st_size
    print(f"Built connector release {version}: {len(files)} files, {size // 1024} KB, signed with "
          f"{protocol.fingerprint(pub)}")
    print(f"Saved to {out}. The control plane offers it to connectors straight away (no restart needed).")


def list_releases(a):
    d = data_dir(a.data) / "releases"
    if not d.is_dir():
        print("No releases yet.")
        return
    for r in sorted(p for p in d.iterdir() if p.is_dir() and not p.name.startswith(".")):
        env = json.loads((r / "release.json").read_text(encoding="utf-8"))
        print(f"{r.name:10} {env['manifest'].get('created_at', '')}  key {protocol.fingerprint(env['key'])}  "
              f"{env['manifest'].get('notes', '')}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Pegasus connector releases")
    p.add_argument("--key", help="release key file (default ~/.pegasus-release/release_key.pem)")
    p.add_argument("--data", help="control plane data folder (default PEGASUS_DATA or control-plane/data)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("keygen", help="create the release key and add its public key to release_keys.py")
    b = sub.add_parser("build", help="sign the current connector code as a release")
    b.add_argument("--notes", help="a line about what changed, shown in Pegasus")
    sub.add_parser("list", help="list the releases in the data folder")
    a = p.parse_args(argv)
    {"keygen": keygen, "build": build, "list": list_releases}[a.cmd](a)


if __name__ == "__main__":
    main()
