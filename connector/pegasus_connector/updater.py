"""Signed connector updates, and the supervisor that runs the newest verified version.

How an update gets in:
1. The control plane offers a version in its heartbeat reply (only when the client's update setting allows it, and
   only when the release is newer than what this connector runs).
2. The connector waits until no job is running, then downloads the release's manifest and bundle. The manifest must
   be signed by a key in release_keys.py (built into this code, not supplied by the control plane), name this
   product, be newer than the running version, and list every file with its SHA-256. The bundle must contain exactly
   those files, each matching. Python packages the release needs must already be installed here.
3. The files go into versions/<version>/ next to config.json, and the connector exits with RESTART.

How it runs: `run` starts as a supervisor. It looks for the newest version under versions/ that is newer than its
own code and still verifies (signature and every file's hash, checked again at each start), and runs it as a child
process. If that version exits before it ever reaches the control plane, it's marked bad and the supervisor goes
back to the version before it. A git pull that brings newer code than anything installed simply wins.

Nothing is ever changed in place: the code the connector was installed with is left alone.
"""
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from . import __version__, protocol
from .release_keys import RELEASE_KEYS

PRODUCT = "pegasus-connector"
RESTART = 75                       # exit code: an update is installed, start the newest version
KEEP = 3                           # installed versions kept
MAX_BUNDLE = 20 * 1024 * 1024
SAFE_FILE = re.compile(r"^pegasus_connector/[A-Za-z0-9_]+(/[A-Za-z0-9_]+)*\.py$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_MODULE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")


class UpdateError(Exception):
    pass


def versions_dir(config_path):
    return Path(config_path).parent / "versions"


def newer(a, b):
    return protocol.version_tuple(a) > protocol.version_tuple(b)


def check_manifest(m, version=None):
    if not isinstance(m, dict) or m.get("product") != PRODUCT:
        raise UpdateError("that isn't a Pegasus connector release")
    try:
        protocol.version_tuple(m.get("version"))
    except ValueError as e:
        raise UpdateError(str(e))
    if version is not None and m["version"] != version:
        raise UpdateError(f"the release is {m['version']}, not the {version} that was offered")
    files = m.get("files")
    if not isinstance(files, dict) or "pegasus_connector/__init__.py" not in files:
        raise UpdateError("the release doesn't list its files")
    for path, digest in files.items():
        if not SAFE_FILE.match(path) or ".." in path or not SHA256.match(str(digest)):
            raise UpdateError(f"the release lists a file Pegasus won't install: {path!r}")
    if not SHA256.match(str(m.get("bundle_sha256"))):
        raise UpdateError("the release has no bundle checksum")
    need = m.get("min_python") or "3.8"
    try:
        if sys.version_info[:2] < protocol.version_tuple(need)[:2]:
            raise UpdateError(f"the release needs Python {need} or newer; this machine has "
                              f"{sys.version_info.major}.{sys.version_info.minor}")
    except ValueError:
        raise UpdateError("the release names an invalid Python version")
    missing = []
    for mod in m.get("requires") or []:
        if not SAFE_MODULE.match(str(mod)):
            raise UpdateError(f"the release needs an oddly named package: {mod!r}")
        if importlib.util.find_spec(mod) is None:
            missing.append(mod)
    if missing:
        raise UpdateError(f"the release needs the Python package(s) {', '.join(missing)}; install them on this machine "
                          f"first (python -m pip install {' '.join(missing)})")
    return m


def verify_envelope(env, version=None, keys=None):
    """The manifest from a release.json envelope, if it's properly signed and acceptable here."""
    keys = RELEASE_KEYS if keys is None else keys
    if not keys:
        raise UpdateError("this connector has no Astute release key built in, so it accepts no updates")
    if not isinstance(env, dict):
        raise UpdateError("the release description is malformed")
    try:
        protocol.verify_release(env.get("manifest"), env.get("signature"), keys)
    except (ValueError, TypeError, AttributeError) as e:
        raise UpdateError(str(e))
    return check_manifest(env["manifest"], version)


def install(get, config_path, version, current=__version__, keys=None):
    """Download, verify and unpack a release into versions/<version>/. Returns that folder."""
    try:
        if not newer(version, current):
            raise UpdateError(f"{version} isn't newer than the running {current}")
    except ValueError as e:
        raise UpdateError(str(e))
    r = get(f"/releases/{version}/release")
    if r.status_code != 200:
        raise UpdateError(f"couldn't get the release description ({r.status_code})")
    env = r.json()
    m = verify_envelope(env, version, keys)
    r = get(f"/releases/{version}/bundle", timeout=120)
    if r.status_code != 200:
        raise UpdateError(f"couldn't download the release ({r.status_code})")
    data = r.content
    if len(data) > MAX_BUNDLE:
        raise UpdateError("the release is too large")
    if hashlib.sha256(data).hexdigest() != m["bundle_sha256"]:
        raise UpdateError("the downloaded release doesn't match its signed checksum")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = [i.filename for i in zf.infolist() if not i.is_dir()]
    except zipfile.BadZipFile:
        raise UpdateError("the downloaded release isn't a valid zip")
    if len(names) != len(set(names)) or set(names) != set(m["files"]):
        raise UpdateError("the release's files don't match its signed list")
    root = versions_dir(config_path)
    root.mkdir(parents=True, exist_ok=True)
    tmp, target = root / f".{version}.tmp", root / version
    shutil.rmtree(tmp, ignore_errors=True)
    for name in names:
        content = zf.read(name)
        if hashlib.sha256(content).hexdigest() != m["files"][name]:
            raise UpdateError(f"{name} doesn't match its signed checksum")
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    (tmp / "release.json").write_text(json.dumps(env), encoding="utf-8")
    shutil.rmtree(target, ignore_errors=True)            # an earlier, failed attempt at the same version
    os.replace(tmp, target)
    prune(root)
    return target


def verify_installed(d, keys=None):
    """Raise UpdateError unless versions/<v>/ still holds exactly the signed release."""
    try:
        env = json.loads((d / "release.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise UpdateError("its release description is missing")
    m = verify_envelope(env, d.name, keys)
    for path, digest in m["files"].items():
        try:
            if hashlib.sha256((d / path).read_bytes()).hexdigest() != digest:
                raise UpdateError(f"{path} has been changed")
        except OSError:
            raise UpdateError(f"{path} is missing")
    extra = {str(p.relative_to(d)).replace(os.sep, "/") for p in (d / "pegasus_connector").rglob("*.py")} - set(m["files"])
    if extra:
        raise UpdateError(f"it has files that aren't part of the release: {', '.join(sorted(extra))}")
    return m


def installed(config_path):
    """[(version tuple, folder)] for every installed version not marked bad, newest first."""
    root = versions_dir(config_path)
    out = []
    if root.is_dir():
        for d in root.iterdir():
            if d.is_dir() and not d.name.startswith(".") and not (d / "BAD").exists():
                try:
                    out.append((protocol.version_tuple(d.name), d))
                except ValueError:
                    continue
    return sorted(out, reverse=True)


def best_installed(config_path, current=__version__, keys=None, log=print):
    """The newest installed version that is newer than the running code and still verifies, or None."""
    for vt, d in installed(config_path):
        if vt <= protocol.version_tuple(current):
            return None
        try:
            verify_installed(d, keys)
            return d
        except UpdateError as e:
            mark_bad(d, f"failed verification at start: {e}")
            log(f"Not using installed version {d.name}: {e}")
    return None


def mark_bad(d, reason):
    try:
        (d / "BAD").write_text(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {reason}\n", encoding="utf-8")
    except OSError:
        pass


def confirm():
    """Called by a version running under a supervisor once it has reached the control plane."""
    d = os.environ.get("PEGASUS_VERSION_DIR")
    if d:
        try:
            (Path(d) / "CONFIRMED").touch()
        except OSError:
            pass


def prune(root, keep=KEEP):
    vs = []
    for d in root.iterdir():
        if d.is_dir() and not d.name.startswith("."):
            try:
                vs.append((protocol.version_tuple(d.name), d))
            except ValueError:
                continue
    for _, d in sorted(vs, reverse=True)[keep:]:
        shutil.rmtree(d, ignore_errors=True)


def supervise(config_path, run_in_process, log=print, sleep=time.sleep, popen=subprocess.Popen):
    """Run the newest verified version: an installed update as a child process, else this code in-process."""
    while True:
        d = best_installed(config_path, log=log)
        if d is None:
            code = run_in_process()
            if code == RESTART:
                continue
            return code
        log(f"Starting connector {d.name} (installed update)")
        (d / "CONFIRMED").unlink(missing_ok=True)
        env = dict(os.environ, PEGASUS_VERSION_DIR=str(d))
        p = popen([sys.executable, "-m", "pegasus_connector", "--config", str(config_path), "run", "--child"],
                  cwd=str(d), env=env)
        try:
            code = p.wait()
        except KeyboardInterrupt:
            try:
                code = p.wait(timeout=30)
            except Exception:
                p.kill()
            return 0
        if code == RESTART:
            continue
        if code in (0, 2):
            return code
        if not (d / "CONFIRMED").exists():
            mark_bad(d, f"exited with code {code} before it reached the control plane")
            log(f"Connector {d.name} stopped (code {code}) before it reached the control plane. "
                "It's marked bad; going back to the previous version.")
            continue
        log(f"Connector {d.name} stopped (code {code}). Starting it again in 10 seconds.")
        sleep(10)
