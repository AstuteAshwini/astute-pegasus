"""Oracle sources the connector reads on the client's behalf: My Oracle Support (latest patches and every download,
the JDK included) and Oracle's public Java releases service (which JDK release is the latest, no download).

These calls run on the connector, inside the client's network, with the client's own Oracle Support account. The
account is saved only on the connector (oracle.json next to config.json, readable by its owner only); the control
plane never sees it. Downloaded patches stay in the connector's cache and are copied to the servers over SSH.
"""
import base64
import datetime as dt
import hashlib
import html as htmlmod
import json
import os
import re
import tarfile
import time
import zipfile
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

import requests

JAVA_API = os.environ.get("PEGASUS_JAVA_API", "https://java.oraclecloud.com")
MOS_BASE = os.environ.get("PEGASUS_MOS_BASE", "https://updates.oracle.com")
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MON_NUM = {m.upper(): i + 1 for i, m in enumerate(MONTHS)}
CATALOG_TTL = 12 * 3600
JDK_PLATFORM = "226P"          # Linux x86-64
# ARU product ids to narrow the JDK patch search, if the plain description search ever stops finding it
JAVA_PRODUCTS = [p.strip() for p in os.environ.get("PEGASUS_MOS_JAVA_PRODUCTS", "").split(",") if p.strip()]

# Product searches (Patches & Updates > Product or Family), one per component.
MOS_PRODUCTS = {
    "weblogic": {"product": "15991", "release": "600000000159803", "plat": "2000P"},   # WebLogic Server 14.1.2.0.0
    "tuxedo": {"product": "16021", "release": "600000000183513", "plat": "226P"},      # Tuxedo 22.1.0.0.0
    "peopletools": {"product": "21918", "release": "600000000214961", "plat": "226P"}, # PeopleTools 8.62
    "dbclient": {"product": "9480", "release": "600000000101150", "plat": "226P"},     # Oracle Database 19c
}


class MOSError(Exception):
    pass


# ---------------------------------------------------------------- local Oracle credentials
def secrets_path(config_path):
    return Path(config_path).parent / "oracle.json"


def load_secrets(config_path):
    try:
        return json.loads(secrets_path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_secrets(config_path, data):
    p = secrets_path(config_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    if os.name != "nt":
        os.chmod(tmp, 0o600)
    os.replace(tmp, p)


# ---------------------------------------------------------------- My Oracle Support
class MOSClient:
    """Signs in to updates.oracle.com with HTTP Basic auth (the same flow as Oracle's wget scripts)."""
    LINK_RE = r"""https://[^"'\s<>]+?Download/process_form/[^"'\s<>]+?\.zip[^"'\s<>]*"""
    # Oracle's patch page may also write the link relative, or only as "<file>.zip?...&patch_file=<file>.zip"
    # inside a script, with no host or path in front of it
    BARE_LINK_RE = r"""(?:/Orion/Download/process_form/)?([A-Za-z0-9_.\-]+\.zip)\?([^"'\s<>]*\bpatch_file=[^"'\s<>]+)"""

    def __init__(self, user, password, base=None):
        self.BASE = (base or MOS_BASE).rstrip("/")
        self.user = user
        self.s = requests.Session()
        self.s.headers["User-Agent"] = "Mozilla/5.0 (Pegasus connector patch downloader)"
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    def get(self, url, stream=False, timeout=60):
        for _ in range(20):
            headers = {"Authorization": self.auth} if self.sends_auth_to(urlparse(url).hostname or "") else {}
            r = self.s.get(url, headers=headers, allow_redirects=False, stream=stream, timeout=timeout)
            if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                url = urljoin(url, r.headers["Location"])
                r.close()
                continue
            return r
        raise MOSError("Oracle Support kept redirecting; the sign-in flow may have changed.")

    def sends_auth_to(self, host):
        # credentials only ever go to Oracle's own hosts (or the configured base), never to a CDN a download
        # redirects to
        return host == "oracle.com" or host.endswith(".oracle.com") or host == urlparse(self.BASE).hostname

    def has_auth_cookie(self):
        return any(c.name == "Oracle_updates_auth" for c in self.s.cookies)

    def login(self):
        r = self.get(self.BASE + "/Orion/Services/download")
        r.close()
        if r.status_code == 401:
            raise MOSError("Oracle Support rejected the user name or password.")
        if not self.has_auth_cookie():
            r = self.get(self.BASE + "/Orion/SavedSearches/switch_to_simple")
            r.close()
        if not self.has_auth_cookie():
            raise MOSError("Signed in, but Oracle Support didn't issue a download session. Check that the account "
                           "has a support identifier (CSI) with download rights, or sign in to updates.oracle.com in "
                           "a browser once to accept any pending terms.")

    def find_files(self, patch, platform, file_filter=""):
        url = (f"{self.BASE}/Orion/SimpleSearch/process_form?search_type=patch"
               f"&patch_number={patch}&plat_lang={platform}")
        r = self.get(url)
        page = r.text
        if r.status_code == 401 or "login.oracle.com" in r.url:
            raise MOSError("The Oracle Support session expired. Sign in again.")
        links = self.download_links(page)
        if not links:   # multi-part patches list their files on a details page
            for d in re.findall(r"/Orion/PatchDetails/process_form[^\"'\s]+", page):
                links += self.download_links(self.get(self.BASE + htmlmod.unescape(d)).text)
        files = {}
        for link in links:
            name = link.split("process_form/")[1].split("?")[0]
            if file_filter and not re.search(file_filter, name):
                continue
            files[name] = link
        return sorted(files.items())

    def download_links(self, page):
        """Every patch file download URL on an Oracle Support page, made absolute and unescaped."""
        page = htmlmod.unescape(page)
        links = [htmlmod.unescape(u) for u in re.findall(self.LINK_RE, page)]
        if not links:
            for name, query in re.findall(self.BARE_LINK_RE, page):
                links.append(f"{self.BASE}/Orion/Download/process_form/{name}?{query}")
        return list(dict.fromkeys(links))

    def download(self, url, dest, log):
        part = Path(str(dest) + ".part")
        r = self.get(url, stream=True, timeout=120)
        if r.status_code != 200:
            raise MOSError(f"Download returned HTTP {r.status_code}.")
        if "text/html" in (r.headers.get("Content-Type") or ""):
            raise MOSError("Oracle Support returned a web page instead of the file. The session may have expired, "
                           "or the license agreement for this patch hasn't been accepted.")
        total = int(r.headers.get("Content-Length") or 0)
        done, next_mark = 0, 0
        with open(part, "wb") as f:
            for chunk in r.iter_content(1024 * 1024):
                f.write(chunk)
                done += len(chunk)
                if total and done * 100 // total >= next_mark:
                    log(f"    {dest.name}: {done * 100 // total}% of {max(total // 1048576, 1)} MB\n")
                    next_mark += 20
        if not zipfile.is_zipfile(part):
            part.unlink()
            raise MOSError(f"{dest.name} isn't a valid zip file. The download was probably an error page.")
        os.replace(part, dest)


def mos_client(config_path):
    s = load_secrets(config_path)
    if not s.get("mos_user") or not s.get("mos_password"):
        return None
    c = MOSClient(s["mos_user"], s["mos_password"])
    c.login()
    return c


def aru_date(text):
    m = re.match(r"(\d{1,2})-([A-Z]{3})-(\d{4})", (text or "").strip().upper())
    return f"{m.group(3)}-{MON_NUM.get(m.group(2), 1):02d}-{int(m.group(1)):02d}" if m else ""


def parse_aru_rows(page):
    """Rows of an ARU patch search results table."""
    rows = []
    for tr in re.findall(r'<tr class="OraBGAccent[^"]*"[^>]*>(.*?)</tr>', page, re.S):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        if len(tds) < 5:
            continue

        def txt(x):
            x = re.sub(r"<br\s*/?>", " | ", x)
            return re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", "", x))).strip()
        patch = txt(tds[0])
        if not patch.isdigit():
            continue
        desc = txt(tds[1])
        kind = "patchset" if ": Patchset" in desc.split("|")[0] else "patch"
        aru = re.search(r"aru=(\d+)", tr)
        rows.append({"patch": patch, "kind": kind, "desc": desc.split("|", 1)[-1].strip(), "release": txt(tds[2]),
                     "updated": aru_date(txt(tds[3])), "size": txt(tds[4]), "aru": aru.group(1) if aru else ""})
    return rows


def mos_product_rows(mos, key, description=None):
    p = MOS_PRODUCTS[key]
    if description:
        url = mos.BASE + "/Orion/AdvancedSearch/process_form?" + urlencode(
            {"product": p["product"], "release": p["release"], "plat_lang": p["plat"], "description": description})
    else:
        url = mos.BASE + "/Orion/SimpleSearch/process_form?" + urlencode(
            {"search_type": "prod", "product": p["product"], "release": p["release"], "plat_lang": p["plat"]})
    r = mos.get(url, timeout=180)
    if r.status_code != 200:
        raise MOSError(f"Oracle Support search returned HTTP {r.status_code}.")
    return parse_aru_rows(r.text)


def latest_weblogic(rows):
    psus, spbs = {}, []
    for r in rows:
        m = re.search(r"WLS PATCH SET UPDATE (\d+\.\d+\.\d+\.\d+)\.(\d{6})", r["desc"], re.I)
        if m:
            psus[m.group(2)] = r
        m = re.search(r"WLS STACK PATCH BUNDLE (\d+\.\d+\.\d+\.\d+)\.(\d{6})", r["desc"], re.I)
        if m:
            spbs.append((m.group(2), r))
    if not psus:
        return None
    stamp = max(psus)
    psu = psus[stamp]
    spb = max(spbs, key=lambda x: (x[1]["updated"], x[0]))[1] if spbs else None
    return {"stamp": stamp, "psu_patch": psu["patch"], "released": psu["updated"],
            "spb_patch": spb["patch"] if spb else "", "spb_desc": spb["desc"] if spb else "",
            "released_by_stamp": {k: v["updated"] for k, v in psus.items()}}


def latest_tuxedo(mos, rows):
    """Rolling patches are cumulative patchsets. Newer ones don't always put 'RPnnn' in the description, so an
    unnumbered patchset is numbered one above the previous one, and confirmed from its readme when possible."""
    rps = sorted([r for r in rows if r["kind"] == "patchset" or re.search(r"\bRP\d+", r["desc"])],
                 key=lambda r: (r["updated"], r["patch"]))
    prev = None
    for r in rps:
        m = re.search(r"\bRP0*(\d+)", r["desc"])
        r["rp"], r["rp_how"] = (int(m.group(1)), "description") if m else ((prev + 1, "inferred") if prev else (None, ""))
        prev = r["rp"] if r["rp"] else prev
    if not rps:
        return None
    last = rps[-1]
    if last["rp_how"] != "description" and last.get("aru"):
        try:
            readme = mos.get(f"{mos.BASE}/Orion/Readme/process_form?aru={last['aru']}&no_header=1", timeout=60).text
            m = re.search(r"\bRP0*(\d{2,3})\b", readme)
            if m:
                last["rp"], last["rp_how"] = int(m.group(1)), "readme"
        except Exception:
            pass
    return {"rp": last["rp"], "rp_how": last["rp_how"], "patch": last["patch"], "released": last["updated"],
            "released_by_rp": {str(r["rp"]): r["updated"] for r in rps if r["rp"]}}


def latest_dbclient(mos):
    """Newest Database 19c Release Update. The family has many one-off patches, so the description filter is
    tried with a few spellings until the RU rows come back."""
    tried = []
    for desc in (None, "DATABASE RELEASE UPDATE 19", "%DATABASE RELEASE UPDATE 19%", "*DATABASE RELEASE UPDATE 19*",
                 "Database Release Update"):
        try:
            rows = mos_product_rows(mos, "dbclient", desc)
        except Exception as e:
            tried.append(f"{desc or 'product search'}: {e}")
            continue
        rus = {}
        for r in rows:
            m = re.search(r"DATABASE RELEASE UPDATE\s*:?\s*19\.(\d+)\.0\.0\.\d+", r["desc"], re.I)
            if m and not re.search(r"\b(GI|OJVM|JAVAVM|REVISION|MERGE|OVERLAY)\b", r["desc"], re.I):
                n = int(m.group(1))
                if n not in rus or r["updated"] > rus[n]["updated"]:
                    rus[n] = r
        if rus:
            n = max(rus)
            return {"ru": n, "patch": rus[n]["patch"], "released": rus[n]["updated"], "how": desc or "product search",
                    "released_by_ru": {str(k): v["updated"] for k, v in rus.items()}}
        tried.append(f"{desc or 'product search'}: {len(rows)} rows, no Release Update")
    return {"error": "Couldn't find a Database 19c Release Update on Oracle Support (" + "; ".join(tried) + ")."}


def mos_latest(mos):
    data, errors = {}, []
    for key, fn in (("weblogic", lambda: latest_weblogic(mos_product_rows(mos, "weblogic"))),
                    ("tuxedo", lambda: latest_tuxedo(mos, mos_product_rows(mos, "tuxedo"))),
                    ("dbclient", lambda: latest_dbclient(mos))):
        try:
            data[key] = fn()
            if isinstance(data[key], dict) and data[key].get("error"):
                errors.append(data[key]["error"])
        except Exception as e:
            errors.append(f"{key}: {e}")
    try:
        infra = [r for r in mos_product_rows(mos, "peopletools") if "INFRA" in r["desc"].upper()]
        if infra:
            i = max(infra, key=lambda r: r["updated"])
            data["infra_dpk"] = {"patch": i["patch"], "desc": i["desc"], "released": i["updated"]}
    except Exception as e:
        errors.append(f"PeopleTools: {e}")
    if errors:
        data["error"] = " ".join(errors)
    return data


# ---------------------------------------------------------------- Java releases (public, no sign-in)
def java_latest(major):
    """Latest Oracle JDK CPU release for a major version."""
    try:
        r = requests.get(f"{JAVA_API}/javaReleases", timeout=20,
                         params={"jdkVersion": major, "releaseType": "CPU", "sortBy": "releaseDate",
                                 "sortOrder": "DESC"})
        items = (r.json() or {}).get("items") or []
    except Exception:
        return {"error": f"Couldn't reach Oracle's Java release service ({JAVA_API}) from the connector. "
                         "Check its internet or proxy access."}
    if not items:
        return {"error": f"Oracle's Java release service lists no CPU release for JDK {major}."}
    it = items[0]
    return {"version": it.get("releaseVersion", ""), "date": (it.get("releaseDate") or "")[:10],
            "license": (it.get("licenseDetails") or {}).get("licenseType", "")}


def java_release_date(version):
    try:
        r = requests.get(f"{JAVA_API}/javaReleases/{version}", timeout=15)
        return (r.json().get("releaseDate") or "")[:10] if r.ok else ""
    except Exception:
        return ""


def catalog(config_path, cache_dir, majors, versions, refresh=False, log=print):
    """Everything the control plane needs to tell what's out of date: latest JDK per major version, release dates
    of the installed JDKs, and the latest WebLogic/Tuxedo/Database client patches from Oracle Support."""
    cache_file = Path(cache_dir) / "catalog.json"
    cache = {}
    try:
        cache = json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    fresh = cache.get("time") and time.time() - cache["time"] < CATALOG_TTL and not refresh
    out = {"java": {}, "java_dates": {}, "oracle": {}, "checked": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    for m in majors:
        hit = (cache.get("java") or {}).get(m)
        out["java"][m] = hit if fresh and hit and hit.get("version") else java_latest(m)
    for v in versions:
        hit = (cache.get("java_dates") or {}).get(v)
        out["java_dates"][v] = hit if hit else java_release_date(v)
    if fresh and cache.get("oracle") and not cache["oracle"].get("error"):
        out["oracle"] = cache["oracle"]
        out["oracle_checked"] = cache.get("oracle_checked")
    else:
        try:
            mos = mos_client(config_path)
        except MOSError as e:
            mos, out["oracle"] = None, {"error": f"Oracle Support sign-in failed: {e}"}
        except requests.RequestException as e:
            mos, out["oracle"] = None, {"error": f"Couldn't reach Oracle Support from the connector: {e}"}
        if mos:
            log("Searching Oracle Support for the latest WebLogic, Tuxedo and Database client patches\n")
            out["oracle"] = mos_latest(mos)
            out["oracle_checked"] = out["checked"]
        elif not out["oracle"]:
            out["oracle"] = {"error": "No Oracle Support account is set on this connector, so WebLogic, Tuxedo and "
                                      "Database client patches can't be looked up. On the connector, run: "
                                      "python -m pegasus_connector oracle-login"}
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    keep = dict(out, time=time.time() if not fresh else cache.get("time"))
    keep["java"] = {**(cache.get("java") or {}), **{k: v for k, v in out["java"].items() if v.get("version")}}
    keep["java_dates"] = {**(cache.get("java_dates") or {}), **{k: v for k, v in out["java_dates"].items() if v}}
    if out["oracle"].get("error") and cache.get("oracle") and not cache["oracle"].get("error"):
        keep["oracle"], keep["oracle_checked"] = cache["oracle"], cache.get("oracle_checked")
    cache_file.write_text(json.dumps(keep), encoding="utf-8")
    return out


# ---------------------------------------------------------------- downloads into the connector's cache
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def cached_files(cache_dir, folder, file_filter=""):
    d = Path(cache_dir) / folder
    if not d.is_dir():
        return []
    return sorted(p for p in d.iterdir() if p.is_file() and not p.name.endswith(".part")
                  and (not file_filter or re.search(file_filter, p.name)))


def cache_folder(patch, platform):
    return f"jdk-{patch}" if platform == "java" else patch


def download_patch(config_path, cache_dir, patch, platform, file_filter, log, mos=None):
    have = cached_files(cache_dir, patch, file_filter)
    if have:
        log(f"Patch {patch}: {len(have)} file(s) already in the connector's cache\n")
        return have, mos
    mos = mos or mos_client(config_path)
    if not mos:
        raise MOSError("No Oracle Support account is set on this connector. On the connector, run: "
                       "python -m pegasus_connector oracle-login  (or put the patch zip in "
                       f"{Path(cache_dir) / patch} and try again).")
    log(f"Patch {patch}: looking it up on Oracle Support (platform {platform})\n")
    found = mos.find_files(patch, platform, file_filter)
    if not found:
        raise MOSError(f"Oracle Support has no files for patch {patch} on platform {platform}"
                       f"{' matching ' + file_filter if file_filter else ''}.")
    (Path(cache_dir) / patch).mkdir(parents=True, exist_ok=True)
    for name, url in found:
        log(f"  Downloading {name}\n")
        mos.download(url, Path(cache_dir) / patch / name, log)
    return cached_files(cache_dir, patch, file_filter), mos


def jdk_patches_path(config_path):
    return Path(config_path).parent / "jdk_patches.json"


def load_jdk_patches(config_path):
    try:
        return json.loads(jdk_patches_path(config_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_jdk_patch(config_path, version, patch):
    data = load_jdk_patches(config_path)
    data[version] = str(patch)
    p = jdk_patches_path(config_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def jdk_row_matches(desc, version):
    """An Oracle Support patch row for exactly this JDK release (21.0.13 doesn't match 21.0.13.0.2, or the reverse)."""
    if not re.search(r"\bjdk\b|java se|java\(tm\) se|development kit", desc, re.I):
        return False
    if re.search(r"\b(jre|server jre|openjdk|graalvm)\b", desc, re.I) and not re.search(r"\bjdk\b", desc, re.I):
        return False
    return bool(re.search(r"(?<![\d.])" + re.escape(version) + r"(?!\.?\d)", desc))


RELEASE_RE = re.compile(r'orig_release_(\d+)="([^"]*)"')
PRODUCT_RE = re.compile(r'orig_product_(\d+)="([^"]*)"')
# Oracle files JDK update patches under product "Java SE (jdk)"; "Java SE JDK and JRE (java2SE)" is tried second
JAVA_PRODUCT_NAMES = [re.compile(r"^java se \(jdk\)$", re.I), re.compile(r"^java se jdk and jre\b", re.I),
                      re.compile(r"^java se\b", re.I)]


def jdk_search_ids(mos, version):
    """(product ids, release ids, releases listed) for this JDK, read from Oracle Support's search form: its script
    lists every product as orig_product_<id>="<name>" and every release as orig_release_<id>="<name>"."""
    page = mos.get(mos.BASE + "/Orion/AdvancedSearch/process_form?" + urlencode({"plat_lang": JDK_PLATFORM}),
                   timeout=300).text
    products = [(rid, htmlmod.unescape(name).strip()) for rid, name in PRODUCT_RE.findall(page)]
    prods = []
    for rx in JAVA_PRODUCT_NAMES:
        prods += [rid for rid, name in products if rx.search(name) and rid not in prods]
    prods += [p for p in JAVA_PRODUCTS if p not in prods]
    names = {}
    for rid, name in RELEASE_RE.findall(page):
        names.setdefault(htmlmod.unescape(name).strip().lower(), rid)
    parts = version.split(".")
    wanted = [version] + ([".".join(parts[:3])] if len(parts) > 3 else [])
    rels = []
    for v in wanted:
        for prefix in ("oracle jdk ", "java se ", "jdk "):
            rid = names.get(prefix + v)
            if rid and rid not in rels:
                rels.append(rid)
    return prods[:4], rels, len(names)


def jdk_release_ids(mos, product, version):
    """Release ids only (kept for callers and tests)."""
    _, rels, n = jdk_search_ids(mos, version)
    return rels, n


def find_jdk_patch(mos, version, config_path=None, log=None):
    """The Oracle Support patch number for an Oracle JDK release: read the Java SE product id and the release's id
    from the search form, list that product's patches for the release on Linux x86-64, and take the one for exactly
    this version. Returns (patch or None, what was tried)."""
    tried = []
    try:
        products, releases, listed = jdk_search_ids(mos, version)
    except requests.RequestException as e:
        return None, [f"search form: {e}"]
    tried.append(f"Java SE product ids: {', '.join(products) or 'none'}; release ids for {version}: "
                 f"{', '.join(releases) or 'none'} (of {listed} releases listed)")
    for rel in releases:
        for prod in products:
            params = {"search_type": "prod", "product": prod, "release": rel, "plat_lang": JDK_PLATFORM}
            try:
                r = mos.get(mos.BASE + "/Orion/SimpleSearch/process_form?" + urlencode(params), timeout=180)
                rows = parse_aru_rows(r.text) if r.status_code == 200 else []
            except requests.RequestException as e:
                tried.append(f"release {rel}, product {prod}: {e}")
                continue
            hits = [row for row in rows if jdk_row_matches(row["desc"], version)]
            if hits:
                return max(hits, key=lambda row: (row["updated"], row["patch"]))["patch"], tried
            tried.append(f"release {rel}, product {prod}: {len(rows)} rows"
                         + (f" ({'; '.join(x['desc'][:40] for x in rows[:3])})" if rows else ""))
    return None, tried


def extract_jdk_tarball(zips, dest_dir, version, log):
    """Oracle Support ships the JDK as a zip holding the tarball: take the Linux x64 JDK tarball out, check it."""
    base = version.split("+")[0]
    for z in zips:
        if not zipfile.is_zipfile(z):
            continue
        with zipfile.ZipFile(z) as zf:
            names = [n for n in zf.namelist() if n.endswith(".tar.gz") and "jdk" in n.lower().rsplit("/", 1)[-1]]
            names.sort(key=lambda n: ("linux-x64" not in n and "linux-x86_64" not in n, base not in n, n))
            if not names:
                continue
            member = names[0]
            name = member.rsplit("/", 1)[-1]
            if not re.match(r"^[A-Za-z0-9_.+\-]{1,200}$", name):
                name = f"jdk-{version}_linux-x64_bin.tar.gz"
            dest_dir.mkdir(parents=True, exist_ok=True)
            part = dest_dir / (name + ".part")
            log(f"  Taking {name} out of {z.name}\n")
            with zf.open(member) as src, open(part, "wb") as out:
                for chunk in iter(lambda: src.read(1024 * 1024), b""):
                    out.write(chunk)
            try:
                with tarfile.open(part, "r:gz") as tf:
                    ok = any(m.name.rstrip("/").endswith("/bin/java") for m in tf)
            except (tarfile.TarError, OSError, EOFError):
                ok = False
            if not ok:
                part.unlink()
                raise RuntimeError(f"{name} from {z.name} isn't a usable JDK tarball (no bin/java in it).")
            os.replace(part, dest_dir / name)
            return [dest_dir / name]
    listing = ", ".join(z.name for z in zips) or "nothing"
    raise RuntimeError(f"The Oracle Support download ({listing}) has no Linux x64 JDK tarball in it.")


def download_jdk(config_path, cache_dir, version, log, mos=None):
    """Linux x64 JDK tarball for an exact release, from My Oracle Support with the connector's Oracle Support
    account, like every other patch. The patch number is found by searching once and remembered on the connector;
    if the search can't find it, it can be given once with: python -m pegasus_connector jdk-patch <version> <patch>."""
    folder = f"jdk-{version}"
    dest_dir = Path(cache_dir) / folder
    have = cached_files(cache_dir, folder)
    if have:
        log(f"JDK {version}: {have[0].name} already in the connector's cache\n")
        return have
    mos = mos or mos_client(config_path)
    if not mos:
        raise MOSError("No Oracle Support account is set on this connector. On the connector, run: "
                       f"python -m pegasus_connector oracle-login  (or put the JDK tarball in {dest_dir}).")
    patch = load_jdk_patches(config_path).get(version)
    if patch:
        log(f"JDK {version}: Oracle Support patch {patch}\n")
    else:
        log(f"JDK {version}: searching Oracle Support for its patch\n")
        patch, tried = find_jdk_patch(mos, version, config_path, log)
        if not patch:
            raise MOSError(
                f"Couldn't find Oracle JDK {version} for Linux x86-64 by searching Oracle Support (tried: "
                f"{'; '.join(tried[:12])}). Look up its patch number on support.oracle.com (product Java SE JDK and "
                f"JRE, description 'Oracle JDK Update {version}'), then on the connector run: python -m "
                f"pegasus_connector jdk-patch {version} <patch number>  (or put the JDK tarball in {dest_dir}).")
        log(f"  Found patch {patch}\n")
        save_jdk_patch(config_path, version, patch)
    zips, _ = download_patch(config_path, cache_dir, patch, JDK_PLATFORM, "", log, mos)
    return extract_jdk_tarball(zips, dest_dir, version, log)
