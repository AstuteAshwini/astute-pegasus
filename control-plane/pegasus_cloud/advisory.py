"""Risk scores from Oracle's Critical Patch Update advisory.

Each quarter Oracle publishes an advisory page (https://www.oracle.com/security-alerts/cpu<mon><year>.html) with a
risk matrix per product family: one row per CVE, with the product, the component and a CVSS base score. Pegasus reads
the page for the latest CPU and keeps, per component it patches, the highest score, the CVE behind it and how many
fixes there are, so people can see how urgent an update is before they apply it.

Pure parsing here; the control plane fetches the page (it has internet access) and caches the result.
"""
import html as htmlmod
import re

MONTH = {1: "jan", 4: "apr", 7: "jul", 10: "oct"}
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
SCORE = re.compile(r"^(10\.0|\d\.\d)$")

# which Pegasus component a risk matrix row belongs to: by the matrix it sits in, then by the row's product
SECTIONS = [("jdk", re.compile(r"java se", re.I)), ("dbclient", re.compile(r"database server", re.I))]
PRODUCTS = [("weblogic", re.compile(r"^oracle weblogic server", re.I)),
            ("tuxedo", re.compile(r"^oracle tuxedo", re.I)),
            ("jdk", re.compile(r"java se|graalvm for jdk", re.I)),
            ("peopletools", re.compile(r"peopletools", re.I))]
TITLES = {"weblogic": "WebLogic", "tuxedo": "Tuxedo", "jdk": "JDK", "dbclient": "Oracle Database",
          "peopletools": "PeopleTools"}


def advisory_url(cpu_iso_date):
    """The advisory page for the CPU released on this date (YYYY-MM-DD)."""
    y, m = int(cpu_iso_date[:4]), int(cpu_iso_date[5:7])
    return f"https://www.oracle.com/security-alerts/cpu{MONTH[m]}{y}.html"


def _text(cell):
    return re.sub(r"\s+", " ", htmlmod.unescape(re.sub(r"<[^>]+>", " ", cell))).strip()


def _rows(chunk):
    for tr in re.findall(r"<tr\b[^>]*>(.*?)</tr>", chunk, re.S | re.I):
        cells = [_text(c) for c in re.findall(r"<t[hd]\b[^>]*>(.*?)</t[hd]>", tr, re.S | re.I)]
        if len(cells) >= 6 and CVE.match(cells[0].split()[0] if cells[0] else ""):
            score = next((c for c in cells[3:8] if SCORE.match(c)), None)
            if score:
                yield cells[0].split()[0], cells[1], cells[2], float(score)


def parse(page):
    """{component: {"max": 9.8, "cve": "CVE-…", "count": 7, "product": "Oracle WebLogic Server"}} from an advisory."""
    out = {}
    # split at each risk matrix heading so a row can be told apart by the family it's listed under
    parts = re.split(r"(<h[1-6][^>]*>[^<]*?Risk Matrix[^<]*?</h[1-6]>)", page, flags=re.I)
    section = ""
    for part in parts:
        if re.match(r"<h[1-6]", part, re.I):
            section = _text(part)
            continue
        for cve, product, component, score in _rows(part):
            comp = next((c for c, rx in SECTIONS if rx.search(section)), None)
            comp = comp or next((c for c, rx in PRODUCTS if rx.search(product)), None)
            if not comp:
                continue
            cur = out.setdefault(comp, {"max": 0.0, "cve": "", "count": 0, "product": product})
            cur["count"] += 1
            if score > cur["max"]:
                cur.update(max=score, cve=cve, product=product)
    return out


def severity(score):
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
