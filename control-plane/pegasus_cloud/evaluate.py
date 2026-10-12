"""Patch posture: compare the levels a connector read from a server with the latest Oracle releases it looked up.

Pure functions, no I/O. Ported from self-hosted Pegasus (pegasus/app.py) so both judge "up to date" the same way.
Sources, in order: a CPU target the operator pinned, Oracle's Java releases (JDK), Oracle Support's patch searches
(WebLogic 14.1.2, Tuxedo 22.1, Database 19c client).
"""
import datetime as dt
import re

COMPONENTS = ["weblogic", "jdk", "dbclient", "tuxedo"]
APPLY_ORDER = ["jdk", "weblogic", "dbclient", "tuxedo"]       # JDK first: OPatch for WebLogic runs on it
COMP_TITLE = {"jdk": "JDK", "weblogic": "WebLogic", "dbclient": "Oracle Database Client", "tuxedo": "Tuxedo"}
DEFAULT_PLATFORM = {"jdk": "226P", "tuxedo": "226P", "weblogic": "2000P", "dbclient": "226P"}
OPATCH_19_KEY = "6880880|226P|190000"           # OPatch 12.2.0.1.x for Database 19c, Linux x86-64
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
TARGET_COLS = ["component", "applies_to", "target", "patch_number", "platform", "file_filter", "label", "notes"]


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def jdk_major(v):
    v = v or ""
    return v.split(".")[1] if v.startswith("1.") else v.split(".")[0]


def cpu_dates(today=None):
    """Oracle Critical Patch Updates ship on the third Tuesday of January, April, July and October."""
    today = today or dt.date.today()

    def third_tuesday(y, m):
        d = dt.date(y, m, 1)
        return d + dt.timedelta(days=(1 - d.weekday()) % 7 + 14)
    dates = sorted(third_tuesday(y, m) for y in (today.year - 1, today.year, today.year + 1) for m in (1, 4, 7, 10))
    last = max(d for d in dates if d <= today)
    nxt = min(d for d in dates if d > today)
    return {"last": last.isoformat(), "next": nxt.isoformat(), "label": last.strftime("%Y-%b")}


def month_label(yymmdd):
    try:
        return f"{MONTHS[int(yymmdd[2:4]) - 1]}{2000 + int(yymmdd[:2])}"
    except (ValueError, IndexError):
        return ""


def cpu_label(iso_date):
    return f"{MONTHS[int(iso_date[5:7]) - 1]}{iso_date[:4]}" if iso_date and len(iso_date) >= 7 else ""


def wls_psu(inst):
    """Date stamp of the installed WebLogic PSU or Stack Patch Bundle, e.g. 260823."""
    best = ""
    for p in (inst or {}).get("patches", []):
        m = re.search(r"(?:PATCH SET UPDATE|STACK PATCH BUNDLE)\s+\d+\.\d+\.\d+\.\d+\.(\d{6})", p.get("desc", ""), re.I)
        if m and m.group(1) > best:
            best = m.group(1)
    return best


def current_label(comp, inst, latest=None, java_dates=None):
    v = inst.get("version", "")
    latest = latest or {}
    if comp == "weblogic":
        psu = wls_psu(inst)
        base = ".".join(v.split(".")[:4])
        rel = ((latest.get("weblogic") or {}).get("released_by_stamp") or {}).get(psu)
        return f"{base} {cpu_label(rel) or month_label(psu)} CPU" if psu else f"{v} ({len(inst.get('patches', []))} patches)"
    if comp == "jdk":
        d = (java_dates or {}).get(v) or ""
        return f"{v} {month_label(d[2:4] + d[5:7] + '01')} CPU" if d else v
    if comp == "dbclient":
        ru = inst.get("ru", "")
        stamp = ru.split(".")[-1] if ru.count(".") >= 4 else ""
        n = ru.split(".")[1] if ru.startswith("19.") else ""
        rel = ((latest.get("dbclient") or {}).get("released_by_ru") or {}).get(n)
        return f"{v} {cpu_label(rel) or month_label(stamp)} CPU" if (rel or stamp) else (f"{v} RU {ru}" if ru else v)
    return f"{v} RP{inst.get('level', '0')}"


def evaluate(host, targets=None, java=None, oracle=None, java_dates=None):
    """One host's components, each with status needed / ok / no-target and the update key to download."""
    items = []
    targets, java, oracle = targets or [], java or {}, oracle or {}
    for comp in COMPONENTS:
        inst = host.get(comp)
        if not inst:
            continue
        version = inst.get("version", "")
        installed = current_label(comp, inst, oracle, java_dates)
        rows = [(i, t) for i, t in enumerate(targets) if t["component"] == comp and
                (not t["applies_to"] or not version or version.startswith(t["applies_to"]))]
        if not rows and comp == "jdk":
            latest = java.get(jdk_major(version)) or {}
            if latest.get("version"):
                needed = vtuple(version) < vtuple(latest["version"])
                d = latest.get("date", "")
                items.append({"component": comp, "installed": installed, "target": latest["version"],
                              "latest_label": f"{latest['version']} {month_label(d[2:4] + d[5:7] + '01')} CPU",
                              "auto": "jdk", "key": f"{latest['version']}|java|", "source": "Oracle Java releases",
                              "status": "needed" if needed else "ok",
                              "detail": f"Oracle's latest JDK {jdk_major(version)} release is {latest['version']} ({d})."})
                continue
            items.append({"component": comp, "installed": installed, "target": "", "status": "no-target",
                          "detail": latest.get("error") or f"Look up the latest Oracle releases to compare JDK {version}."})
            continue
        lw, lt, ld = oracle.get("weblogic"), oracle.get("tuxedo"), oracle.get("dbclient")
        if not rows and comp == "weblogic" and lw and wls_psu(inst) and version.startswith("14.1.2.0"):
            psu = wls_psu(inst)
            needed = psu < lw["stamp"]
            patch = lw["spb_patch"] or lw["psu_patch"]
            items.append({"component": comp, "installed": installed, "target": lw["stamp"],
                          "latest_label": f"14.1.2.0 {cpu_label(lw['released'])} CPU", "source": "Oracle Support",
                          "auto": "mos", "patch_number": patch, "platform": "2000P",
                          "verify_ids": [lw["psu_patch"]], "key": f"{patch}|2000P|",
                          "status": "needed" if needed else "ok",
                          "detail": (f"Installed WLS PSU 14.1.2.0.{psu}; newest is 14.1.2.0.{lw['stamp']} (patch "
                                     f"{lw['psu_patch']}, released {lw['released']}). Download gets the Stack Patch "
                                     f"Bundle {lw['spb_patch']}, the full set Cloud Manager applies." if needed else
                                     f"Installed PSU 14.1.2.0.{psu} is the newest on Oracle Support.")})
            continue
        if not rows and comp == "tuxedo" and lt and lt.get("rp") and version.startswith("22.1.0.0.0"):
            cur = int(inst.get("level") or 0)
            needed = cur < lt["rp"]
            items.append({"component": comp, "installed": installed, "target": str(lt["rp"]), "level": str(lt["rp"]),
                          "latest_label": f"{version} RP{lt['rp']:03d}", "source": "Oracle Support",
                          "auto": "mos", "patch_number": lt["patch"], "platform": "226P",
                          "key": f"{lt['patch']}|226P|", "status": "needed" if needed else "ok",
                          "detail": f"Newest rolling patch: RP{lt['rp']:03d}, patch {lt['patch']} (released "
                                    f"{lt['released']}" + (", RP number inferred from the sequence"
                                                           if lt.get("rp_how") == "inferred" else "") + ")."})
            continue
        if not rows and comp == "dbclient" and ld and ld.get("ru"):
            ru = inst.get("ru", "")
            cur = int(ru.split(".")[1]) if ru.startswith("19.") and ru.split(".")[1].isdigit() else None
            if cur is not None:
                needed = cur < ld["ru"]
                items.append({"component": comp, "installed": installed, "target": f"19.{ld['ru']}",
                              "latest_label": f"{version} {cpu_label(ld['released'])} CPU", "source": "Oracle Support",
                              "auto": "mos", "patch_number": ld["patch"], "platform": "226P",
                              "verify_ids": [ld["patch"]], "key": f"{ld['patch']}|226P|",
                              "status": "needed" if needed else "ok",
                              "detail": f"Installed Release Update {ru}; newest is 19.{ld['ru']} (patch {ld['patch']}, "
                                        f"released {ld['released']}).", "needs_opatch": True})
                continue
        if not rows:
            why = oracle.get("error") or (
                "Oracle Support doesn't list a newer patch for this release; pin one under CPU targets."
                if oracle else "Look up the latest Oracle releases to compare.")
            items.append({"component": comp, "installed": installed, "target": "", "status": "no-target", "detail": why})
            continue
        for i, t in rows:
            if comp == "jdk":
                needed = vtuple(version) < vtuple(t["target"])
                detail = f"Upgrade {version} to {t['target']}" if needed else "At or above target"
            elif comp == "tuxedo":
                needed = int(inst.get("level") or 0) < int(re.sub(r"\D", "", t["target"]) or 0)
                detail = f"Patch level {inst.get('level')} is below {t['target']}" if needed else "At or above target"
            else:
                have = {p["id"] for p in inst.get("patches", [])} | {re.sub(r"\D", "", inst.get("ru", ""))}
                missing = [p for p in re.split(r"[\s,;]+", t["target"]) if p and p not in have]
                if comp == "dbclient" and t["target"].startswith("19."):
                    missing = [] if vtuple(inst.get("ru", "")) >= vtuple(t["target"]) else [t["target"]]
                needed = bool(missing)
                detail = ("Missing " + ", ".join(missing)) if needed else "All target patches installed"
            label = f"{version} RP{re.sub(r'[^0-9]', '', t['target'])}" if comp == "tuxedo" else t["target"]
            key = ""
            if comp == "jdk" and not t["patch_number"]:
                key = f"{t['target']}|java|"
            elif t["patch_number"]:
                key = f"{t['patch_number']}|{t['platform'] or DEFAULT_PLATFORM[comp]}|{t['file_filter']}"
            items.append({"component": comp, "installed": installed, "target": t["target"], "target_index": i,
                          "latest_label": (t["label"] + ": " if t["label"] else "") + label,
                          "patch_number": t["patch_number"], "label": t["label"], "source": "CPU target",
                          "level": t["target"] if comp == "tuxedo" else "",
                          "key": key, "status": "needed" if needed else "ok", "detail": detail})
    return items


def stage_label(item):
    """Folder name under the staging root for an update."""
    patch, platform, _ = item["key"].split("|")
    if platform == "java":
        return f"jdk-{patch}"
    return item.get("label") or f"p{patch}"


def plan_signature(plan):
    """What an approval covers: every component, update and server in the plan."""
    return sorted(f"{p['component']}|{p['key']}|{p['host']}" for p in plan)


def wiki(text):
    return re.sub(r"([{}\[\]|*_^~+\-!#])", r"\\\1", str(text or ""))


def describe_plan(env, client_name, tier, plan, notes, who, when, window=None):
    """Jira wiki-markup description of a patch plan: what changes, impact, backout, request details."""
    comps = []
    for comp in dict.fromkeys(p["component"] for p in plan):
        steps = [p for p in plan if p["component"] == comp]
        comps.append((COMP_TITLE[comp], steps[0]["label"], [p["host"] for p in steps]))
    hosts = list(dict.fromkeys(p["host"] for p in plan))
    rows = "\n".join(f"|{wiki(c)}|{wiki(v)}|{wiki(', '.join(h))}|" for c, v, h in comps)
    backups = []
    if any(p["component"] == "jdk" for p in plan):
        backups.append("JDK: the old JDK is kept as jdk.bak.<timestamp> next to the new one, and put back "
                       "automatically if the new JDK fails verification.")
    if any(p["component"] == "weblogic" for p in plan):
        backups.append("WebLogic: the WebLogic home is archived to <home>.bak.<timestamp>.tar.gz before patching.")
    if any(p["component"] == "dbclient" for p in plan):
        backups.append("Oracle Database Client: the client home is backed up first, and the previous OPatch is kept "
                       "as OPatch.bak.<timestamp>.")
    if any(p["component"] == "tuxedo" for p in plan):
        backups.append("Tuxedo: the Tuxedo home is backed up before the rolling patch.")
    window = window or {}
    return "\n".join([
        "h3. What will change",
        "||Component||Update||Servers||",
        rows,
        "",
        "h3. Impact",
        f"{wiki(env)} is unavailable for the whole window. Pegasus stops every domain (web, process scheduler, app "
        f"server), confirms no WebLogic or Tuxedo processes are left, patches the servers one at a time, then starts "
        f"every domain again and checks status. Servers affected: {wiki(', '.join(hosts))}.",
        "",
        "h3. Backout",
        *[f"* {wiki(b)}" for b in backups],
        "* If a server fails, the remaining servers are left alone and all domains are started again. The failing step "
        "and backup location are reported back on this ticket.",
        "",
        "h3. Request",
        f"* Environment: {wiki(env)} ({wiki(client_name)}, tier {wiki(tier or 'not set')})",
        f"* Requested in Pegasus by {wiki(who)} on {when}",
        *([f"* Planned window: {wiki(window.get('start') or 'not set')} to {wiki(window.get('end') or 'not set')}"]
          if window.get("start") or window.get("end") else []),
        *([f"* Notes: {wiki(notes)}"] if notes else []),
        "",
        "{panel}Pegasus applies exactly this plan once, and only after this ticket is approved by someone other than "
        "the account that raised it. If the plan changes before then, Pegasus asks for a new ticket.{panel}",
    ])
