"""Change approval in Jira (Cloud or Data Center), per client.

With approval on, Apply doesn't patch anything by itself. Pegasus first raises a Jira ticket describing exactly what
will change. Apply unlocks only once the ticket is approved by someone other than the account that raised it, and
Pegasus asks Jira again at the moment Apply is clicked, so the browser can't skip the step. Each approval covers one
exact plan, once. When the apply finishes, the result goes back to the ticket.
"""
import json
import re

import requests

DEFAULTS = {
    "enabled": False,
    "require": "all",                 # "all" environments, or "prd" only
    "url": "",                        # https://yourcompany.atlassian.net  or  https://jira.yourcompany.com
    "deployment": "cloud",            # "cloud" (email + API token) or "datacenter" (personal access token)
    "user": "",                       # Jira Cloud account email
    "project": "",                    # project key, e.g. CHG
    "issue_type": "Change",
    "change_type": "Normal",          # Jira Service Management "Change type" (Standard, Normal, Emergency)
    "change_risk": "",
    "impact": "",
    "urgency": "",
    "submit_transition": "",          # optional transition right after creating, to send it for approval
    "approved_statuses": ["Approved", "Awaiting implementation", "Scheduled"],
    "rejected_statuses": ["Rejected", "Declined", "Canceled", "Cancelled", "Won't Do"],
    "start_transition": "",           # optional transition when the apply starts, e.g. "Implement"
    "done_transition": "",            # optional transition when it succeeds, e.g. "Done"
    "extra_fields": {"labels": ["pegasus", "cpu-patching"]},
    "block_self_approval": True,
}


class JiraError(Exception):
    pass


def config(stored):
    c = dict(DEFAULTS)
    c.update(stored or {})
    return c


def validate(body, c, has_token):
    """New config from a settings form. Returns (config, problems)."""
    problems = []
    url = str(body.get("url", c["url"]) or "").strip().rstrip("/")
    if url and not re.match(r"^https://[A-Za-z0-9.\-]+(:\d+)?(/[A-Za-z0-9._~\-/]*)?$", url):
        problems.append("The Jira URL should look like https://yourcompany.atlassian.net.")
    project = str(body.get("project", c["project"]) or "").strip().upper()
    if project and not re.match(r"^[A-Z][A-Z0-9_]{1,19}$", project):
        problems.append("The project key should look like CHG or PSOPS.")
    deployment = body.get("deployment", c["deployment"])
    if deployment not in ("cloud", "datacenter"):
        problems.append("Choose Jira Cloud or Jira Data Center.")
    require = body.get("require", c["require"])
    if require not in ("all", "prd"):
        problems.append("Choose whether approval is needed for every environment or production only.")

    def names(key):
        v = body.get(key, c[key])
        v = v if isinstance(v, list) else re.split(r"\s*,\s*", str(v or ""))
        return [x.strip()[:60] for x in v if x and x.strip()]

    extra = body.get("extra_fields", c["extra_fields"])
    if isinstance(extra, str):
        try:
            extra = json.loads(extra) if extra.strip() else {}
        except ValueError:
            problems.append("Additional fields must be JSON, e.g. {\"labels\": [\"pegasus\"]}.")
            extra = c["extra_fields"]
    if not isinstance(extra, dict):
        problems.append("Additional fields must be a JSON object.")
        extra = c["extra_fields"]
    approved = names("approved_statuses")
    enabled = bool(body.get("enabled", c["enabled"]))
    if enabled and not approved:
        problems.append("List at least one status that means approved.")
    text = lambda k, n: str(body.get(k, c[k]) or "").strip()[:n]
    new = {"enabled": enabled, "require": require, "url": url, "deployment": deployment, "user": text("user", 120),
           "project": project, "issue_type": text("issue_type", 60) or "Change", "change_type": text("change_type", 40),
           "change_risk": text("change_risk", 40), "impact": text("impact", 40), "urgency": text("urgency", 40),
           "submit_transition": text("submit_transition", 60), "approved_statuses": approved,
           "rejected_statuses": names("rejected_statuses"), "start_transition": text("start_transition", 60),
           "done_transition": text("done_transition", 60), "extra_fields": extra,
           "block_self_approval": bool(body.get("block_self_approval", c["block_self_approval"]))}
    if enabled and not (new["url"] and new["project"] and (deployment == "datacenter" or new["user"])):
        problems.append("Fill in the Jira URL, project key and (for Jira Cloud) the account email before switching "
                        "approval on.")
    if enabled and not has_token:
        problems.append("Add the Jira API token before switching approval on.")
    return new, problems


def _error_text(r):
    try:
        j = r.json()
        parts = list(j.get("errorMessages") or []) + [f"{k}: {v}" for k, v in (j.get("errors") or {}).items()]
        if parts:
            return "; ".join(parts)[:500]
    except ValueError:
        pass
    return (r.text or r.reason or "")[:300]


def _who(u):
    """A Jira user's stable identity: accountId on Cloud, key or name on Data Center."""
    u = u or {}
    return u.get("accountId") or u.get("key") or u.get("name") or ""


class Jira:
    def __init__(self, cfg, token):
        if not cfg["url"] or not cfg["project"]:
            raise JiraError("Jira isn't set up for this client yet. Fill in the Jira URL and project.")
        if not token:
            raise JiraError("No Jira API token is saved for this client.")
        if cfg["deployment"] == "cloud" and not cfg["user"]:
            raise JiraError("Jira Cloud signs in with an account email and API token. Enter the email.")
        self.cfg = cfg
        self.base = cfg["url"].rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if cfg["deployment"] == "cloud":
            self.s.auth = (cfg["user"], token)
        else:
            self.s.headers["Authorization"] = f"Bearer {token}"

    def call(self, method, path, body=None, params=None):
        try:
            r = self.s.request(method, f"{self.base}/rest/api/2/{path}", json=body, params=params, timeout=20)
        except requests.RequestException as e:
            raise JiraError(f"Couldn't reach Jira at {self.base}: {e}")
        if r.status_code in (401, 403):
            raise JiraError(f"Jira refused the sign-in ({r.status_code}). Check the account and API token. "
                            + _error_text(r))
        if r.status_code >= 300:
            raise JiraError(f"Jira returned {r.status_code}: {_error_text(r)}")
        return r.json() if r.content else {}

    def browse(self, key):
        return f"{self.base}/browse/{key}"

    def myself(self):
        return self.call("GET", "myself")

    def project(self):
        return self.call("GET", f"project/{self.cfg['project']}")

    def create_meta(self):
        """The fields Jira offers when creating the configured issue type in the project: {lower name: field}."""
        proj, want = self.cfg["project"], self.cfg["issue_type"].strip().lower()
        try:   # Jira Cloud and Data Center 8.4+
            types = self.call("GET", f"issue/createmeta/{proj}/issuetypes", params={"maxResults": 100})
            types = types.get("values") or types.get("issueTypes") or []
            it = next((t for t in types if t.get("name", "").lower() == want), None)
            if not it:
                raise JiraError(f"Project {proj} has no '{self.cfg['issue_type']}' issue type. "
                                f"Available: {', '.join(t.get('name', '') for t in types) or 'none'}.")
            fields, start = [], 0
            while True:
                page = self.call("GET", f"issue/createmeta/{proj}/issuetypes/{it['id']}",
                                 params={"startAt": start, "maxResults": 100})
                vals = page.get("values") or page.get("fields") or []
                fields += vals
                start += len(vals)
                if not vals or page.get("isLast", True) or start >= page.get("total", start):
                    break
        except JiraError as e:
            if "returned 404" not in str(e):
                raise
            meta = self.call("GET", "issue/createmeta", params={"projectKeys": proj,
                                                                 "expand": "projects.issuetypes.fields"})
            types = [t for p in meta.get("projects") or [] for t in p.get("issuetypes") or []]
            it = next((t for t in types if t.get("name", "").lower() == want), None)
            if not it:
                raise JiraError(f"Project {proj} has no '{self.cfg['issue_type']}' issue type. "
                                f"Available: {', '.join(t.get('name', '') for t in types) or 'none'}.")
            fields = [dict(f, fieldId=fid) for fid, f in (it.get("fields") or {}).items()]
        return {(f.get("name") or "").strip().lower(): dict(f, fieldId=f.get("fieldId") or f.get("key")) for f in fields}

    def change_fields(self, meta, window):
        """Fill the Change fields this project has (by name, since their IDs differ between Jira sites)."""
        out, problems = {}, []

        def put(name, value):
            f = meta.get(name)
            if not f or value in (None, ""):
                return
            kind = (f.get("schema") or {}).get("type", "")
            if kind == "option":
                allowed = [a.get("value") or a.get("name") for a in f.get("allowedValues") or []]
                match = next((a for a in allowed if a and a.lower() == str(value).lower()), None)
                if allowed and not match:
                    problems.append(f"'{value}' isn't a valid {f['name']} in Jira. Choose one of: {', '.join(allowed)}.")
                    return
                out[f["fieldId"]] = {"value": match or value}
            elif kind == "priority":
                out[f["fieldId"]] = {"name": value}
            elif kind == "date":
                out[f["fieldId"]] = str(value)[:10]
            else:
                out[f["fieldId"]] = value

        put("change type", self.cfg.get("change_type"))
        put("change risk", self.cfg.get("change_risk"))
        put("impact", self.cfg.get("impact"))
        put("urgency", self.cfg.get("urgency"))
        put("planned start", (window or {}).get("start"))
        put("planned end", (window or {}).get("end"))
        if problems:
            raise JiraError(" ".join(problems))
        return out

    def create(self, summary, description, window=None):
        meta = self.create_meta()
        fields = self.change_fields(meta, window)
        fields.update(self.cfg.get("extra_fields") or {})
        fields.update({"project": {"key": self.cfg["project"]}, "summary": summary[:250], "description": description,
                       "issuetype": {"name": self.cfg["issue_type"]}})
        missing = missing_required(meta, fields)
        if missing:
            raise JiraError(f"Jira needs these fields on a {self.cfg['issue_type']}, which Pegasus doesn't fill in: "
                            f"{'; '.join(missing)}. Add them under Additional fields in the Jira settings.")
        return self.call("POST", "issue", {"fields": fields})["key"]

    def issue(self, key):
        return self.call("GET", f"issue/{key}", params={"fields": "status,creator,reporter", "expand": "changelog"})

    def approvals(self, key):
        """Jira Service Management approvals on the ticket, or None if the project isn't a service project."""
        try:
            r = self.s.get(f"{self.base}/rest/servicedeskapi/request/{key}/approval", timeout=20)
        except requests.RequestException:
            return None
        if r.status_code != 200:
            return None
        try:
            return r.json().get("values") or []
        except ValueError:
            return None

    def approval_state(self, key):
        return status(self.cfg, self.issue(key), self.approvals(key))

    def comment(self, key, text):
        self.call("POST", f"issue/{key}/comment", {"body": text})

    def transition(self, key, name):
        if not name:
            return None
        ts = self.call("GET", f"issue/{key}/transitions").get("transitions") or []
        want = name.strip().lower()
        t = next((t for t in ts if t["name"].lower() == want or (t.get("to") or {}).get("name", "").lower() == want), None)
        if not t:
            raise JiraError(f"No '{name}' transition is available on {key} from its current status. "
                            f"Available: {', '.join(x['name'] for x in ts) or 'none'}.")
        self.call("POST", f"issue/{key}/transitions", {"transition": {"id": t["id"]}})
        return t["name"]


def missing_required(meta, fields):
    """Required create fields that are still empty, each with its allowed values when Jira lists them."""
    out = []
    for f in meta.values():
        fid = f.get("fieldId")
        if not f.get("required") or f.get("hasDefaultValue") or fid in fields or fid in ("reporter", "attachment"):
            continue
        allowed = [a.get("value") or a.get("name") for a in f.get("allowedValues") or []][:12]
        out.append(f"{f.get('name')} ({fid}" + (f"; one of {', '.join(a for a in allowed if a)}" if allowed else "") + ")")
    return out


def status(cfg, issue, jsm=None):
    """(state, Jira status name, approver). state: approved, rejected, pending or self_approved."""
    f = issue.get("fields") or {}
    name = (f.get("status") or {}).get("name", "")
    low = name.lower()
    if low in {s.lower() for s in cfg["rejected_statuses"]}:
        return "rejected", name, ""
    raiser = {_who(f.get("creator")), _who(f.get("reporter"))} - {""}
    if jsm:
        if any((a.get("finalDecision") or "pending").lower() == "pending" for a in jsm):
            return "pending", name, ""
        done = sorted(jsm, key=lambda a: ((a.get("completedDate") or {}).get("epochMillis") or 0))
        last = done[-1]
        if (last.get("finalDecision") or "").lower() != "approved":
            return "rejected", name, ""
        yes = [a.get("approver") or {} for a in last.get("approvers") or []
               if (a.get("approverDecision") or "").lower() == "approved"]
        approver = ", ".join(u.get("displayName", "") for u in yes if u.get("displayName"))
        if cfg.get("block_self_approval", True) and (not yes or all(_who(u) in raiser for u in yes)):
            return "self_approved", name, approver
        return "approved", name, approver
    if low not in {s.lower() for s in cfg["approved_statuses"]}:
        return "pending", name, ""
    approver, approver_id = "", ""
    for hist in reversed((issue.get("changelog") or {}).get("histories") or []):
        if any(it.get("field") == "status" and (it.get("toString") or "").lower() == low for it in hist.get("items") or []):
            approver, approver_id = (hist.get("author") or {}).get("displayName", ""), _who(hist.get("author"))
            break
    if cfg.get("block_self_approval", True) and (not approver_id or approver_id in raiser):
        return "self_approved", name, approver
    return "approved", name, approver
