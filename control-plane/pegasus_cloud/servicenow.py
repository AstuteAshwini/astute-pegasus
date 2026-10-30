"""Change approval in ServiceNow, per client: the same contract as jira.py, so the rest of Pegasus doesn't care which
ticketing system a client uses.

Pegasus raises a change request (Table API, change_request) describing exactly what will change, moves it to the
state that asks for approval (Assess by default), and treats it as approved once ServiceNow's approval field says so,
or it reaches one of the approved states, and the approver isn't the account Pegasus signs in with. Comments go in as
work notes; the start and finish of the apply can move the change to a state, e.g. Implement and Review.
"""
import datetime as dt
import json
import re
from urllib.parse import quote

import requests

from .jira import JiraError

DEFAULTS = {
    "enabled": False,
    "require": "all",                     # "all" environments, or "prd" only
    "url": "",                            # https://yourcompany.service-now.com
    "auth": "basic",                      # "basic" (user + password) or "oauth" (a bearer token)
    "user": "",                           # the integration user (also used to spot self-approval)
    "change_type": "Normal",              # Normal, Standard or Emergency
    "assignment_group": "",               # optional, the group's name
    "category": "",
    "submit_transition": "Assess",        # state that asks for approval right after creating
    "approved_statuses": ["Scheduled", "Implement"],
    "rejected_statuses": ["Canceled", "Cancelled"],
    "start_transition": "Implement",      # state when the apply starts
    "done_transition": "Review",          # state when it succeeds
    "extra_fields": {},
    "block_self_approval": True,
}
# the out-of-the-box states of a change request
STATES = {"new": "-5", "assess": "-4", "authorize": "-3", "scheduled": "-2", "implement": "-1", "review": "0",
          "closed": "3", "canceled": "4", "cancelled": "4"}


class ServiceNowError(JiraError):
    """A JiraError, so every place that handles a ticketing failure handles this one too."""


def config(stored):
    c = dict(DEFAULTS)
    c.update(stored or {})
    return c


def validate(body, c, has_token):
    """New config from a settings form. Returns (config, problems)."""
    problems = []
    url = str(body.get("url", c["url"]) or "").strip().rstrip("/")
    if url and not re.match(r"^https://[A-Za-z0-9.\-]+(:\d+)?$", url):
        problems.append("The ServiceNow URL should look like https://yourcompany.service-now.com.")
    auth = body.get("auth", c["auth"])
    if auth not in ("basic", "oauth"):
        problems.append("Choose a user and password, or an OAuth token.")
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
            problems.append("Additional fields must be JSON, e.g. {\"u_service\": \"PeopleSoft\"}.")
            extra = c["extra_fields"]
    if not isinstance(extra, dict):
        problems.append("Additional fields must be a JSON object.")
        extra = c["extra_fields"]
    text = lambda k, n: str(body.get(k, c[k]) or "").strip()[:n]
    for k in ("submit_transition", "start_transition", "done_transition"):
        v = text(k, 30)
        if v and v.lower() not in STATES and not re.fullmatch(r"-?\d{1,3}", v):
            problems.append(f"'{v}' isn't a change request state (New, Assess, Authorize, Scheduled, Implement, "
                            "Review, Closed, Canceled, or the state's number).")
    enabled = bool(body.get("enabled", c["enabled"]))
    new = {"enabled": enabled, "require": require, "url": url, "auth": auth, "user": text("user", 120),
           "change_type": text("change_type", 40) or "Normal", "assignment_group": text("assignment_group", 80),
           "category": text("category", 60), "submit_transition": text("submit_transition", 30),
           "approved_statuses": names("approved_statuses"), "rejected_statuses": names("rejected_statuses"),
           "start_transition": text("start_transition", 30), "done_transition": text("done_transition", 30),
           "extra_fields": extra, "block_self_approval": bool(body.get("block_self_approval", c["block_self_approval"]))}
    if enabled and not (new["url"] and new["user"]):
        problems.append("Fill in the ServiceNow URL and the integration user before switching approval on.")
    if enabled and not has_token:
        problems.append("Add the ServiceNow password or token before switching approval on.")
    return new, problems


def wiki_to_text(text):
    """Pegasus writes ticket text in Jira's markup; ServiceNow shows plain text."""
    out = []
    for line in str(text or "").splitlines():
        if line.strip() in ("{noformat}", "{panel}") or line.startswith("{panel}"):
            line = line.replace("{panel}", "").replace("{noformat}", "")
            if not line.strip():
                continue
        line = line.replace("{panel}", "").replace("{noformat}", "")
        m = re.match(r"^h[1-6]\.\s*(.*)$", line)
        if m:
            line = "\n" + m.group(1).upper()
        elif line.startswith("||"):
            line = " | ".join(x for x in line.strip("|").split("||"))
        elif line.startswith("|"):
            line = " | ".join(line.strip("|").split("|"))
        line = re.sub(r"\[([^|\]]+)\|(https?://[^\]]+)\]", r"\1 (\2)", line)
        line = re.sub(r"\[(https?://[^\]]+)\]", r"\1", line)
        line = re.sub(r"\\([{}\[\]|*_^~+\-!#])", r"\1", line)
        out.append(line)
    return "\n".join(out).strip()


def _when(v):
    """Pegasus's window time (2026-11-07T22:00:00.000-0800) as ServiceNow's internal UTC format."""
    if not v:
        return ""
    d = dt.datetime.strptime(v[:19] + v[-5:], "%Y-%m-%dT%H:%M:%S%z")
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _error_text(r):
    try:
        e = (r.json() or {}).get("error") or {}
        msg = " ".join(x for x in (e.get("message"), e.get("detail")) if x)
        if msg:
            return msg[:500]
    except ValueError:
        pass
    return (r.text or r.reason or "")[:300]


def _val(rec, field, kind="value"):
    v = (rec or {}).get(field)
    if isinstance(v, dict):
        return str(v.get(kind) or v.get("value") or "")
    return str(v or "")


class ServiceNow:
    def __init__(self, cfg, token):
        if not cfg["url"]:
            raise ServiceNowError("ServiceNow isn't set up for this client yet. Fill in the ServiceNow URL.")
        if not token:
            raise ServiceNowError("No ServiceNow password or token is saved for this client.")
        if cfg["auth"] == "basic" and not cfg["user"]:
            raise ServiceNowError("Enter the ServiceNow integration user.")
        self.cfg = cfg
        self.base = cfg["url"].rstrip("/")
        self.s = requests.Session()
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        if cfg["auth"] == "basic":
            self.s.auth = (cfg["user"], token)
        else:
            self.s.headers["Authorization"] = f"Bearer {token}"
        self._ids = {}

    def call(self, method, path, body=None, params=None):
        try:
            r = self.s.request(method, f"{self.base}/api/now/{path}", json=body, params=params, timeout=30)
        except requests.RequestException as e:
            raise ServiceNowError(f"Couldn't reach ServiceNow at {self.base}: {e}")
        if r.status_code in (401, 403):
            raise ServiceNowError(f"ServiceNow refused the request ({r.status_code}): {_error_text(r)}. Check the "
                                  "user, password or token, and that the user has the itil role.")
        if r.status_code >= 400:
            raise ServiceNowError(f"ServiceNow returned {r.status_code}: {_error_text(r)}")
        try:
            return (r.json() or {}).get("result")
        except ValueError:
            raise ServiceNowError("ServiceNow answered with something that isn't JSON. Check the URL.")

    # ---- the same contract as jira.Jira
    def browse(self, key):
        return f"{self.base}/change_request.do?sysparm_query=number%3D{quote(key)}"

    def myself(self):
        if not self.cfg["user"]:
            return {"displayName": "OAuth token"}
        rows = self.call("GET", "table/sys_user", params={"sysparm_query": f"user_name={self.cfg['user']}",
                                                          "sysparm_fields": "sys_id,name,user_name",
                                                          "sysparm_limit": 1}) or []
        if not rows:
            raise ServiceNowError(f"ServiceNow has no user named {self.cfg['user']}.")
        return {"displayName": rows[0].get("name") or self.cfg["user"], "sys_id": rows[0].get("sys_id")}

    def project(self):
        """Proves the user can read change requests (what Test connection checks)."""
        self.call("GET", "table/change_request", params={"sysparm_limit": 1, "sysparm_fields": "number"})
        return {"name": "change_request", "issueTypes": [{"name": t} for t in ("Normal", "Standard", "Emergency")]}

    def _group_id(self, name):
        rows = self.call("GET", "table/sys_user_group", params={"sysparm_query": f"name={name}",
                                                                "sysparm_fields": "sys_id", "sysparm_limit": 1}) or []
        if not rows:
            raise ServiceNowError(f"ServiceNow has no assignment group named '{name}'.")
        return rows[0]["sys_id"]

    def create(self, summary, description, window=None):
        window = window or {}
        fields = {"short_description": summary[:160], "description": wiki_to_text(description),
                  "type": (self.cfg.get("change_type") or "Normal").lower()}
        if self.cfg.get("category"):
            fields["category"] = self.cfg["category"]
        if self.cfg.get("assignment_group"):
            fields["assignment_group"] = self._group_id(self.cfg["assignment_group"])
        if window.get("start"):
            fields["start_date"] = _when(window["start"])
        if window.get("end"):
            fields["end_date"] = _when(window["end"])
        fields.update(self.cfg.get("extra_fields") or {})
        rec = self.call("POST", "table/change_request", fields) or {}
        key = rec.get("number")
        if not key:
            raise ServiceNowError("ServiceNow didn't return a change number.")
        self._ids[key] = rec.get("sys_id")
        return key

    def issue(self, key):
        rows = self.call("GET", "table/change_request", params={
            "sysparm_query": f"number={key}", "sysparm_display_value": "all", "sysparm_limit": 1,
            "sysparm_fields": "sys_id,number,state,approval,opened_by,sys_created_by"}) or []
        if not rows:
            raise ServiceNowError(f"ServiceNow has no change request {key}.")
        self._ids[key] = _val(rows[0], "sys_id")
        return rows[0]

    def _sys_id(self, key):
        return self._ids.get(key) or _val(self.issue(key), "sys_id")

    def approvers(self, sys_id):
        return self.call("GET", "table/sysapproval_approver", params={
            "sysparm_query": f"sysapproval={sys_id}^state=approved^ORDERBYDESCsys_updated_on",
            "sysparm_display_value": "all", "sysparm_fields": "approver,state,sys_updated_on"}) or []

    def approval_state(self, key):
        rec = self.issue(key)
        approvers = []
        if _val(rec, "approval").lower() == "approved":
            approvers = self.approvers(_val(rec, "sys_id"))
        own = self.myself().get("sys_id") if self.cfg.get("user") else None
        return status(self.cfg, rec, approvers, own)

    def comment(self, key, text):
        self.call("PATCH", f"table/change_request/{self._sys_id(key)}", {"work_notes": wiki_to_text(text)})

    def transition(self, key, name):
        if not name:
            return None
        value = STATES.get(name.strip().lower(), name.strip())
        fields = {"state": value}
        if value == "3":            # closing needs a close code and notes
            fields.update(close_code="successful", close_notes="Applied by Pegasus.")
        self.call("PATCH", f"table/change_request/{self._sys_id(key)}", fields)
        return name


def status(cfg, rec, approvers=(), own_id=None):
    """(state, ServiceNow state name, approver). state: approved, rejected, pending or self_approved."""
    name = _val(rec, "state", "display_value")
    approval = _val(rec, "approval").lower()
    low = name.lower()
    if approval == "rejected" or low in {s.lower() for s in cfg["rejected_statuses"]}:
        return "rejected", name, ""
    if approval != "approved" and low not in {s.lower() for s in cfg["approved_statuses"]}:
        return "pending", name, ""
    people = [(_val(a, "approver", "display_value"), _val(a, "approver")) for a in approvers or []]
    approver = ", ".join(dict.fromkeys(n for n, _ in people if n))
    raiser = {own_id, _val(rec, "opened_by")} - {None, ""}
    if cfg.get("block_self_approval", True) and (not people or all(i in raiser for _, i in people)):
        return "self_approved", name, approver
    return "approved", name, approver
