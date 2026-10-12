"""Local policy: rules the client sets on their own connector, which the control plane can't override.

policy.json sits next to config.json. Every field is optional:

{
  "read_only": false,                       # true: only checks (ping, status, levels, catalog, host.idle, access.check)
  "allowed_operations": [...],              # default: every operation in operations.OPERATIONS
  "allowed_hosts": [],                      # empty means any host; otherwise names or IPs
  "blocked_hosts": ["hrprddb01"],
  "paused": false                           # true: accept nothing at all (a kill switch that keeps the connector online)
}
"""
import json
from pathlib import Path

from .operations import OPERATIONS, READ_ONLY_OPERATIONS

DEFAULT = {"read_only": False, "allowed_operations": sorted(OPERATIONS), "allowed_hosts": [], "blocked_hosts": [],
           "paused": False}


def load(path):
    p = Path(path)
    if not p.exists():
        return dict(DEFAULT)
    data = json.loads(p.read_text(encoding="utf-8"))
    policy = dict(DEFAULT)
    policy.update({k: v for k, v in data.items() if k in DEFAULT})
    return policy


def check(policy, job):
    """Raise ValueError with the reason if local policy forbids this job."""
    if policy.get("paused"):
        raise ValueError("this connector is paused by local policy")
    steps = job["params"].get("steps") or []
    for step in steps:
        op = step.get("op")
        if op not in policy.get("allowed_operations", []):
            raise ValueError(f"local policy doesn't allow '{op}'")
        if policy.get("read_only") and op not in READ_ONLY_OPERATIONS:
            raise ValueError(f"this connector is read-only; '{op}' changes servers")
        t = step.get("target")
        if not t:
            continue                  # catalog and downloads run on the connector itself, not on a server
        names = {str(t.get("host") or ""), str(t.get("ip") or "")} - {""}
        allowed = set(policy.get("allowed_hosts") or [])
        if allowed and not names & allowed:
            raise ValueError(f"{t.get('host') or t.get('ip')} isn't in this connector's allowed hosts")
        if names & set(policy.get("blocked_hosts") or []):
            raise ValueError(f"{t.get('host') or t.get('ip')} is blocked by local policy")
