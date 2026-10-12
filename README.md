# Astute Pegasus

PeopleSoft environment operations: start/stop, patch posture, CPU patching with change approval, and SSH access,
for environments on OCI, Azure, AWS or on-prem.

| Folder | What it is |
|---|---|
| `pegasus/` | Pegasus as it runs today: a self-hosted web app on an admin/jump host. See `pegasus/README.md`. |
| `control-plane/` | Pegasus Cloud: the hosted web app and job queue (SaaS). |
| `connector/` | The agent each client runs in their own network. Outbound HTTPS only, keys stay with the client. |
| `tests/` | End-to-end tests: real control plane and connector, simulated PeopleSoft servers. |
| `scripts/demo_servers.py` | Runs a connector against simulated servers, for demos. |

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q tests
```

## Roadmap

1. **Connector and job protocol** (this milestone): registration, signed jobs, local policy, status/start/stop/
   restart, patch levels, connection test.
2. **Multi-tenant core**: managed database, per-user SSO and roles, connector certificates, auto-update; move
   patch staging/apply, Jira approvals and SSH access from `pegasus/` onto the connector.
3. **Pilot-ready**: hosted on OCI with monitoring and backups, signed Windows installer and Linux package, OCI
   Resource Manager stack, security documentation (HECVAT).
4. **Sellable SaaS**: billing and onboarding, Azure/AWS/on-prem installers, ServiceNow, SOC 2.
