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
| `scripts/connector_release.py` | Creates the release key and builds signed connector releases. |

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -q tests
```

## Roadmap

1. **Connector and job protocol** (done): registration, signed jobs, local policy, status/start/stop/restart,
   patch levels, connection test.
2. **Multi-tenant core** (done): CPU patching on the connector (latest-release lookup, download, staging, apply in
   one maintenance window), Jira change approval per client, SSH access, accounts with email + password +
   authenticator-app MFA, roles (admin, operator, viewer), client-scoped users, audit log, connector certificates
   (own key, signed requests, automatic renewal, revocation), and signed connector auto-update with rollback.
3. **Pilot-ready**: hosted on OCI with a managed database, monitoring and backups, signed Windows installer and Linux
   package (connector as a service), OCI Resource Manager stack, security documentation (HECVAT).
4. **Sellable SaaS**: billing and onboarding, Azure/AWS/on-prem installers, ServiceNow, SOC 2.
