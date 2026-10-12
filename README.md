# Astute Pegasus

PeopleSoft environment operations: start/stop, patch posture, CPU patching with change approval, and SSH access.

| Folder | What it is |
|---|---|
| `pegasus/` | Pegasus as it runs today: a self-hosted web app on an admin/jump host (Python, Flask, Paramiko). See `pegasus/README.md`. |

Planned (SaaS, milestone 1): `control-plane/` (hosted web app and job queue) and `connector/` (agent in each client network, outbound HTTPS only).
