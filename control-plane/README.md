# Pegasus control plane

The hosted part of Pegasus: clients (tenants), their connectors, server inventory and the job queue, with a web
page for operators. It never connects to a client's network; connectors call in.

Milestone 1 scope: one admin password, SQLite, the Flask development server. Milestone 2 adds per-user SSO and
roles, a managed database and a production server; milestone 3 hosting on OCI behind HTTPS.

## Run locally

```bash
python3 -m pip install -r requirements.txt
export PEGASUS_ADMIN_PASSWORD='choose-one'
export PEGASUS_COOKIE_SECURE=false        # only when testing over plain http on localhost
python3 -m pegasus_cloud                  # http://127.0.0.1:8443
```

| Variable | Default | Purpose |
|---|---|---|
| `PEGASUS_ADMIN_PASSWORD` | (required) | Sign-in password (milestone 2 replaces this with SSO) |
| `PEGASUS_DATA` | `control-plane/data` | Database and signing key |
| `PEGASUS_HOST` / `PEGASUS_PORT` | `127.0.0.1` / `8443` | Address and port |
| `PEGASUS_PUBLIC_URL` | request URL | URL connectors use, shown in the register command |
| `PEGASUS_SECRET` | random | Session signing key |

The job-signing key is created on first start in `PEGASUS_DATA/signing_key.pem`. Keep it safe and backed up:
connectors trust only that key, so replacing it means registering every connector again.

## How a job flows

1. An operator clicks an action (status, start, stop, restart, patch levels, test connection). Pegasus builds the
   steps in the safe order (stop: web, process scheduler, app; start: the reverse) and queues one job.
2. The client's connector, long-polling outbound, claims it. Pegasus signs the job for that connector at that
   moment.
3. The connector checks the signature and its local policy, runs the steps, and streams output back. Domain
   states (running/stopped) are read from psadmin's output.
4. Queued jobs nobody picks up expire after 15 minutes. A running job whose connector goes silent for 10 minutes
   is marked failed. Only one job runs per environment at a time. Production start/stop/restart needs the
   environment name typed to confirm.
