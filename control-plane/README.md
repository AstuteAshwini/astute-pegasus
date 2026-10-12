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

## Trying it with real clients before it's hosted (temporary public address)

Run the control plane on a machine you control (your laptop or an Astute server, not a client's VM) and give it a
temporary HTTPS address with a Cloudflare quick tunnel. Only connectors can use that address; the web page works
only on this machine.

Windows Command Prompt:

```
cd c:\astute-pegasus\control-plane
set PEGASUS_ADMIN_PASSWORD=<password>
set PEGASUS_COOKIE_SECURE=false
set PEGASUS_ADMIN_LOCAL_ONLY=true
set PEGASUS_PUBLIC_URL=https://<name>.trycloudflare.com
start "Pegasus control plane" python -m pegasus_cloud
cloudflared tunnel --url http://127.0.0.1:8443
```

Start the tunnel first if you don't know its address yet: it prints `https://<name>.trycloudflare.com`; then set
`PEGASUS_PUBLIC_URL` to it and start the control plane. (`cloudflared` is a single download from Cloudflare; no
account is needed for a quick tunnel.)

* Open the web page at http://127.0.0.1:8443 on this machine. Through the tunnel address, everything except the
  connector API answers "Not found".
* Each client's connector registers with `--url https://<name>.trycloudflare.com` and only needs outbound HTTPS.
* A quick tunnel's address changes every time `cloudflared` restarts. When it does, update `PEGASUS_PUBLIC_URL`,
  restart the control plane, and change `"url"` in each connector's `config.json`, then restart the connectors.
  This is for testing only; the stable address comes with hosting on OCI.
