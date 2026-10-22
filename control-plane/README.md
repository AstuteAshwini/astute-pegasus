# Pegasus control plane

The hosted part of Pegasus: clients (tenants), their connectors, server inventory and the job queue, with a web
page for operators. It never connects to a client's network; connectors call in.

Today: named accounts with MFA and roles, SQLite, the Flask development server. A managed database and a production
server come with hosting on OCI behind HTTPS (milestone 3).

## People and sign-in

Everyone signs in with an email, a password (12+ characters) and a 6-digit code from an authenticator app
(Microsoft Authenticator, Google Authenticator, 1Password...). The app is set up at the first sign-in, which also
shows 10 one-time recovery codes. Five wrong passwords or codes lock the account for 15 minutes.

| Role | Can |
|---|---|
| Viewer | See clients, environments, patch posture, jobs and activity. Change nothing. |
| Operator | Also run status/start/stop, check and download patches, request approval and apply, manage SSH keys. |
| Admin | Also add clients and connectors, import inventory, Jira and patch settings, and manage people. |

Astute staff see every client. A client's own people (operator or viewer) see only that client.

**First start:** with no accounts yet, the page offers *Set up Pegasus Cloud*. Enter `PEGASUS_ADMIN_PASSWORD` (or,
if it isn't set, do this on the machine Pegasus runs on), your name, email and password, then set up your
authenticator app. After that, add people under **People and access**; each gets a temporary password to change at
first sign-in. Upgrading from milestone 1 keeps every client, connector, inventory and job.

## Run locally

```bash
python3 -m pip install -r requirements.txt
export PEGASUS_ADMIN_PASSWORD='choose-one'
export PEGASUS_COOKIE_SECURE=false        # only when testing over plain http on localhost
python3 -m pegasus_cloud                  # http://127.0.0.1:8443
```

| Variable | Default | Purpose |
|---|---|---|
| `PEGASUS_ADMIN_PASSWORD` | (none) | Setup password for creating the first admin account; not used after that |
| `PEGASUS_DATA` | `control-plane/data` | Database, signing key, session key and the key that encrypts Jira tokens |
| `PEGASUS_HOST` / `PEGASUS_PORT` | `127.0.0.1` / `8443` | Address and port |
| `PEGASUS_STATUS_EVERY` | `600` | Seconds between automatic status checks of every domain; `0` turns them off |
| `PEGASUS_PUBLIC_URL` | request URL | URL connectors use, shown in the register command |
| `PEGASUS_SECRET` | `PEGASUS_DATA/session.key` | Session signing key |
| `PEGASUS_SECRET_KEY` | `PEGASUS_DATA/secret.key` | Fernet key that encrypts stored secrets (Jira tokens); OCI Vault in production |
| `PEGASUS_RELEASE_KEYS` | (any) | Comma-separated release public keys to offer connector releases from |

The job-signing key is created on first start in `PEGASUS_DATA/signing_key.pem`. Keep it safe and backed up:
connectors trust only that key (for jobs and for their certificates), so replacing it means registering every
connector again. Back up `secret.key` with
the database too: without it, saved Jira tokens can't be read and have to be entered again.

## Connector certificates

Each connector holds its own Ed25519 key; this control plane issues it a 90-day certificate (signed with the same key
that signs jobs) at registration, and the connector renews it with a fresh key about monthly. Every connector request
is signed (method, path, time, a nonce and the body's hash) and checked against the connector's current key; nonces
are kept for ten minutes, so a captured request can't be sent again. During a renewal the previous key is accepted
for ten more minutes, for requests already on their way.

The Overview tab shows each connector's certificate and when it expires. **Remove** revokes it immediately.
Connectors registered with a shared secret before certificates get one the next time they start, after which the
secret is refused.

## Connector releases and updates

Releases are built and signed on the machine that holds Astute's release key, never on the control plane:

```bash
python scripts/connector_release.py keygen            # once; adds the public key to connector/.../release_keys.py
python scripts/connector_release.py build --notes "what changed"
```

`build` signs the current `connector/pegasus_connector` code as the version in its `__init__.py` and writes it to
`PEGASUS_DATA/releases/<version>/` (by default `control-plane/data/releases/`). Pegasus picks it up without a
restart and shows it on each client's Overview tab, with the release key's fingerprint.

Per client (admins): **Connector updates: Manual** (default; each connector shows **Update to x.y.z**) or
**Automatic** (every connector takes a new release as soon as it's out). Each connector reports what happened:
updating, updated, failed (with the reason) or refused by its local policy, and every step is in Activity. A failed
release isn't offered again until an admin clicks Update.

Set `PEGASUS_RELEASE_KEYS` to list the release keys Pegasus will offer releases from; by default it checks each
release against the key it was built with. Either way, connectors check against the keys built into their own code.

## Domain status

The Overview tab shows every domain as Running, Stopped, Unreachable or Unknown, with when it was last checked, and a
summary per environment. The state comes from the latest status check, start, stop, restart or patch run, so it's
always the last thing Pegasus actually saw.

Pegasus also checks every domain by itself: every 10 minutes (`PEGASUS_STATUS_EVERY`, in seconds; `0` turns it off)
and when someone opens a client whose last check is older than that. **Check all now** asks straight away. Each domain row also has **Start**, **Stop** and **Restart**, which act on
that one domain only; the environment's **Start all** / **Stop all** keep the safe order across every domain. These
automatic checks are read-only, run beside anything else the connector is doing, don't block start/stop or patching,
and are left out of Recent jobs. They need the client's connector to be online.

## Adding servers

On a client's **Overview** tab (admins), **Add servers**: enter IP addresses (`10.0.1.21`, or `10.0.1.21:2222` for
another SSH port) and click **Scan servers**. The connector signs in to each one, finds who runs PeopleSoft (from
running processes, else psadm1/psadm2/psadm3, or the OS users you enter), and lists their web, app server and process
scheduler domains. Domains that look like leftovers (no `config.xml` / `PSTUXCFG`) start unticked. Name the
environment (a new one, or an existing one to add to), set its tier, and click **Add ticked domains**. Adding merges
into the inventory: other environments are kept and a domain that's already there is updated, not duplicated.

A server the connector has never connected to isn't scanned until you trust its SSH host key: Pegasus shows the
fingerprint; compare it on the server with `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`, then click **Trust key
and scan**. The connector re-reads the key and saves it to its own `known_hosts` only if it still matches.

The CSV import is still there (under the Add servers panel) and replaces the client's whole inventory. **Remove** on
an environment drops it from the inventory without touching the servers.

## CPU patching

On a client's **Patching** tab, per environment:

1. **Check patch levels.** The connector reads JDK, WebLogic, Tuxedo and Database client levels (and the owner of
   each home) on every server, then looks up Oracle's latest: the Java releases service for the JDK, and Oracle
   Support searches for WebLogic 14.1.2, Tuxedo 22.1 and Database 19c, with the client's own Oracle account saved on
   the connector (`oracle-login`; Pegasus never sees it). Results are cached on the connector for 12 hours;
   **Look up latest again** asks Oracle afresh.
2. **Download.** The connector downloads each update once into its cache and copies it to the staging folder
   (Settings tab, default `/u01/app/oracle/staging/cpu`) on each server, checking the SHA-256. Nothing is installed.
3. **Request approval** (when Jira approval is on): Pegasus raises a ticket describing exactly what changes, the
   outage and the backout. Apply unlocks once someone other than the Pegasus account approves it; Pegasus asks
   Jira again at the moment Apply is clicked. An approval covers one exact plan, once.
4. **Apply.** One maintenance window: stop every domain, check no WebLogic or Tuxedo process is left, back up and
   patch each home as its owner (JDK first, then WebLogic, Database client, Tuxedo), start every domain again even
   if a step failed, check status and read the levels again. The result is posted to the Jira ticket.

The apply scripts live in the connector and are built there from validated values; the control plane only sends
which update goes where. **CPU targets** (Settings) pin a level for releases Oracle Support searches don't cover.

## Jira change approval

Per client, under Settings. Jira Cloud signs in with an account email and API token; Data Center with a personal
access token. The token is stored encrypted. **Test connection** shows which Change fields Pegasus fills in and
which required fields still need values under Additional fields.

## SSH access

The **SSH access** tab adds, checks or removes a person's public key in an account's `authorized_keys` on every
server of the chosen environments (a backup of the file is kept first). Keys Pegasus added are listed so they can be
checked or removed in one click. Production needs the environment name typed to confirm. Root's keys are never
managed.

## How a job flows

1. An operator clicks an action (status, start, stop, restart, patch levels, download, apply, SSH key). Pegasus
   builds the steps in the safe order (stop: web, process scheduler, app; start: the reverse) and queues one job.
2. The client's connector, long-polling outbound, claims it. Pegasus signs the job for that connector at that
   moment.
3. The connector checks the signature and its local policy, runs the steps, and streams output back. Domain
   states (running/stopped) are read from psadmin's output.
4. Queued jobs nobody picks up expire after 15 minutes. A running job whose connector goes silent for 10 minutes
   is marked failed. Only one job runs per environment at a time. Production start/stop/restart and patching need
   the environment name typed to confirm.
5. When the job finishes, Pegasus records what it learned (patch levels, staged files, SSH keys), closes any Jira
   change request, and writes the audit log (the client's **Activity** tab).

## Hosting it

To run Pegasus at a permanent HTTPS address on an OCI VM (as a service, with backups), follow
`deploy/oci/README.md`. In production it runs on waitress behind Caddy, with `PEGASUS_TRUST_PROXY=true` so it takes
the client's address and https from the proxy.

## Trying it with real clients before it's hosted (temporary public address)

Run the control plane on a machine you control (your laptop or an Astute server, not a client's VM) and give it a
temporary HTTPS address with a Cloudflare quick tunnel. Only connectors can use that address; the web page works
only on this machine.

Windows Command Prompt:

```
cd c:\astute-pegasus\control-plane
set PEGASUS_ADMIN_PASSWORD=<setup password, only needed until the first admin account exists>
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
