# Pegasus control plane on an OCI VM

Pegasus behind HTTPS at a permanent address (e.g. https://pegasus.beastute.com), running as a service, with nightly
backups. Caddy handles the certificate (Let's Encrypt) and renews it by itself.

**Before you start:** an Oracle Linux 8/9 VM with a reserved public IP; its subnet allows TCP 443 and 80 from
anywhere and 22 from your IP; and the DNS name has an A record pointing at that IP (check with
`nslookup pegasus.beastute.com`).

## 1. Install (on the VM)

```bash
sudo dnf install -y git
git clone https://github.com/AstuteAshwini/astute-pegasus /tmp/astute-pegasus
sudo bash /tmp/astute-pegasus/deploy/oci/setup.sh pegasus.beastute.com you@beastute.com
rm -rf /tmp/astute-pegasus
```

The email gets Let's Encrypt's notices about the certificate. Running `setup.sh` again later is safe.

| What | Where |
|---|---|
| Code | `/opt/pegasus/app` (a git checkout) |
| Data: database, signing key, encryption keys, releases | `/var/lib/pegasus` |
| Settings | `/etc/pegasus/pegasus.env` |
| Backups (nightly at 02:30, kept 14 days) | `/var/backups/pegasus` |
| Logs | `journalctl -u pegasus`, `journalctl -u caddy` |

## 2. Bring your existing data across (once)

Stop Pegasus on the laptop (Ctrl+C in its window), then from the laptop:

```
scp -r c:\astute-pegasus\control-plane\data opc@<vm-ip>:/tmp/pegasus-data
```

and on the VM:

```bash
sudo bash /opt/pegasus/app/deploy/oci/import-data.sh /tmp/pegasus-data
```

Clients, connectors, people, inventory, jobs, Jira settings and the signing key all come across, so connectors keep
their certificates. Don't run the laptop copy again afterwards: keep its `data` folder as a spare backup only.

## 3. Point each connector at the new address

On each client's connector machine (Linux):

```bash
~/pegasus-venv/bin/python -c "import json,sys;p=sys.argv[1];c=json.load(open(p));c['url']=sys.argv[2];json.dump(c,open(p,'w'),indent=2)" ~/.pegasus-connector/config.json https://pegasus.beastute.com
sudo systemctl restart pegasus-connector
```

## Day to day

* **Update Pegasus:** `sudo bash /opt/pegasus/app/deploy/oci/update.sh` (backs up first).
* **Publish a connector release:** build it on the laptop (`python scripts\connector_release.py build`), copy the
  `control-plane\data\releases\<version>` folder to the VM's `/tmp`, then
  `sudo bash /opt/pegasus/app/deploy/oci/publish-release.sh /tmp/<version>`. The release key never leaves the laptop.
* **Back up now:** `sudo /usr/local/sbin/pegasus-backup`. Backups hold keys: copy them somewhere off the VM as well
  (e.g. an Object Storage bucket with a retention rule).
* **Restore:** stop Pegasus, unpack a backup into `/var/lib/pegasus`, `chown -R pegasus:pegasus /var/lib/pegasus`,
  start it.

## Sign in with Google

People sign in with their Google account. Only people with a Pegasus account (same email) get in, and Pegasus still
decides which clients each person sees and what they can do.

1. In the Google Cloud console for the beastute.com Workspace: **APIs & Services → OAuth consent screen**, user type
   **Internal**. Then **Credentials → Create credentials → OAuth client ID**, type **Web application**, authorized
   redirect URI `https://pegasus.beastute.com/api/sso/google/callback`.
2. Add to `/etc/pegasus/pegasus.env` on the VM (`sudo vi /etc/pegasus/pegasus.env`):
   ```
   PEGASUS_GOOGLE_CLIENT_ID=<client id>
   PEGASUS_GOOGLE_CLIENT_SECRET=<client secret>
   PEGASUS_GOOGLE_DOMAIN=beastute.com
   PEGASUS_PASSWORD_SIGNIN=admins
   ```
   `PEGASUS_PASSWORD_SIGNIN=admins` keeps password + authenticator sign-in for admins only, as a way in if Google is
   ever unavailable; leave it out to keep passwords for everyone.
3. `sudo systemctl restart pegasus`. The sign-in page shows **Sign in with Google**.

Google needs the real address with a trusted certificate, so the DNS record must be in place first.

If the repo is private, give the VM read access with a GitHub deploy key before `setup.sh` and `update.sh`.
