# Pegasus connector

Runs inside a client's network, next to their PeopleSoft servers. It only makes **outbound HTTPS** calls to the
Pegasus control plane, asks for work, runs it over SSH on the client's servers, and streams the output back.
Nothing connects to it, and the SSH key it uses never leaves the machine it runs on.

## What it will and won't do

* It runs only **named operations**, listed in `operations.py`: connection test, psadmin status/start/stop,
  patch levels, finding PeopleSoft domains on a server (`discover`) and trusting a server's host key after an operator
  compared its fingerprint (`hostkey.trust`), the latest-release lookup (`catalog`), patch download and staging, a check that no WebLogic or
  Tuxedo process is running, patch apply, and SSH key check/add/remove. Commands and scripts (including the apply
  scripts, in `patching.py`) are built here from fixed templates; every value is validated and shell-quoted.
  Nothing sent by the control plane is ever run as a shell command.
* Every job must carry a valid **signature** from the control plane's key (learned once, at registration), be
  addressed to this connector, and be inside its validity window. Replayed jobs are refused.
* **Local policy** (`policy.json` next to `config.json`) lets the client restrict it further, and the control
  plane can't override it:

```json
{ "read_only": true, "blocked_hosts": ["hrprddb01"], "allowed_hosts": [], "paused": false }
```

`read_only` allows only checks (ping, status, patch levels, scanning for domains, latest-release lookup, the process
check and SSH key checks). `paused` refuses everything (a kill switch that keeps the connector online). `allowed_operations` limits it
to a list. Stopping the service cuts Pegasus off completely.

## Oracle Support account (for patching)

Downloads and the WebLogic/Tuxedo/Database client lookups use the client's own Oracle Support account, saved only on
this machine (`oracle.json` next to `config.json`, readable only by its owner):

```bash
python3 -m pegasus_connector oracle-login --user name@client.com          # asks for the password
python3 -m pegasus_connector oracle-login --jms-token <token>             # only for OTN-licensed JDK downloads
python3 -m pegasus_connector oracle-login --forget
```

Downloaded patches are kept in `cache/` next to `config.json` (set `PEGASUS_CACHE` to put them elsewhere) and
copied to the servers over SSH. The connector needs outbound HTTPS to `updates.oracle.com`, `login.oracle.com` and
`java.oraclecloud.com` for this. A patch zip copied into `cache/<patch number>/` by hand is used as is.

## Install and register (milestone 1: Python on Linux or Windows)

```bash
python3 -m pip install -r requirements.txt
python3 -m pegasus_connector register --url https://<control plane> --token <one-time token> \
        --ssh-user opc --ssh-key /home/opc/.ssh/id_rsa
python3 -m pegasus_connector run          # foreground; a systemd/Windows service comes in milestone 3
python3 -m pegasus_connector oracle-login --user name@client.com
python3 -m pegasus_connector status
```

The token comes from **Add connector** in Pegasus. It works once and expires after 24 hours. `register` prints
the control plane's signing key fingerprint; check it matches the one Pegasus shows. Configuration is written to
`/etc/pegasus-connector/config.json` (root), `~/.pegasus-connector/config.json` (other users) or
`%ProgramData%\PegasusConnector\config.json` (Windows), readable only by the owner. If the SSH key has a
passphrase, set `PEGASUS_SSH_PASSPHRASE`.

The connector needs outbound HTTPS to the control plane, and SSH (22) to the PeopleSoft servers. The servers'
host keys must already be in the connector user's `known_hosts`.

If the PeopleSoft owner (`os_user`, e.g. psadm2) differs from the SSH user, commands run with
`sudo -n -iu <os_user>`, so the SSH user needs a passwordless sudo rule for it. Patches are applied as the owner of
each home (e.g. psadm1 for the JDK and WebLogic), and SSH keys are added for the account you choose, the same way.

The connector runs up to 4 jobs at once (`PEGASUS_WORKERS`), so a status check doesn't wait behind a long download.
Pegasus still allows only one job per environment at a time.
