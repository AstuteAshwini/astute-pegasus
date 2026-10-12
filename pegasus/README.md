# Pegasus

**PeopleSoft Environments, Governed by Astute: Start, Update, Secure.**

Pegasus runs, checks and patches every PeopleSoft environment from one place:
* **Environments:** each environment drawn as Web server → Application server, with the Process
  scheduler alongside, and a live state light on every domain. **Check status everywhere** refreshes
  the whole fleet; the last known state of each domain is remembered between sessions.
* **Patch posture** on every environment card (on the latest CPU, or how many updates are outstanding),
  linking to the Patching tab.
* **Patching:** live WebLogic, JDK, Database Client and Tuxedo levels against the latest on Oracle
  Support; download, stage and apply, one component or everything in one maintenance window.

The interface uses the Archivo and JetBrains Mono fonts from Google Fonts when the machine has internet
access, and falls back to system fonts otherwise.

## About this folder

A small web app that runs on your admin/jump host. It keeps your PeopleSoft
environments in a CSV file and uses `psadmin` over SSH to start, stop and check domains.

## What's in the folder

| File | Purpose |
|---|---|
| `app.py` | The web app (Python, Flask + Paramiko) |
| `static/index.html` | The dashboard page |
| `data/environments.csv` | The inventory, one row per server. Edit it by hand or use the Import tab |
| `environments.example.csv` | Sample rows showing every column |
| `logs/actions.log` | Each action with who ran it, when, and the result (created on first use) |
| `logs/jobs/*.log` | Full psadmin output for each action |
| `data/backups/` | A copy of the CSV, taken before each import or removal |
| `data/access_keys.json` | SSH keys added from the Access section, and where they are |
| `data/change_requests.json` | Jira change tickets raised from the Patching tab, and what happened to each |

## Setup (one time)

You need Python 3.8+ on the admin host.

```bash
cd ps-admin-dashboard
export PSDASH_PASSWORD='pick-a-strong-password'
./start.sh
```

`start.sh` creates a virtual environment, installs Flask and Paramiko, and starts the
dashboard on **http://127.0.0.1:8080**. To keep the password out of your shell history,
put `export PSDASH_PASSWORD='...'` in `~/.psdash.env` (chmod 600) instead.

To open the dashboard from your laptop, use an SSH tunnel:

```bash
ssh -L 8080:127.0.0.1:8080 <you>@<admin-host>
# then browse to http://localhost:8080
```

To listen on the network instead, set `PSDASH_HOST=0.0.0.0` and put the dashboard behind
HTTPS (nginx or similar). Don't expose it to the internet.

## First use

1. Sign in with the dashboard password.
2. Click **Set up** next to "No SSH connection set". Enter your **SSH user ID** and the
   **path to your private key on the admin host** (e.g. `/home/opc/.ssh/id_rsa`). If the key
   has a passphrase, enter it too. The passphrase is kept in memory only and is cleared when
   you sign out.
3. Go to **Import**, paste your server list or choose a CSV, check the preview, and import.
4. On **Environments**, use Status, Start or Stop for one server, or Start all, Stop all
   or Restart all for the whole environment.

## Discovering an environment from its IP addresses

On the **Import** tab, use **Discover from servers** to add an environment without typing rows:

1. Enter the IPs of the environment's servers (web, app, process scheduler), separated by
   commas or spaces. If a server doesn't use port 22, add `:port`.
2. Click **Scan servers**. For each IP, the dashboard connects with your SSH user and key and:
   * reads the host name
   * finds the PeopleSoft owner from running WebLogic/Tuxedo processes, or tries psadm2,
     psadm1 and psadm3 if none are running
   * as that owner, reads `PS_HOME`, `PS_CFG_HOME` and `JAVA_HOME`, and lists the domains: web
     (`webserv/*` with `startPIA.sh`), app server (`appserv/*` with `psappsrv.cfg`) and
     process scheduler (`appserv/prcs/*` with `psprcs.cfg`)
3. If a server is new to the dashboard, you'll see its host key fingerprint. Check that it
   matches the server (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server), then
   click **Trust key and scan**. This adds the key to `known_hosts`, so you don't need to run
   `ssh-keyscan` by hand.
4. Untick any domains you don't want, enter the environment name, client and tier, and click
   **Review import**. The rows go to the import preview. Nothing is saved until you click Import.

The scan is read-only. If the owner's domains aren't running and the owner isn't
psadm1/psadm2/psadm3, type the owner's name in the **PeopleSoft OS user** box.

## Patching tab: CPU patches for WebLogic, JDK, Oracle Database Client and Tuxedo

The patch-level table follows Cloud Manager's layout: Hostname, Node Type, Component, Current
Version, Latest Version, Status. **Current Version is always read live from the server.**
**Latest Version comes from Oracle Support, the same way Cloud Manager gets it — no CPU targets
needed.** With your saved Oracle Support sign-in, the dashboard runs the "Product or Family" patch
search and reads the results table:

| Component | Oracle Support search | Latest = | Download gets |
|---|---|---|---|
| WebLogic 14.1.2.0 | product 15991, release 14.1.2.0.0, Generic | newest "WLS PATCH SET UPDATE" | the matching Stack Patch Bundle |
| Tuxedo 22.1.0.0.0 | product 16021, Linux x86-64 | newest rolling-patch patchset (RP number from its description, readme, or the sequence) | that patchset |
| Database Client 19c | product 9480, release 19.0.0.0.0, Linux x86-64 | newest "DATABASE RELEASE UPDATE 19.x" | that Release Update |
| JDK | Oracle's public Java release service | newest release of the installed major version | the Linux x64 tarball |

CPU labels use each patch's release date on Oracle Support (e.g. WLS PSU 14.1.2.0.260823, released
14-SEP-2026, is "Sep2026 CPU"), matching Cloud Manager. The newest PeopleTools Infrastructure DPK
for 8.62 is shown for reference. Results are cached for 12 hours in `data/mos_latest.json`;
**Check patch levels** refreshes them. A CPU target row, if you add one, overrides the automatic
latest for that component.

### Details

**JDK is automatic.** With no JDK target row, each server's JDK is compared with Oracle's latest
release for that major version, taken from Oracle's public Java Releases API
(`java.oraclecloud.com/javaReleases`). Staging downloads the Linux x64 tarball from Oracle's Java
download service and checks it against Oracle's published SHA-256. Releases under the OTN license
(JDK 8, 11, 17, and JDK 21 from the October 2026 CPU on) need a Java Management Service download
token: create one in the OCI Console under Java Management > Java Download > Tokens and save it on
the Patching tab. Add a JDK row only to pin a version.

**WebLogic and Tuxedo need targets.** Oracle publishes their CPU patch numbers only on My Oracle
Support, so there's no public feed to read them from. The Patching tab shows the latest and next CPU
dates (third Tuesday of January, April, July and October) as a reminder to update them.

**1. Set CPU targets (once per quarter).** Add one row per component and version line:

| Component | Target means | Example |
|---|---|---|
| jdk | Minimum JDK version | applies to `21`, target `21.0.12` |
| weblogic | Patch IDs that must appear in `opatch lspatches` (space separated) | applies to `14.1.2.0`, target `39796630` |
| tuxedo | Minimum rolling patch level | applies to `22.1.0.0.0`, target `051` |

*MOS patch* is the patch number to download. *Platform* defaults to `226P` (Linux x86-64) for
JDK and Tuxedo and `2000P` (Generic) for WebLogic; if a lookup returns no files, check the patch's
platform on support.oracle.com. *File filter* is a pattern that picks the right file when a patch
has several releases (e.g. `141200`). *Label* becomes the staging subfolder (e.g. `2026-Jul`).
Targets are stored in `data/cpu_targets.csv`.

**2. Check patch levels.** Pick an environment and click **Check patch levels**. For each server,
as the PeopleSoft owner, the dashboard reads the PeopleTools version (`psadmin -v`), the JDK
version (`$JAVA_HOME/bin/java -version`), the Tuxedo version and patch level (`$TUXDIR/bin/tmadmin -v`),
and the WebLogic version and installed patches (`OPatch/opatch lspatches`). It's read-only.
Results are saved in `data/patch_levels.json` and compared against the targets.

**3. Download and stage.** Tick the patches you want (by default, every one that's needed), set
the staging folder, and click **Download and stage**. The dashboard:
* signs in to Oracle Support with your MOS user name and password (kept in memory only) and
  downloads each patch once into `data/patches/<patch number>/` on this machine, then
* copies the files into `<staging folder>/<label>/` on each server that needs them, as the
  PeopleSoft owner, and checks each one with SHA-256. Files that are already there are skipped.

Downloading doesn't install anything or stop any domains. Before copying, Pegasus checks that the
PeopleSoft owner can write to the staging folder on each server. If it can't, Pegasus creates the
folder as root with the SSH user's sudo (opc on OCI), gives it to the owner, and makes it readable
(755/644) so the patch owner (psadm1, oracle2) can apply from it. It only changes the staging folder
itself and refuses general folders such as /u01 or /u01/app/oracle.

**4. Apply.** When an update has been downloaded on every server that needs it, the Patching tab
shows **Apply to <environment>** for that component. One click covers the whole environment:

1. Stops every domain (web, then process scheduler, then app server) and confirms no WebLogic or
   Tuxedo processes are still running. If any are, nothing is patched.
2. On each server in turn, runs the apply **in the background as the owner of that home** (psadm1
   on DPK installs, read from the folder owner during the patch-level check), with its own log
   (`~psadm1/psdash_apply/<job>/apply.log`). A dropped SSH session or closed browser doesn't stop it;
   the dashboard reconnects and keeps following the log.
   * **JDK:** extracts the new JDK, checks its version, merges certificates from the current
     `cacerts`, swaps it in at the same path, verifies, and restores the old one if verification
     fails. The old JDK is kept as `jdk.bak.<timestamp>`.
   * **WebLogic:** backs up the WebLogic home to `bea.bak.<timestamp>.tar.gz` (after a free-space
     check), runs the Stack Patch Bundle tool if the download is an SPB, otherwise an OPatch conflict
     check and `opatch apply` for each patch, then confirms the target patch IDs are listed.
   * **Oracle Database Client:** backs up the client home, upgrades OPatch from patch 6880880 (19c
     build, downloaded together with the Release Update) when the home's OPatch is older, then runs
     the OPatch conflict check and `opatch apply`, and confirms the RU is listed. The previous OPatch
     is kept as `OPatch.bak.<timestamp>`.
   * **Tuxedo:** backs up the Tuxedo home, applies the rolling patch with OPatch, and confirms the
     patch level with `tmadmin -v`.
3. If a server fails, the remaining servers are left alone. The failing step and the backup
   location are in the output.
4. Starts every domain (app, process scheduler, web), runs status, and re-checks patch levels.

PRD environments ask you to type the environment name first. Backups are not deleted
automatically; remove old `*.bak.*` files once you're happy with the patch.

If a download from Oracle Support fails (the sign-in flow changes from time to time), download the
zip in a browser, put it in `data/patches/<patch number>/`, and stage again. Files already in that
folder are always used instead of downloading.

This machine needs HTTPS access to `updates.oracle.com`, `login.oracle.com` and `java.oraclecloud.com`.

## Access: adding people's SSH keys

The **Access** section adds a person's SSH public key to the servers, so they can sign in with their own key, and
takes it off again when they no longer need access.

1. Paste their public key, drop their `.pub` file on the box, or choose the file. Pegasus shows the name in the key
   and its fingerprint, and refuses private keys, PuTTY-format keys (it says how to convert them), damaged or
   truncated keys, keys with `from=`/`command=` options, and RSA keys under 2048 bits. A key pasted across several
   lines is joined back together.
2. Leave **Account on the servers** blank to use your SSH user (usually `opc`), or enter another account such as
   `psadm1`. For another account, your SSH user needs a passwordless sudo rule for it, e.g.
   `opc ALL=(psadm1) NOPASSWD: ALL`. Pegasus won't add keys for root.
3. Tick the environments, add a reason or ticket number, and click **Add key**, **Check servers** or **Remove key**.
   Production environments ask you to type their name first.

On each server Pegasus backs up `authorized_keys` to `authorized_keys.bak.<timestamp>` before changing it, appends
the key on its own line (adding a missing newline first so the previous key isn't damaged), never adds a key that's
already there, sets `~/.ssh` to 700 and the file to 600, and restores the SELinux context. Removing a key takes out
only that key's line. The console shows the result for every server (added, exists, removed, not present, or the
error), and each run is in **Activity**.

**Keys added through Pegasus** lists every key Pegasus has added, with the account, environments, servers, who added
it and why. **Check** confirms it's still on those servers, and **Remove** takes it off all of them. The list is kept in
`data/access_keys.json`.

## Change approval with Jira

With approval switched on, **Apply doesn't patch anything by itself**. The Apply button becomes **Request
approval**, which raises a Jira ticket, and Apply only unlocks once that ticket is approved.

**Setting it up** (Patching tab, **Change approval (Jira)**):

| Setting | What to enter |
|---|---|
| Required for | Every environment, or production (PRD) only |
| Jira type | **Jira Cloud** signs in with an account email and an API token (id.atlassian.com → Security → API tokens). **Jira Data Center / Server** uses a personal access token (Profile → Personal Access Tokens). |
| Jira URL | e.g. `https://yourcompany.atlassian.net` |
| Project key / Issue type | Where tickets go. Use your Jira Service Management change project and the **Change** issue type, so the ticket goes through your normal change approval. |
| Default change type | `Normal`, `Standard` or `Emergency`. You can pick a different one each time you request approval. |
| Change risk, Impact, Urgency | Optional. Filled in on each ticket when your Change form has these fields. Values must match the options in Jira. |
| Send for approval with transition | Optional. A transition Pegasus runs right after creating the ticket, e.g. `Submit for approval`, if your workflow needs one to start approval. |
| Statuses that mean approved / rejected | Match your Jira workflow, e.g. `Approved, Awaiting implementation` and `Rejected, Declined` |
| Transitions (optional) | Moved automatically when the apply starts (e.g. `Start Progress`) and when it succeeds (e.g. `Done`) |
| Additional fields (optional) | JSON merged into each new ticket, for fields your project requires, e.g. `{"labels": ["pegasus"], "priority": {"name": "High"}, "customfield_10050": {"value": "Standard"}}` |

**Change tickets.** Pegasus finds your project's Change fields by name, because their IDs differ from one Jira
site to another. It fills in **Change type**, **Change risk**, **Impact**, **Urgency**, **Planned start** and **Planned end**
where the form has them. **Test connection** lists the fields Pegasus will fill in, and warns you about any other
required fields on your Change form, with their field ID and allowed values, so you can add them under Additional fields
(e.g. `{"customfield_10050": {"value": "Maintenance"}}`).

**Approvals in Jira Service Management.** If the project is a service project, Pegasus reads the ticket's approval
steps directly. Any step still waiting means not approved yet. The latest completed step decides: approved unlocks Apply,
declined blocks it. The approver must be someone other than the Pegasus account. For other Jira projects, the status
names above decide.

Use a dedicated service account for Pegasus (e.g. `pegasus-bot@yourcompany.com`) that can create, comment on and
transition issues in the project, but that nobody uses to approve changes. Click **Test connection** after saving.

The token goes in the operating system's credential store, like the Oracle Support password. If there isn't one,
set `PSDASH_JIRA_TOKEN` in `~/.psdash.env` (or the Windows environment), otherwise the token is kept in memory until
Pegasus restarts.

**How it works:**

1. Download the update(s) as usual. A ticket can only be raised once the files are staged, so it shows exactly what
   will be applied.
2. Click **Request approval** (per component, or **all outstanding updates**). Set the planned start and end (the
   default is next Saturday, 8 PM to 11 PM), pick the change type, add notes for the approver, and click **Raise Jira
   ticket**. If you set a submit transition, Pegasus also sends the ticket for approval. The ticket lists each component, version and server, the outage,
   the backups taken and the backout.
3. The row shows the ticket number and its Jira status. Use **Check now** to refresh, or **Withdraw** to cancel.
4. When the ticket reaches an approved status, the row shows who approved it and **Apply** appears.
5. When you click Apply, Pegasus asks Jira again before stopping anything. It refuses if:
   * the ticket isn't in an approved status, or has been rejected,
   * it was moved to approved by the Pegasus account itself, or Pegasus can't tell who approved it (turn off
     "Don't accept approvals made by the Jira account above" only if your workflow approves another way),
   * the plan has changed since the ticket was raised (different updates or servers), or
   * the ticket has already been used for an apply.
6. Pegasus comments on the ticket when the apply starts and when it finishes (succeeded or failed, with the last
   40 lines of the log), and runs the transitions you set.

The check is enforced by the server, not the page, so the API can't be used to apply without an approved ticket.
Changes to the approval settings are recorded in `logs/actions.log`. Anyone who can sign in to Pegasus can
change these settings, so keep the dashboard password limited to the people who run patching.

Start, stop and restart from the Environments tab don't need approval.

## Updating Pegasus (Windows)

Stop Pegasus, download the new `ps-admin-dashboard.zip` to your Downloads folder, and double-click
`update.bat`. It copies the new program files over this folder, installs any new libraries, and leaves
`data\` and `logs\` alone. Then start Pegasus with `start.bat`.

## Saved credentials

The SSH connection box and the Oracle Support sign-in box both have **Remember on this machine**
(ticked by default). When it's ticked:

* the SSH user ID and key path are written to `data/saved_credentials.json`. The private key file
  itself is never copied; keep it where it is and keep its permissions tight.
* the key passphrase and the Oracle Support password go in the operating system's credential store
  (Windows Credential Manager, under "psdash-peoplesoft-dashboard"), never in a file. They belong to
  the Windows account that runs `app.py`.
* after a restart, signing in to the dashboard restores them automatically.

Each box has a **Forget** link to remove what's saved. If no secure credential store is available
(for example a Linux host without a keyring), the user ID and key path are still saved, but
passwords aren't, and the dashboard says so.

## Server-side requirements

* **Host keys:** the admin host must already trust each server's SSH host key. You can SSH to
  each server once by hand, or run `ssh-keyscan <host> >> ~/.ssh/known_hosts` as the OS user
  that runs the dashboard. Setting `PSDASH_STRICT_HOST_KEYS=false` accepts unknown keys, but
  isn't recommended.
* **sudo to the PeopleSoft owner:** if your SSH user (e.g. `opc`) is different from the row's
  `os_user` (e.g. `psadm2`), the command runs as `sudo -n -iu psadm2 bash -lc '...'`.
  This needs a passwordless sudo rule such as:
  `opc ALL=(psadm2) NOPASSWD: ALL`
  If you SSH in directly as the PeopleSoft owner, leave `os_user` blank or set it to the
  same name as the SSH user.
* **Environment script:** set `env_script` to the path of `psconfig.sh`. The dashboard sources it
  so that `PS_HOME`, `PS_CFG_HOME` and the path to `psadmin` are set. If `env_script` is blank,
  the user's login profile has to set them.

## What each button runs

| Role | Start | Stop | Status |
|---|---|---|---|
| app | `psadmin -c boot -d DOM` | `psadmin -c shutdown -d DOM` | `psadmin -c sstatus -d DOM` |
| prcs | `psadmin -p start -d DOM` | `psadmin -p stop -d DOM` | `psadmin -p status -d DOM` |
| web | `psadmin -w start -d DOM` | `psadmin -w shutdown -d DOM` | `psadmin -w status -d DOM` |

* **Start all** goes app, then prcs, then web. **Stop all** goes web, then prcs, then app.
  **Restart all** runs Stop all, then Start all.
* A start or stop sequence stops at the first step that fails, so you can check the output.
  Stopping a domain that's already down may return an error, which also stops the sequence.
* For environments with tier `PRD`, you have to type the environment name before a stop or
  restart runs.
* The commands are in the `COMMANDS` table near the top of `app.py`. Change them there,
  for example to `shutdown!` for a forced app server shutdown.

## Safety notes

* Only the commands in `COMMANDS` can run. Domain names, users and paths from the CSV are
  validated and shell-quoted. Nothing typed in the browser is run as a command.
* The private key stays on the admin host. The browser only sends its path.
* Sessions use an HttpOnly, SameSite=Strict cookie. Set `PSDASH_SECRET` to keep sessions
  valid across restarts.

## Settings (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PSDASH_PASSWORD` | (required) | Dashboard sign-in password |
| `PSDASH_HOST` / `PSDASH_PORT` | `127.0.0.1` / `8080` | Address and port to listen on |
| `PSDASH_DATA` / `PSDASH_LOGS` | `./data` / `./logs` | Where the CSV and logs are kept |
| `PSDASH_ACTION_TIMEOUT` | `900` | Seconds allowed for each server step |
| `PSDASH_STRICT_HOST_KEYS` | `true` | Reject servers that aren't in known_hosts |
| `PSDASH_SECRET` | random | Key used to sign sessions |
| `PSDASH_JIRA_TOKEN` | (none) | Jira API token or personal access token, if you'd rather not save it in the credential store |
