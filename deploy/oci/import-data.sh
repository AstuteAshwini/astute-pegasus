#!/usr/bin/env bash
# Move the control plane's data from your laptop onto this VM: clients, connectors (with their certificates), users,
# inventory, jobs, Jira settings, the signing key and connector releases. Connectors keep working without
# re-registering because the signing key comes along; only their URL changes.
#
#   1. Stop Pegasus on the laptop (Ctrl+C), then copy its data folder here:
#        scp -r c:\astute-pegasus\control-plane\data opc@<vm>:/tmp/pegasus-data
#   2. sudo bash import-data.sh /tmp/pegasus-data
set -euo pipefail
SRC="${1:?usage: sudo bash import-data.sh <folder copied from the laptop>}"
DATA=/var/lib/pegasus
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
[ -f "$SRC/pegasus.db" ] && [ -f "$SRC/signing_key.pem" ] || { echo "$SRC doesn't look like a Pegasus data folder (no pegasus.db / signing_key.pem)."; exit 1; }
systemctl stop pegasus
if [ -f "$DATA/pegasus.db" ]; then
  keep="/var/backups/pegasus/before-import-$(date +%Y%m%d-%H%M)"
  mkdir -p "$keep"; cp -rp "$DATA"/. "$keep"/
  echo "Kept what was here in $keep"
fi
find "$DATA" -mindepth 1 -delete
cp -r "$SRC"/. "$DATA"/
rm -rf "$DATA/logs"
chown -R pegasus:pegasus "$DATA"
chmod -R go-rwx "$DATA"
restorecon -Rq "$DATA" 2>/dev/null || true
systemctl start pegasus
sleep 2
journalctl -u pegasus -n 5 --no-pager
rm -rf "$SRC"
echo "Imported. Removed $SRC (it contained keys). Sign in with your usual email, password and authenticator code."
