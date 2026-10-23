#!/usr/bin/env bash
# Nightly backup of the Pegasus control plane: a consistent copy of the database (taken live), the signing key,
# the key that encrypts stored Jira tokens, the session key and the published connector releases. Keeps 14 days.
# The backups contain secrets: they're readable by root only. Copy them off the VM too (Object Storage, for example).
set -euo pipefail
DATA=/var/lib/pegasus BACKUPS=/var/backups/pegasus KEEP_DAYS=14
stamp=$(date +%Y%m%d-%H%M)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ -f "$DATA/pegasus.db" ]; then
  # Read the database as the pegasus account, so nothing in the data folder ends up owned by root.
  chown pegasus "$work"
  runuser -u pegasus -- /opt/pegasus/venv/bin/python - "$DATA/pegasus.db" "$work/pegasus.db" <<'PY'
import sqlite3, sys
src, dst = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True), sqlite3.connect(sys.argv[2])
src.backup(dst)
dst.close(); src.close()
PY
  chown root "$work" "$work/pegasus.db"
else
  echo "No database yet; backing up the keys only."
fi
for f in signing_key.pem secret.key session.key; do [ -f "$DATA/$f" ] && cp -p "$DATA/$f" "$work/"; done
[ -d "$DATA/releases" ] && cp -rp "$DATA/releases" "$work/"
umask 077
tar -czf "$BACKUPS/pegasus-$stamp.tar.gz" -C "$work" .
find "$BACKUPS" -name 'pegasus-*.tar.gz' -mtime +$KEEP_DAYS -delete
echo "Backed up to $BACKUPS/pegasus-$stamp.tar.gz"
