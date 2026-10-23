#!/usr/bin/env bash
# Update the control plane to the latest code on GitHub and restart it.   sudo bash /opt/pegasus/app/deploy/oci/update.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
cd /opt/pegasus
sudo -u pegasus git -C /opt/pegasus/app pull -q --ff-only
install -m 750 /opt/pegasus/app/deploy/oci/backup.sh /usr/local/sbin/pegasus-backup
/usr/local/sbin/pegasus-backup                     # data as it was before the new code runs
chown -R pegasus:pegasus /var/lib/pegasus
sudo -u pegasus /opt/pegasus/venv/bin/pip install -q -r /opt/pegasus/app/control-plane/requirements.txt
systemctl restart pegasus
sleep 3
systemctl --no-pager --lines=0 status pegasus | grep -E "Active:"
journalctl -u pegasus -n 3 --no-pager
