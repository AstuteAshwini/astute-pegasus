#!/usr/bin/env bash
# Update the control plane to the latest code on GitHub and restart it.   sudo bash /opt/pegasus/app/deploy/oci/update.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
cd /opt/pegasus
/usr/local/sbin/pegasus-backup
sudo -u pegasus git -C /opt/pegasus/app pull -q --ff-only
sudo -u pegasus /opt/pegasus/venv/bin/pip install -q -r /opt/pegasus/app/control-plane/requirements.txt
systemctl restart pegasus
sleep 2
journalctl -u pegasus -n 3 --no-pager
