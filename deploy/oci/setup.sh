#!/usr/bin/env bash
# Pegasus control plane on an Oracle Linux 8/9 VM: Pegasus as a service behind Caddy (HTTPS from Let's Encrypt,
# renewed automatically), the OS firewall opened for 80/443, and nightly backups.
#
#   sudo bash setup.sh pegasus.beastute.com you@beastute.com
#
# The DNS record for the name must already point at this VM's public IP (Let's Encrypt checks it), and the subnet
# must allow TCP 80 and 443 in. Safe to run again: it updates the code and keeps the data.
set -euo pipefail
DOMAIN="${1:?usage: sudo bash setup.sh <domain> <email for certificate notices>}"
EMAIL="${2:?usage: sudo bash setup.sh <domain> <email for certificate notices>}"
REPO="${PEGASUS_REPO:-https://github.com/AstuteAshwini/astute-pegasus}"
CADDY_VERSION=2.8.4
APP=/opt/pegasus/app VENV=/opt/pegasus/venv DATA=/var/lib/pegasus ETC=/etc/pegasus BACKUPS=/var/backups/pegasus
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
here="$(cd "$(dirname "$0")" && pwd)"

echo "== Packages"
dnf install -y -q git python3.11 python3.11-pip tar firewalld >/dev/null
systemctl enable --now firewalld >/dev/null

echo "== Firewall: http and https"
firewall-cmd -q --permanent --add-service=http --add-service=https
firewall-cmd -q --reload

echo "== Pegasus account and folders"
id pegasus >/dev/null 2>&1 || useradd --system --home-dir /opt/pegasus --shell /sbin/nologin pegasus
install -d -o pegasus -g pegasus -m 750 /opt/pegasus "$DATA"
install -d -o root -g pegasus -m 750 "$ETC"
install -d -o root -g root -m 700 "$BACKUPS"
cd /opt/pegasus          # the pegasus account can't read the folder sudo was started from

echo "== Code"
if [ -d "$APP/.git" ]; then
  sudo -u pegasus git -C "$APP" pull -q --ff-only
else
  sudo -u pegasus git clone -q "$REPO" "$APP"
fi
[ -x "$VENV/bin/python" ] || sudo -u pegasus python3.11 -m venv "$VENV"
sudo -u pegasus "$VENV/bin/pip" install -q --upgrade pip
sudo -u pegasus "$VENV/bin/pip" install -q -r "$APP/control-plane/requirements.txt"

echo "== Settings ($ETC/pegasus.env)"
if [ ! -f "$ETC/pegasus.env" ]; then
  cat > "$ETC/pegasus.env" <<ENV
PEGASUS_DATA=$DATA
PEGASUS_HOST=127.0.0.1
PEGASUS_PORT=8443
PEGASUS_PUBLIC_URL=https://$DOMAIN
PEGASUS_COOKIE_SECURE=true
PEGASUS_TRUST_PROXY=true
PEGASUS_ADMIN_LOCAL_ONLY=false
# Only needed to create the first admin on an empty install (not when you import your existing data):
# PEGASUS_ADMIN_PASSWORD=
ENV
fi
chown root:pegasus "$ETC/pegasus.env"; chmod 640 "$ETC/pegasus.env"

echo "== Pegasus service"
install -m 644 "$here/pegasus.service" /etc/systemd/system/pegasus.service

echo "== Caddy $CADDY_VERSION (HTTPS)"
case "$(uname -m)" in
  x86_64) arch=amd64; sum=b8bec15d14fb033562af9f207850027bcbaa1f891edc9efe00d38bf39e1bf9944f8b6b8eba041ddd4c171cd70c905174c704d705be2f23bc678fe1eaf37a2485 ;;
  aarch64) arch=arm64; sum=5466234be3e988071cef937aedbdd94c15b6f75cf7307397e67c2641219ac9bfe2c2bb3b31fc05bc68d3b6398bbe50abfa16ccf3b127318ccac31115ad26507c ;;
  *) echo "Unsupported CPU $(uname -m)"; exit 1 ;;
esac
if ! /usr/local/bin/caddy version 2>/dev/null | grep -q "v$CADDY_VERSION"; then
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/caddy.tgz" "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_$arch.tar.gz"
  echo "$sum  $tmp/caddy.tgz" | sha512sum -c --quiet
  tar -xzf "$tmp/caddy.tgz" -C "$tmp" caddy
  install -m 755 "$tmp/caddy" /usr/local/bin/caddy
  restorecon -q /usr/local/bin/caddy 2>/dev/null || true
  rm -rf "$tmp"
fi
id caddy >/dev/null 2>&1 || useradd --system --home-dir /var/lib/caddy --create-home --shell /sbin/nologin caddy
install -d -o root -g root -m 755 /etc/caddy
sed -e "s/__DOMAIN__/$DOMAIN/g" -e "s/__EMAIL__/$EMAIL/g" "$here/Caddyfile" > /etc/caddy/Caddyfile
install -m 644 "$here/caddy.service" /etc/systemd/system/caddy.service
# SELinux: let Caddy connect to Pegasus on 127.0.0.1:8443
setsebool -P httpd_can_network_connect 1 2>/dev/null || true

echo "== Nightly backups"
install -m 750 "$here/backup.sh" /usr/local/sbin/pegasus-backup
install -m 644 "$here/pegasus-backup.service" "$here/pegasus-backup.timer" /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now pegasus caddy pegasus-backup.timer >/dev/null
systemctl restart pegasus caddy
sleep 3
systemctl --no-pager --lines=0 status pegasus caddy | grep -E "Active:|●"
echo
echo "Done. Open https://$DOMAIN (the first visit can take a minute while the certificate is issued)."
echo "Logs: journalctl -u pegasus -f    Certificate: journalctl -u caddy -f"
