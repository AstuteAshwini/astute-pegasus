#!/usr/bin/env bash
# Publish a connector release built on your laptop (where the release key lives):
#   laptop:  python scripts\connector_release.py build --notes "..."
#            scp -r c:\astute-pegasus\control-plane\data\releases\<version> opc@<vm>:/tmp/
#   VM:      sudo bash /opt/pegasus/app/deploy/oci/publish-release.sh /tmp/<version>
# Pegasus checks the signature and offers it straight away; connectors check it again against their built-in key.
set -euo pipefail
SRC="${1:?usage: sudo bash publish-release.sh /tmp/<version>}"
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }
[ -f "$SRC/release.json" ] && [ -f "$SRC/bundle.zip" ] || { echo "$SRC isn't a release folder (release.json + bundle.zip)."; exit 1; }
v=$(basename "$SRC")
install -d -o pegasus -g pegasus -m 700 /var/lib/pegasus/releases
[ -e "/var/lib/pegasus/releases/$v" ] && { echo "Release $v is already published."; exit 1; }
cp -r "$SRC" "/var/lib/pegasus/releases/$v"
chown -R pegasus:pegasus "/var/lib/pegasus/releases/$v"
rm -rf "$SRC"
echo "Published connector release $v. It shows on each client's Overview tab."
