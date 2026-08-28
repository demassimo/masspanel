#!/usr/bin/env bash
set -Eeuo pipefail
test "${EUID}" -eq 0
stage=${MASSPANEL_STAGE_DIR:-/tmp/masspanel-stage}
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends unzip curl php8.3-fpm
ADMINNEO_VERSION=5.7.0
FILEBROWSER_VERSION=1.5.3-stable
curl -fsSL "https://www.adminneo.org/files/${ADMINNEO_VERSION}/mysql_en_default-blue/adminneo-${ADMINNEO_VERSION}.zip" -o /tmp/adminneo.zip
curl -fsSL "https://github.com/gtsteffaniak/filebrowser/releases/download/v${FILEBROWSER_VERSION}/linux-amd64-filebrowser" -o /tmp/masspanel-filebrowser
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
unzip -q /tmp/adminneo.zip -d "$work"
install -d -m 0755 /opt/masspanel/tools/adminneo /etc/masspanel /var/lib/masspanel/filebrowser /etc/nginx/snippets
install -m 0644 "$work/adminneo-${ADMINNEO_VERSION}.php" /opt/masspanel/tools/adminneo/index.php
install -m 0644 "$stage/deploy/adminneo-config.php" /opt/masspanel/tools/adminneo/adminneo-config.php
install -m 0644 "$stage/deploy/adminneo-plugins.php" /opt/masspanel/tools/adminneo/adminneo-plugins.php
for plugin in ExternalLoginPlugin FrameSupportPlugin JsonPreviewPlugin; do install -m 0644 "$work/adminneo-plugins/${plugin}.php" "/opt/masspanel/tools/adminneo/${plugin}.php"; done
install -m 0755 /tmp/masspanel-filebrowser /usr/local/bin/masspanel-filebrowser
install -m 0640 "$stage/deploy/filebrowser-config.yaml" /etc/masspanel/filebrowser.yaml
install -m 0644 "$stage/deploy/masspanel-filebrowser.service" /etc/systemd/system/masspanel-filebrowser.service
install -m 0644 "$stage/deploy/masspanel-tools.conf" /etc/nginx/snippets/masspanel-tools.conf
systemctl daemon-reload
systemctl enable --now masspanel-filebrowser php8.3-fpm
