#!/bin/sh
set -eu

sudo -S -p '' true
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip

ADMINNEO_VERSION=5.7.0
FILEBROWSER_VERSION=1.5.3-stable
ADMINNEO_URL="https://www.adminneo.org/files/${ADMINNEO_VERSION}/mysql_en_default-blue/adminneo-${ADMINNEO_VERSION}.zip"
FILEBROWSER_URL="https://github.com/gtsteffaniak/filebrowser/releases/download/v${FILEBROWSER_VERSION}/linux-amd64-filebrowser"

curl -fsSL "$ADMINNEO_URL" -o /tmp/adminneo.zip
curl -fsSL "$FILEBROWSER_URL" -o /tmp/masspanel-filebrowser

rm -rf /tmp/adminneo-unpack
mkdir -p /tmp/adminneo-unpack
unzip -q /tmp/adminneo.zip -d /tmp/adminneo-unpack

sudo install -d -o root -g root -m 0755 /opt/masspanel/tools/adminneo /etc/masspanel /var/lib/masspanel/filebrowser
sudo install -o root -g root -m 0644 "/tmp/adminneo-unpack/adminneo-${ADMINNEO_VERSION}.php" /opt/masspanel/tools/adminneo/index.php
sudo install -o root -g root -m 0644 /tmp/adminneo-config.php /opt/masspanel/tools/adminneo/adminneo-config.php
sudo install -o root -g root -m 0644 /tmp/adminneo-plugins.php /opt/masspanel/tools/adminneo/adminneo-plugins.php
for plugin in ExternalLoginPlugin FrameSupportPlugin JsonPreviewPlugin; do
    sudo install -o root -g root -m 0644 "/tmp/adminneo-unpack/adminneo-plugins/${plugin}.php" "/opt/masspanel/tools/adminneo/${plugin}.php"
done

sudo install -o root -g root -m 0755 /tmp/masspanel-filebrowser /usr/local/bin/masspanel-filebrowser
sudo install -o root -g root -m 0640 /tmp/filebrowser-config.yaml /etc/masspanel/filebrowser.yaml
sudo install -o root -g root -m 0644 /tmp/masspanel-filebrowser.service /etc/systemd/system/masspanel-filebrowser.service
sudo install -d -o root -g root -m 0755 /etc/nginx/snippets
sudo install -o root -g root -m 0644 /tmp/masspanel-tools.conf /etc/nginx/snippets/masspanel-tools.conf

for config in /etc/nginx/sites-available/masspanel-panel-host /etc/nginx/sites-available/masspanel-panel-legacy; do
    [ -f "$config" ] || continue
    if ! grep -q 'masspanel-tools.conf' "$config"; then
        sudo sed -i '/root \/opt\/masspanel\/frontend;/a\    include /etc/nginx/snippets/masspanel-tools.conf;' "$config"
    fi
done

sudo systemctl daemon-reload
sudo systemctl enable --now masspanel-filebrowser
sudo nginx -t
sudo systemctl reload nginx

ADMINNEO_SHA=$(sha256sum /tmp/adminneo.zip | awk '{print $1}')
FILEBROWSER_SHA=$(sha256sum /tmp/masspanel-filebrowser | awk '{print $1}')
sudo tee /opt/masspanel/THIRD_PARTY_COMPONENTS.md >/dev/null <<EOF
# Bundled third-party components

- AdminNeo ${ADMINNEO_VERSION} - Apache-2.0 or GPL-2.0 - https://github.com/adminneo-org/adminneo - archive SHA-256: ${ADMINNEO_SHA}
- FileBrowser Quantum ${FILEBROWSER_VERSION} - Apache-2.0 - https://github.com/gtsteffaniak/filebrowser - binary SHA-256: ${FILEBROWSER_SHA}
EOF

curl -fsS --unix-socket /run/masspanel-filebrowser/filebrowser.sock http://localhost/file-tool/ >/dev/null
systemctl is-active masspanel-filebrowser php8.3-fpm nginx
