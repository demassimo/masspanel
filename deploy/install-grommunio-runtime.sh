#!/usr/bin/env bash
set -Eeuo pipefail
test "${EUID}" -eq 0
export DEBIAN_FRONTEND=noninteractive
stage=${MASSPANEL_STAGE_DIR:-/tmp/masspanel-stage}
apt-get install -y --no-install-recommends curl ca-certificates gnupg software-properties-common
add-apt-repository -y universe
curl --fail --show-error --location --proto '=https' --tlsv1.2 https://download.grommunio.com/RPM-GPG-KEY-grommunio | gpg --dearmor --yes --output /usr/share/keyrings/download.grommunio.com.gpg
cat > /etc/apt/sources.list.d/grommunio.sources <<'EOF'
Types: deb
URIs: https://download.grommunio.com/community/Ubuntu_24.04
Suites: Ubuntu_24.04
Components: main
Signed-By: /usr/share/keyrings/download.grommunio.com.gpg
EOF
apt-get update
apt-get install -y --no-install-recommends gromox grommunio-web grommunio-admin-api grommunio-sync grommunio-dav postfix rspamd clamav-daemon certbot
install -d -m 0755 /etc/grommunio-common/ssl /var/www/snappymail
for unit in mariadb postfix rspamd gromox-http gromox-imap gromox-pop3 grommunio-admin-api; do systemctl enable --now "$unit" 2>/dev/null || true; done
if [[ -x "$stage/deploy/configure-gromox-smtp-auth.sh" ]]; then "$stage/deploy/configure-gromox-smtp-auth.sh"; fi
command -v grommunio-admin >/dev/null
command -v gromox-mbop >/dev/null

