#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID} -eq 0 ]] || { echo 'Run: sudo ./setup.sh' >&2; exit 1; }
root=$(cd "$(dirname "$0")" && pwd)
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo 'MassPanel requires Ubuntu 24.04 LTS.' >&2; exit 2; }
[[ ! -e /etc/masspanel/installation-complete.json ]] || { echo 'MassPanel is already installed.' >&2; exit 3; }
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 ca-certificates curl openssl
install -d -m 0700 /opt/masspanel-installer
install -d -m 0700 /opt/masspanel-installer/stage
cp -a "$root/." /opt/masspanel-installer/stage/
chmod 0755 /opt/masspanel-installer/stage/setup.sh /opt/masspanel-installer/stage/installer/*.py /opt/masspanel-installer/stage/installer/*.sh /opt/masspanel-installer/stage/deploy/*.sh
token=$(openssl rand -hex 24)
install -d -m 0750 /etc/masspanel
printf 'MASSPANEL_INSTALL_TOKEN=%s\nMASSPANEL_INSTALL_STAGE=/opt/masspanel-installer/stage\n' "$token" > /etc/masspanel/installer.env
chmod 0600 /etc/masspanel/installer.env
install -m 0644 /opt/masspanel-installer/stage/installer/masspanel-installer.service /etc/systemd/system/masspanel-installer.service
systemctl daemon-reload
systemctl enable --now masspanel-installer
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then ufw allow 8080/tcp; fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --permanent --add-port=8080/tcp; firewall-cmd --reload; fi
ip=$(hostname -I | awk '{print $1}')
echo
echo "Open this one-time setup URL:"
echo "http://${ip}:8080/?token=${token}"
echo
echo 'Port 8080 is disabled automatically after a successful installation.'
