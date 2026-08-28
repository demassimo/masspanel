#!/usr/bin/env bash
set -euo pipefail
test "${EUID}" -eq 0
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends bind9 bind9-utils
install -d -m 0755 -o bind -g bind /var/lib/bind/masspanel
touch /etc/bind/masspanel-zones.conf
chown root:bind /etc/bind/masspanel-zones.conf
chmod 0644 /etc/bind/masspanel-zones.conf
if ! grep -Fq 'include "/etc/bind/masspanel-zones.conf";' /etc/bind/named.conf.local; then
  printf '\ninclude "/etc/bind/masspanel-zones.conf";\n' >> /etc/bind/named.conf.local
fi
named-checkconf
systemctl enable --now named
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow 53/tcp
  ufw allow 53/udp
fi
