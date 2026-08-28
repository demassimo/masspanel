#!/usr/bin/env bash
set -euo pipefail
test "${EUID}" -eq 0
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends mariadb-server php8.3-fpm php8.3-mysql php8.3-curl php8.3-gd php8.3-intl php8.3-mbstring php8.3-xml php8.3-zip curl ca-certificates acl certbot bzip2
curl --fail --show-error --location --retry 3 --connect-timeout 15 --max-time 180 \
  https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp
chmod 0755 /usr/local/bin/wp
/usr/local/bin/wp --allow-root --info >/dev/null
systemctl enable --now mariadb php8.3-fpm
