#!/usr/bin/env bash
set -euo pipefail

SNAPPYMAIL_VERSION="2.38.2"
MAIL_HOST="${1:-mail.example.com}"
WEB_ROOT="/var/www/snappymail"
DATA_ROOT="/var/lib/snappymail"
ARCHIVE="/tmp/snappymail-${SNAPPYMAIL_VERSION}.tar.gz"

if [[ ! "$MAIL_HOST" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$ ]]; then
  echo "Invalid mail hostname" >&2
  exit 2
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl ca-certificates php8.3-fpm php8.3-curl php8.3-xml php8.3-mbstring php8.3-intl php8.3-zip
curl --fail --location --proto '=https' --tlsv1.2 \
  "https://github.com/the-djmaze/snappymail/releases/download/v${SNAPPYMAIL_VERSION}/snappymail-${SNAPPYMAIL_VERSION}.tar.gz" \
  --output "$ARCHIVE"

install -d -m 0755 "$WEB_ROOT"
find "$WEB_ROOT" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
tar -xzf "$ARCHIVE" -C "$WEB_ROOT"
if [[ ! -d "$DATA_ROOT/_data_" ]]; then
  install -d -m 0750 -o www-data -g www-data "$DATA_ROOT"
  cp -a "$WEB_ROOT/data/." "$DATA_ROOT/"
fi
rm -rf "$WEB_ROOT/data"
ln -s "$DATA_ROOT" "$WEB_ROOT/data"
chown -R www-data:www-data "$WEB_ROOT"
chown -R www-data:www-data "$DATA_ROOT"
find "$WEB_ROOT" -type d -exec chmod 0755 {} +
find "$WEB_ROOT" -type f -exec chmod 0644 {} +

cat > /etc/nginx/sites-available/masspanel-mail <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${MAIL_HOST};
  root ${WEB_ROOT};
  location ^~ /.well-known/acme-challenge/ { try_files \$uri =404; }
  location / { return 301 https://\$host\$request_uri; }
}
server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name ${MAIL_HOST};
  root ${WEB_ROOT};
  index index.php;
  ssl_certificate /etc/letsencrypt/live/${MAIL_HOST}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${MAIL_HOST}/privkey.pem;
  location ^~ /_data_ { deny all; }
  location ~ /\. { deny all; }
  location / { try_files \$uri \$uri/ /index.php?\$query_string; }
  location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.3-fpm.sock;
  }
}
EOF

ln -sfn /etc/nginx/sites-available/masspanel-mail /etc/nginx/sites-enabled/masspanel-mail
nginx -t
systemctl enable --now php8.3-fpm
systemctl reload php8.3-fpm nginx
# MassPanel manages this installation; keep SnappyMail's separate admin console closed.
curl --fail --silent --show-error --resolve "${MAIL_HOST}:443:127.0.0.1" "https://${MAIL_HOST}/" >/dev/null
if [[ -f "$DATA_ROOT/_data_/_default_/configs/application.ini" ]]; then
  sed -i 's/^allow_admin_panel = .*/allow_admin_panel = Off/' "$DATA_ROOT/_data_/_default_/configs/application.ini"
fi
rm -f "$ARCHIVE"
echo "SnappyMail ${SNAPPYMAIL_VERSION} installed at https://${MAIL_HOST}/"
