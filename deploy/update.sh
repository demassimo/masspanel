#!/usr/bin/env bash
set -euo pipefail
test "${EUID}" -eq 0

if ! command -v rclone >/dev/null 2>&1 || ! command -v cron >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cron rclone
fi
stage=${MASSPANEL_UPDATE_STAGE:-/tmp/masspanel-update}
test -f "$stage/backend/app.py"
test -f "$stage/backend/license_public.pem"
/opt/masspanel/venv/bin/pip install --disable-pip-version-check --no-cache-dir -r "$stage/backend/requirements.txt"
if test -f "$stage/deploy/write-runtime-lock.py"; then
  install -m 0755 -o root -g root "$stage/deploy/write-runtime-lock.py" /usr/local/libexec/masspanel-write-runtime-lock
  /usr/local/libexec/masspanel-write-runtime-lock
fi
install -m 0640 -o root -g masspanel "$stage/backend/app.py" /opt/masspanel/backend/app.py
install -m 0640 -o root -g masspanel "$stage/backend/helper.py" /opt/masspanel/backend/helper.py
install -m 0750 -o root -g masspanel "$stage/backend/scheduled_backup.py" /opt/masspanel/backend/scheduled_backup.py
install -m 0644 -o root -g masspanel "$stage/backend/license_public.pem" /opt/masspanel/backend/license_public.pem
install -m 0640 -o root -g masspanel "$stage/backend/requirements.txt" /opt/masspanel/backend/requirements.txt
install -m 0755 -o root -g root "$stage/backend/helper.py" /usr/local/libexec/masspanel-helper
if test -f "$stage/deploy/system-mail-sorter.py"; then
  install -m 0755 -o root -g root "$stage/deploy/system-mail-sorter.py" /usr/local/libexec/masspanel-system-mail-sorter
  install -m 0644 -o root -g root "$stage/deploy/masspanel-system-mail-sorter.service" /etc/systemd/system/masspanel-system-mail-sorter.service
  install -m 0644 -o root -g root "$stage/deploy/masspanel-system-mail-sorter.timer" /etc/systemd/system/masspanel-system-mail-sorter.timer
  systemctl daemon-reload
fi
if test -d "$stage/deploy/fail2ban"; then
  if ! dpkg-query -W -f='${Status}\n' fail2ban firewalld 2>/dev/null | grep -c 'install ok installed' | grep -qx '2'; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban firewalld
  fi
  install -m 0644 -o root -g root "$stage/deploy/fail2ban/masspanel-auth.conf" /etc/fail2ban/filter.d/masspanel-auth.conf
  install -m 0644 -o root -g root "$stage/deploy/fail2ban/grommunio-web-auth.conf" /etc/fail2ban/filter.d/grommunio-web-auth.conf
  install -m 0644 -o root -g root "$stage/deploy/fail2ban/masspanel.local" /etc/fail2ban/jail.d/masspanel.local
  install -m 0755 -o root -g root "$stage/deploy/masspanel-fail2ban-ignore" /usr/local/libexec/masspanel-fail2ban-ignore
  fail2ban-client -t
  systemctl enable --now firewalld fail2ban >/dev/null
  systemctl restart fail2ban
fi
if test -f "$stage/deploy/runtime-patches/class.webappauthentication.php" && test -d /usr/share/grommunio-web/server/includes/core; then
  install -m 0644 -o root -g root "$stage/deploy/runtime-patches/class.webappauthentication.php" /usr/share/grommunio-web/server/includes/core/class.webappauthentication.php
fi
install -d -m 0755 -o root -g root /opt/masspanel/frontend/assets
# Hashed assets are immutable. Keep earlier versions so tabs opened before an
# upgrade can finish loading their modules; publish the new HTML entrypoint last.
cp -a "$stage/frontend/dist/assets/." /opt/masspanel/frontend/assets/
find /opt/masspanel/frontend/assets -type f -mtime +30 -delete
find "$stage/frontend/dist" -maxdepth 1 -type f -name '*.html' -exec install -m 0644 -o root -g root {} /opt/masspanel/frontend/ \;
chown -R root:root /opt/masspanel/frontend
install -d -m 0755 -o root -g root /var/www/masspanel-default
printf '%s\n' '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MassPanel hosting</title><style>body{font-family:system-ui;background:#101c2e;color:white;display:grid;place-items:center;min-height:100vh;margin:0}main{text-align:center}p{color:#aebbcf}</style></head><body><main><h1>Website hosting is ready</h1><p>Add a domain from MassPanel on port 8443.</p></main></body></html>' > /var/www/masspanel-default/index.html
install -m 0644 -o root -g root "$stage/deploy/nginx-masspanel.conf" /etc/nginx/sites-available/masspanel
install -d -m 0755 -o root -g root /usr/share/doc/masspanel /usr/share/doc/masspanel/licenses /usr/share/masspanel/source /etc/grommunio-common/nginx/locations.d /etc/nginx/snippets
install -m 0644 -o root -g root "$stage/LICENSE" /usr/share/doc/masspanel/LICENSE
install -m 0644 -o root -g root "$stage/NOTICE" /usr/share/doc/masspanel/NOTICE
install -m 0644 -o root -g root "$stage/SOURCE_OFFER.md" /usr/share/doc/masspanel/SOURCE_OFFER.md
install -m 0644 -o root -g root "$stage/THIRD_PARTY.md" /usr/share/doc/masspanel/THIRD_PARTY.md
install -m 0644 -o root -g root "$stage/third_party/sources.lock.json" /usr/share/doc/masspanel/sources.lock.json
install -m 0644 -o root -g root "$stage/third_party/GROMOX-LICENSE.txt" /usr/share/doc/masspanel/GROMOX-LICENSE.txt
install -m 0644 -o root -g root "$stage/third_party/grommunio-web/LICENSE.txt" /usr/share/doc/masspanel/GROMMUNIO-WEB-LICENSE.txt
install -m 0644 -o root -g root "$stage"/third_party/licenses/* /usr/share/doc/masspanel/licenses/
install -m 0644 -o root -g root "$stage/deploy/masspanel-source.html" /usr/share/doc/masspanel/masspanel-source.html
install -m 0644 -o root -g root "$stage/deploy/masspanel-source-offer.conf" /etc/grommunio-common/nginx/locations.d/05-masspanel-source-offer.conf
install -m 0644 -o root -g root "$stage/deploy/masspanel-panel-source-offer.conf" /etc/nginx/snippets/masspanel-source-offer.conf
for enabled_site in /etc/nginx/sites-enabled/*; do
  test -e "$enabled_site" || continue
  site_config=$(readlink -f "$enabled_site")
  grep -q 'root /opt/masspanel/frontend' "$site_config" || continue
  grep -q 'location = /masspanel-source' "$site_config" && continue
  grep -q 'include /etc/nginx/snippets/masspanel-source-offer.conf;' "$site_config" || \
    sed -i '/^[[:space:]]*location \/api\//i\    include /etc/nginx/snippets/masspanel-source-offer.conf;' "$site_config"
done
find "$stage/third_party/source-archives" -maxdepth 1 -type f ! -name 'gromox-container-0.0.4.tar.gz' -exec install -m 0644 -o root -g root {} /usr/share/masspanel/source/ \;
tar --exclude='./third_party/source-archives/gromox-container-0.0.4.tar.gz' -czf /usr/share/masspanel/source/masspanel-corresponding-source.tar.gz -C "$stage" .
chmod 0644 /usr/share/masspanel/source/masspanel-corresponding-source.tar.gz
/opt/masspanel/venv/bin/python -m py_compile /opt/masspanel/backend/app.py /opt/masspanel/backend/helper.py /opt/masspanel/backend/scheduled_backup.py
nginx -t
systemctl restart masspanel
systemctl reload nginx
systemctl enable masspanel nginx >/dev/null
if test -x "$stage/deploy/install-mail-security.sh"; then
  "$stage/deploy/install-mail-security.sh"
fi
if test -x "$stage/deploy/install-updater.sh"; then
  MASSPANEL_STAGE_DIR="$stage" "$stage/deploy/install-updater.sh"
fi
