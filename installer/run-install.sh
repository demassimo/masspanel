#!/usr/bin/env bash
set -Eeuo pipefail
stage=${MASSPANEL_INSTALL_STAGE:?}
panel_host=${MASSPANEL_PANEL_HOST:?}
mail_host=${MASSPANEL_MAIL_HOST:?}
admin_user=${MASSPANEL_ADMIN_USER:?}
admin_password=${MASSPANEL_ADMIN_PASSWORD:?}
cert_email=${MASSPANEL_CERT_EMAIL:?}
panel_name=${MASSPANEL_PANEL_NAME:?}
export DEBIAN_FRONTEND=noninteractive MASSPANEL_STAGE_DIR="$stage" MASSPANEL_PUBLIC_HOST="$panel_host" MASSPANEL_ADMIN_USERNAME="$admin_user" MASSPANEL_INITIAL_PASSWORD="$admin_password" MASSPANEL_MAIL_HOST="$mail_host"
trap 'echo "Installation failed at line $LINENO."' ERR
echo 'PROGRESS:5:Checking Ubuntu and DNS…'
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || { echo 'MassPanel requires a clean Ubuntu 24.04 LTS server.'; exit 2; }
server_ip=$(curl -4fsS --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')
for host in "$panel_host" "$mail_host"; do getent ahostsv4 "$host" | awk '{print $1}' | grep -Fxq "$server_ip" || { echo "DNS for $host does not point to $server_ip."; exit 3; }; done
echo 'PROGRESS:12:Installing the MassPanel core…'
"$stage/deploy/install.sh"
echo 'PROGRESS:30:Installing website and database services…'
"$stage/deploy/install-app-runtime.sh"
echo 'PROGRESS:42:Installing authoritative DNS…'
"$stage/deploy/install-dns-runtime.sh"
echo 'PROGRESS:50:Installing Grommunio and Gromox…'
"$stage/deploy/install-grommunio-runtime.sh"
echo 'PROGRESS:65:Installing management and security tools…'
"$stage/deploy/install-integrated-tools-root.sh"
"$stage/deploy/install-mail-security.sh"
echo 'PROGRESS:75:Saving server identity…'
set -a; . /etc/masspanel/masspanel.env; set +a
/opt/masspanel/venv/bin/python - "$panel_host" "$mail_host" "$panel_name" "$cert_email" <<'PY'
import os,sqlite3,sys
db=os.path.join(os.environ['MASSPANEL_STATE_DIR'],'masspanel.db'); stamp='installer'
with sqlite3.connect(db) as c:
 for key,value in {'public_url':'https://'+sys.argv[1],'mail_hostname':sys.argv[2],'panel_name':sys.argv[3],'company_name':sys.argv[3],'support_email':sys.argv[4]}.items():
  c.execute("INSERT INTO panel_settings(setting_key,setting_value,updated_at) VALUES(?,?,?) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at",(key,value,stamp))
PY
echo 'PROGRESS:82:Issuing panel SSL certificate…'
printf '%s' "{\"operation\":\"panel_certificate\",\"hostname\":\"$panel_host\",\"email\":\"$cert_email\"}" | /usr/local/libexec/masspanel-helper >/dev/null
echo 'PROGRESS:90:Issuing mail SSL certificate…'
install -d -m 0755 /var/www/snappymail
printf '%s' "{\"operation\":\"mail_certificate\",\"hostname\":\"$mail_host\",\"email\":\"$cert_email\"}" | /usr/local/libexec/masspanel-helper >/dev/null
echo 'PROGRESS:96:Running final service checks…'
nginx -t
systemctl restart masspanel nginx
systemctl is-active --quiet masspanel nginx mariadb named
install -d -m 0750 /etc/masspanel
printf '{"panel_url":"https://%s","mail_hostname":"%s","installed_at":"%s"}\n' "$panel_host" "$mail_host" "$(date -u +%FT%TZ)" > /etc/masspanel/installation-complete.json
chmod 0600 /etc/masspanel/installation-complete.json
rm -f /etc/masspanel/installer.env
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --permanent --remove-port=8080/tcp >/dev/null 2>&1 || true; firewall-cmd --reload >/dev/null 2>&1 || true; fi
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then ufw delete allow 8080/tcp >/dev/null 2>&1 || true; fi
systemctl disable masspanel-installer.service >/dev/null 2>&1 || true
systemd-run --unit=masspanel-installer-shutdown --on-active=2m /usr/bin/systemctl stop masspanel-installer.service >/dev/null 2>&1 || true
echo 'PROGRESS:99:Installation complete; opening the secure panel…'
