#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

STAGE_DIR=${MASSPANEL_STAGE_DIR:-/tmp/masspanel-stage}
PANEL_ADMIN_USERNAME=${MASSPANEL_ADMIN_USERNAME:-admin}
PANEL_PUBLIC_HOST=${MASSPANEL_PUBLIC_HOST:-$(hostname -f)}
if [[ ! ${PANEL_ADMIN_USERNAME} =~ ^[a-z][a-z0-9_-]{2,31}$ ]]; then
  echo "MASSPANEL_ADMIN_USERNAME must be a valid Linux-style username." >&2
  exit 1
fi
if [[ ${PANEL_PUBLIC_HOST} =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  PANEL_CERT_SAN="IP:${PANEL_PUBLIC_HOST}"
else
  PANEL_CERT_SAN="DNS:${PANEL_PUBLIC_HOST}"
fi
if [[ ! -d "${STAGE_DIR}/backend" || ! -d "${STAGE_DIR}/frontend" ]]; then
  echo "Deployment stage is incomplete." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends nginx python3-venv python3-pip openssl sudo ca-certificates

if ! id masspanel >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/masspanel --create-home --shell /usr/sbin/nologin masspanel
fi

install -d -m 0750 -o root -g masspanel /opt/masspanel/backend
install -d -m 0755 -o root -g root /opt/masspanel/frontend
install -d -m 0750 -o masspanel -g masspanel /var/lib/masspanel
install -d -m 0750 -o root -g masspanel /etc/masspanel
install -d -m 0700 -o root -g root /etc/masspanel/tls
install -d -m 0755 -o root -g root /usr/local/libexec
install -d -m 0755 -o root -g root /usr/share/doc/masspanel /usr/share/doc/masspanel/licenses /usr/share/masspanel/source /etc/grommunio-common/nginx/locations.d /etc/nginx/snippets

cp -a "${STAGE_DIR}/backend/." /opt/masspanel/backend/
cp -a "${STAGE_DIR}/frontend/dist/." /opt/masspanel/frontend/
chown -R root:masspanel /opt/masspanel/backend
chmod -R o-rwx /opt/masspanel/backend
chown -R root:root /opt/masspanel/frontend

# Publish the exact preferred source and licence notices used by this release.
install -m 0644 -o root -g root "${STAGE_DIR}/LICENSE" /usr/share/doc/masspanel/LICENSE
install -m 0644 -o root -g root "${STAGE_DIR}/NOTICE" /usr/share/doc/masspanel/NOTICE
install -m 0644 -o root -g root "${STAGE_DIR}/SOURCE_OFFER.md" /usr/share/doc/masspanel/SOURCE_OFFER.md
install -m 0644 -o root -g root "${STAGE_DIR}/THIRD_PARTY.md" /usr/share/doc/masspanel/THIRD_PARTY.md
install -m 0644 -o root -g root "${STAGE_DIR}/third_party/sources.lock.json" /usr/share/doc/masspanel/sources.lock.json
install -m 0644 -o root -g root "${STAGE_DIR}"/third_party/licenses/* /usr/share/doc/masspanel/licenses/
install -m 0644 -o root -g root "${STAGE_DIR}/deploy/masspanel-source.html" /usr/share/doc/masspanel/masspanel-source.html
install -m 0644 -o root -g root "${STAGE_DIR}/deploy/masspanel-source-offer.conf" /etc/grommunio-common/nginx/locations.d/05-masspanel-source-offer.conf
install -m 0644 -o root -g root "${STAGE_DIR}/deploy/masspanel-panel-source-offer.conf" /etc/nginx/snippets/masspanel-source-offer.conf
tar --exclude='./third_party/source-archives/gromox-container-0.0.4.tar.gz' -czf /usr/share/masspanel/source/masspanel-corresponding-source.tar.gz -C "${STAGE_DIR}" .
chmod 0644 /usr/share/masspanel/source/masspanel-corresponding-source.tar.gz

install -m 0755 -o root -g root /opt/masspanel/backend/helper.py /usr/local/libexec/masspanel-helper
install -m 0755 -o root -g root "${STAGE_DIR}/deploy/system-mail-sorter.py" /usr/local/libexec/masspanel-system-mail-sorter
install -m 0644 -o root -g root "${STAGE_DIR}/deploy/masspanel-system-mail-sorter.service" /etc/systemd/system/masspanel-system-mail-sorter.service
install -m 0644 -o root -g root "${STAGE_DIR}/deploy/masspanel-system-mail-sorter.timer" /etc/systemd/system/masspanel-system-mail-sorter.timer
install -m 0440 -o root -g root "${STAGE_DIR}/deploy/masspanel.sudoers" /etc/sudoers.d/masspanel
visudo -cf /etc/sudoers.d/masspanel

python3 -m venv /opt/masspanel/venv
/opt/masspanel/venv/bin/pip install --disable-pip-version-check --no-cache-dir -r /opt/masspanel/backend/requirements.txt
install -m 0755 -o root -g root "${STAGE_DIR}/deploy/write-runtime-lock.py" /usr/local/libexec/masspanel-write-runtime-lock
/usr/local/libexec/masspanel-write-runtime-lock

panel_secret=$(openssl rand -hex 32)
umask 077
printf 'MASSPANEL_SECRET_KEY=%s\nMASSPANEL_STATE_DIR=/var/lib/masspanel\nMASSPANEL_HELPER=/usr/local/libexec/masspanel-helper\nMASSPANEL_LICENSE_SERVER_URL=https://masspanel.masscomputing.co.za\nMASSPANEL_LICENSE_PUBLIC_KEY=/opt/masspanel/backend/license_public.pem\n' "${panel_secret}" > /etc/masspanel/masspanel.env
chown root:masspanel /etc/masspanel/masspanel.env
chmod 0640 /etc/masspanel/masspanel.env

if [[ -n ${MASSPANEL_INITIAL_PASSWORD:-} ]]; then
  initial_password=${MASSPANEL_INITIAL_PASSWORD}
  password_was_supplied=1
else
  initial_password=$(openssl rand -base64 32 | tr -d '/+=' | head -c 24)
  password_was_supplied=0
fi
set -a
source /etc/masspanel/masspanel.env
set +a
export MASSPANEL_INITIAL_PASSWORD="${initial_password}"
runuser -u masspanel -- /opt/masspanel/venv/bin/python /opt/masspanel/backend/app.py init-admin "${PANEL_ADMIN_USERNAME}"
unset MASSPANEL_INITIAL_PASSWORD

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -keyout /etc/masspanel/tls/masspanel.key \
  -out /etc/masspanel/tls/masspanel.crt \
  -subj "/CN=${PANEL_PUBLIC_HOST}/O=MassPanel" \
  -addext "subjectAltName=${PANEL_CERT_SAN}"
chmod 0600 /etc/masspanel/tls/masspanel.key
chmod 0644 /etc/masspanel/tls/masspanel.crt

install -m 0644 -o root -g root "${STAGE_DIR}/deploy/masspanel.service" /etc/systemd/system/masspanel.service
rm -f /etc/nginx/sites-enabled/default
install -m 0644 -o root -g root "${STAGE_DIR}/deploy/nginx-masspanel.conf" /etc/nginx/sites-available/masspanel
ln -sfn /etc/nginx/sites-available/masspanel /etc/nginx/sites-enabled/masspanel

nginx -t
systemctl daemon-reload
systemctl enable --now masspanel nginx
systemctl restart nginx

"${STAGE_DIR}/deploy/install-updater.sh"

echo "MASSPANEL_URL=https://${PANEL_PUBLIC_HOST}:8443"
echo "INITIAL_ADMIN_USERNAME=${PANEL_ADMIN_USERNAME}"
if [[ ${password_was_supplied} -eq 1 ]]; then echo "INITIAL_ADMIN_PASSWORD=configured in the web installer"; else echo "INITIAL_ADMIN_PASSWORD=${initial_password}"; fi
