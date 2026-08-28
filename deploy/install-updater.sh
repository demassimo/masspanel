#!/usr/bin/env bash
set -Eeuo pipefail
test "${EUID}" -eq 0
stage=${MASSPANEL_STAGE_DIR:-/tmp/masspanel-stage}
test -f "$stage/updater/masspanel-updater.py"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y --no-install-recommends python3-venv openssl curl ca-certificates
install -d -m 0700 /opt/masspanel-updater/current /var/lib/masspanel-updater/backups /etc/masspanel-updater
python3 -m venv /opt/masspanel-updater/venv
install -m 0700 "$stage/updater/masspanel-updater.py" /opt/masspanel-updater/current/masspanel-updater.py
install -m 0755 "$stage/updater/masspanel-update" /usr/local/sbin/masspanel-update
if [[ ! -f /etc/masspanel-updater/config.json ]]; then install -m 0600 "$stage/updater/config.json" /etc/masspanel-updater/config.json; fi
install -m 0644 "$stage/updater/update-signing-public.pem" /etc/masspanel-updater/update-signing-public.pem
install -m 0644 "$stage/updater/masspanel-updater.service" /etc/systemd/system/masspanel-updater.service
install -m 0644 "$stage/updater/masspanel-updater.timer" /etc/systemd/system/masspanel-updater.timer
install -m 0644 "$stage/VERSION" /opt/masspanel/VERSION
systemctl daemon-reload
systemctl enable --now masspanel-updater.timer
/opt/masspanel-updater/venv/bin/python -m py_compile /opt/masspanel-updater/current/masspanel-updater.py
