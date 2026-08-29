#!/usr/bin/env bash
set -euo pipefail

install -o root -g masspanel -m 0640 /tmp/masspanel-app.py /opt/masspanel/backend/app.py
install -o root -g masspanel -m 0640 /tmp/masspanel-helper.py /opt/masspanel/backend/helper.py
test ! -f /tmp/masspanel-scheduled-backup.py || install -o root -g masspanel -m 0750 /tmp/masspanel-scheduled-backup.py /opt/masspanel/backend/scheduled_backup.py
install -o root -g root -m 0755 /tmp/masspanel-helper.py /usr/local/libexec/masspanel-helper
install -o root -g root -m 0644 /tmp/masspanel-auth.conf /etc/fail2ban/filter.d/masspanel-auth.conf
install -o root -g root -m 0644 /tmp/grommunio-web-auth.conf /etc/fail2ban/filter.d/grommunio-web-auth.conf
install -o root -g root -m 0644 /tmp/masspanel.local /etc/fail2ban/jail.d/masspanel.local
install -o root -g root -m 0755 /tmp/masspanel-fail2ban-ignore /usr/local/libexec/masspanel-fail2ban-ignore

/opt/masspanel/venv/bin/python -m py_compile /opt/masspanel/backend/app.py /opt/masspanel/backend/helper.py /opt/masspanel/backend/scheduled_backup.py
fail2ban-client -t

firewall-cmd --permanent --zone=public --add-service=dns
firewall-cmd --permanent --zone=public --add-port=465/tcp
firewall-cmd --permanent --zone=public --add-port=995/tcp
firewall-cmd --permanent --zone=public --remove-port=8080/tcp
firewall-cmd --reload

systemctl restart masspanel
systemctl enable --now fail2ban
systemctl restart fail2ban
systemctl is-active masspanel
systemctl is-active fail2ban
