#!/usr/bin/env bash
set -euo pipefail

install -d -m 0750 -o root -g masspanel /etc/masspanel
install -d -m 0700 -o masspanel -g masspanel /var/lib/masspanel/mail-quarantine
secret_file=/etc/masspanel/rspamd-export-secret
if ! test -s "$secret_file"; then
  umask 027
  openssl rand -base64 36 > "$secret_file"
fi
chown root:masspanel "$secret_file"
chmod 0640 "$secret_file"
secret=$(tr -d '\r\n' < "$secret_file")

install -d -m 0755 /etc/rspamd/local.d
if test -f /tmp/rspamd-antivirus.conf; then
  install -o root -g _rspamd -m 0640 /tmp/rspamd-antivirus.conf /etc/rspamd/local.d/antivirus.conf
fi
cat > /etc/rspamd/local.d/metadata_exporter.conf <<EOF
rules {
  MASSPANEL_TRACKING {
    backend = "http";
    url = "http://127.0.0.1:8100/api/mail-security/ingest/event";
    selector = "default";
    formatter = "json";
    user = "masspanel";
    password = "${secret}";
    timeout = 5s;
  }
  MASSPANEL_QUARANTINE {
    backend = "http";
    url = "http://127.0.0.1:8100/api/mail-security/ingest/quarantine";
    selector = "is_reject";
    formatter = "default";
    meta_headers = true;
    mime_type = "message/rfc822";
    user = "masspanel";
    password = "${secret}";
    timeout = 10s;
  }
}
EOF
chmod 0640 /etc/rspamd/local.d/metadata_exporter.conf
chown root:_rspamd /etc/rspamd/local.d/metadata_exporter.conf

master=/etc/postfix/master.cf
if ! grep -q '^# MASSPANEL RELEASE SERVICE$' "$master"; then
  cat >> "$master" <<'EOF'

# MASSPANEL RELEASE SERVICE
127.0.0.1:10026 inet n - n - - smtpd
  -o syslog_name=postfix/masspanel-release
  -o smtpd_milters=
  -o non_smtpd_milters=
  -o content_filter=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_helo_restrictions=
  -o smtpd_sender_restrictions=
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
EOF
fi

rspamadm configtest
postfix check
systemctl reload rspamd
systemctl reload postfix
if systemctl list-unit-files clamav-daemon.service >/dev/null 2>&1; then
  systemctl enable --now clamav-daemon.socket clamav-daemon.service
fi
