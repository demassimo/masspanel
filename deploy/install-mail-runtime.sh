#!/usr/bin/env bash
set -euo pipefail
test "${EUID}" -eq 0
MAIL_HOST=${MASSPANEL_MAIL_HOST:-mail.example.com}
export DEBIAN_FRONTEND=noninteractive
echo "postfix postfix/mailname string ${MAIL_HOST}" | debconf-set-selections
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
apt-get update
apt-get install -y --no-install-recommends postfix postfix-pcre dovecot-core dovecot-imapd dovecot-lmtpd
if ! id vmail >/dev/null 2>&1; then
  groupadd --gid 5000 vmail
  useradd --system --uid 5000 --gid vmail --home-dir /var/vmail --create-home --shell /usr/sbin/nologin vmail
fi
install -d -m 0750 -o vmail -g vmail /var/vmail
touch /etc/postfix/masspanel-domains /etc/postfix/masspanel-mailboxes /etc/postfix/masspanel-aliases
postmap /etc/postfix/masspanel-domains
postmap /etc/postfix/masspanel-mailboxes
postmap /etc/postfix/masspanel-aliases
postconf -e "myhostname = ${MAIL_HOST}"
postconf -e 'mydestination = localhost'
postconf -e 'inet_interfaces = all'
postconf -e 'inet_protocols = all'
postconf -e 'virtual_mailbox_base = /var/vmail'
postconf -e 'virtual_mailbox_domains = hash:/etc/postfix/masspanel-domains'
postconf -e 'virtual_mailbox_maps = hash:/etc/postfix/masspanel-mailboxes'
postconf -e 'virtual_alias_maps = hash:/etc/postfix/masspanel-aliases'
postconf -e 'virtual_uid_maps = static:5000'
postconf -e 'virtual_gid_maps = static:5000'
postconf -e 'virtual_transport = lmtp:unix:private/dovecot-lmtp'
postconf -e 'smtpd_sasl_type = dovecot'
postconf -e 'smtpd_sasl_path = private/auth'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_tls_security_level = may'
postconf -e 'smtpd_tls_cert_file = /etc/masspanel/tls/masspanel.crt'
postconf -e 'smtpd_tls_key_file = /etc/masspanel/tls/masspanel.key'
postconf -e 'smtpd_recipient_restrictions = permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination'
if ! grep -Eq '^submission[[:space:]]+inet' /etc/postfix/master.cf; then
  cat >> /etc/postfix/master.cf <<'EOF'
submission inet n - y - - smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
smtps inet n - y - - smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_relay_restrictions=permit_sasl_authenticated,reject
EOF
fi
sed -i 's/^!include auth-system.conf.ext/# !include auth-system.conf.ext/' /etc/dovecot/conf.d/10-auth.conf
cat > /etc/dovecot/conf.d/99-masspanel.conf <<'EOF'
protocols = imap lmtp
mail_location = maildir:/var/vmail/%d/%n/Maildir
mail_plugins = quota
first_valid_uid = 5000
last_valid_uid = 5000
auth_mechanisms = plain login
disable_plaintext_auth = yes
ssl = required
ssl_cert = </etc/masspanel/tls/masspanel.crt
ssl_key = </etc/masspanel/tls/masspanel.key
passdb {
  driver = passwd-file
  args = username_format=%u /etc/dovecot/masspanel-users
}
userdb {
  driver = passwd-file
  args = username_format=%u /etc/dovecot/masspanel-users
}
protocol imap {
  mail_plugins = $mail_plugins imap_quota
}
protocol lmtp {
  mail_plugins = $mail_plugins quota
}
plugin {
  quota = maildir:User quota
}
service lmtp {
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
    mode = 0600
    user = postfix
    group = postfix
  }
}
service auth {
  unix_listener /var/spool/postfix/private/auth {
    mode = 0660
    user = postfix
    group = postfix
  }
}
EOF
touch /etc/dovecot/masspanel-users
chown root:dovecot /etc/dovecot/masspanel-users
chmod 0640 /etc/dovecot/masspanel-users
postfix check
doveconf -n >/dev/null
systemctl enable --now postfix dovecot
systemctl restart postfix dovecot
install -d -m 0755 -o root -g root /var/www/masspanel-mail/.well-known/acme-challenge
printf '%s\n' 'MassPanel mail services are running.' > /var/www/masspanel-mail/index.html
cat > /etc/nginx/sites-available/masspanel-mail <<EOF
server {
  listen 80;
  listen [::]:80;
  server_name ${MAIL_HOST};
  root /var/www/masspanel-mail;
  location ^~ /.well-known/acme-challenge/ { try_files \$uri =404; }
  location / { try_files /index.html =404; }
}
EOF
ln -sfn /etc/nginx/sites-available/masspanel-mail /etc/nginx/sites-enabled/masspanel-mail
nginx -t
systemctl reload nginx
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/masspanel-reload-services <<'EOF'
#!/bin/sh
set -eu
systemctl reload nginx
systemctl reload postfix
systemctl reload dovecot
EOF
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/masspanel-reload-services
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  for port in 25 465 587 143 993; do ufw allow "${port}/tcp"; done
fi
