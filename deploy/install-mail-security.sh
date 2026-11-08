#!/usr/bin/env bash
# Stage only. Public mail routing and the delivery timer require separate activation.
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
install -d -m 0750 -o root -g masspanel /etc/masspanel
install -d -m 0700 -o masspanel -g masspanel /var/lib/masspanel/mail-quarantine
secret_file=/etc/masspanel/rspamd-export-secret
if ! test -s "$secret_file"; then
  umask 027
  openssl rand -base64 36 > "$secret_file"
fi
chown root:masspanel "$secret_file"
chmod 0640 "$secret_file"
install -d -m 0755 /usr/local/libexec /etc/masspanel/mail-security-examples
install -m 0755 "$source_dir/mail-security-pipe.py" /usr/local/libexec/masspanel-mail-security-pipe
install -m 0644 "$source_dir/masspanel-mail-delivery.service" "$source_dir/masspanel-mail-delivery.timer" /etc/systemd/system/
install -m 0644 "$source_dir/mail-security-postfix.example" "$source_dir/mail-security-statistic.example" /etc/masspanel/mail-security-examples/
runtime=/etc/masspanel/mail-security-delivery.json
if ! test -e "$runtime"; then
  printf '%s\n' '{"enabled":false,"lda_port":10024}' > "$runtime"
  chown root:masspanel "$runtime"
  chmod 0640 "$runtime"
fi
systemctl daemon-reload
echo 'Mail security staged. No Postfix/Rspamd/Gromox routing changed and no timer enabled.'
echo 'Review docs/MAIL_SECURITY.md before explicit activation. AI remains owner-configured.'
