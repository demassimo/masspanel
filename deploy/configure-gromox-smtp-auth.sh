#!/bin/bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

PAM_MODULE=/usr/lib/x86_64-linux-gnu/security/pam_gromox.so
if [[ ! -f "$PAM_MODULE" ]]; then
  echo "Gromox PAM authentication module is unavailable" >&2
  exit 1
fi
for command in postconf postfix systemctl; do
  command -v "$command" >/dev/null || { echo "Missing required command: $command" >&2; exit 1; }
done

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="/var/backups/masspanel/smtp-auth-$stamp"
install -d -m 0700 "$backup_dir"

backup_file() {
  local path=$1
  if [[ -e "$path" ]]; then
    cp -a "$path" "$backup_dir/$(echo "$path" | tr '/' '_')"
  fi
}

restore_file() {
  local path=$1 saved="$backup_dir/$(echo "$path" | tr '/' '_')"
  if [[ -e "$saved" ]]; then
    cp -a "$saved" "$path"
  else
    rm -f "$path"
  fi
}

was_sasl_active=$(systemctl is-active saslauthd 2>/dev/null || true)
was_sasl_enabled=$(systemctl is-enabled saslauthd 2>/dev/null || true)
for path in /etc/default/saslauthd /etc/pam.d/smtp /etc/postfix/sasl/smtpd.conf /etc/postfix/main.cf /etc/postfix/master.cf; do
  backup_file "$path"
done

rollback() {
  local status=$?
  trap - ERR
  echo "SMTP authentication configuration failed; restoring $backup_dir" >&2
  for path in /etc/default/saslauthd /etc/pam.d/smtp /etc/postfix/sasl/smtpd.conf /etc/postfix/main.cf /etc/postfix/master.cf; do
    restore_file "$path"
  done
  if [[ "$was_sasl_enabled" != "enabled" ]]; then systemctl disable saslauthd >/dev/null 2>&1 || true; fi
  if [[ "$was_sasl_active" == "active" ]]; then
    systemctl restart saslauthd >/dev/null 2>&1 || true
  else
    systemctl stop saslauthd >/dev/null 2>&1 || true
  fi
  postfix check >/dev/null 2>&1 && systemctl restart postfix >/dev/null 2>&1 || true
  exit "$status"
}
trap rollback ERR

set_default() {
  local key=$1 value=$2 file=/etc/default/saslauthd
  if grep -qE "^${key}=" "$file"; then
    sed -i -E "s|^${key}=.*|${key}=${value}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

install -d -m 0755 /etc/postfix/sasl
printf '%s\n' \
  '#%PAM-1.0' \
  'auth required pam_gromox.so' \
  'account required pam_permit.so service=smtp' \
  > /etc/pam.d/smtp
chmod 0644 /etc/pam.d/smtp

printf '%s\n' \
  'pwcheck_method: saslauthd' \
  'mech_list: PLAIN LOGIN' \
  'saslauthd_path: /var/run/saslauthd/mux' \
  > /etc/postfix/sasl/smtpd.conf
chmod 0644 /etc/postfix/sasl/smtpd.conf

set_default START yes
set_default MECHANISMS '"pam"'
set_default OPTIONS '"-r -c -m /var/run/saslauthd"'
usermod -a -G sasl postfix

postconf -e 'smtpd_sasl_type = cyrus'
postconf -e 'smtpd_sasl_path = smtpd'
postconf -e 'smtpd_sasl_auth_enable = yes'
postconf -e 'smtpd_sasl_security_options = noanonymous'
postconf -e 'broken_sasl_auth_clients = yes'

# Public port 25 receives server-to-server mail and must not advertise AUTH.
# Submission ports remain TLS-protected and explicitly enable authentication.
postconf -P 'smtp/inet/smtpd_sasl_auth_enable=no'
postconf -P 'submission/inet/smtpd_sasl_auth_enable=yes'
postconf -P 'submission/inet/smtpd_tls_security_level=encrypt'
postconf -P 'smtps/inet/smtpd_sasl_auth_enable=yes'
postconf -P 'smtps/inet/smtpd_tls_wrappermode=yes'

systemctl enable saslauthd >/dev/null
systemctl restart saslauthd
postfix check
systemctl restart postfix

systemctl is-active --quiet saslauthd
systemctl is-active --quiet postfix
[[ -S /var/run/saslauthd/mux ]]
[[ $(postconf -h smtpd_sasl_type) == cyrus ]]
[[ $(postconf -h smtpd_sasl_path) == smtpd ]]

trap - ERR
echo "Gromox SMTP authentication is active. Backup: $backup_dir"
