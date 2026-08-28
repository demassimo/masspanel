#!/usr/bin/env bash
set -euo pipefail
source_dir=/var/lib/masspanel-license
backup_dir=/var/backups/masspanel-license
stamp=$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 -o root -g root "$backup_dir"
archive="$backup_dir/masspanel-license-$stamp.tar.gz"
tar -C "$source_dir" -czf "$archive" licenses.db signing-key.pem signing-public.pem
chmod 0600 "$archive"
find "$backup_dir" -maxdepth 1 -type f -name 'masspanel-license-*.tar.gz' -mtime +30 -delete

