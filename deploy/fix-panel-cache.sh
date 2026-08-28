#!/usr/bin/env bash
set -euo pipefail

stamp="$(date +%Y%m%d-%H%M%S)"
for file in /etc/nginx/sites-available/masspanel-panel-host /etc/nginx/sites-available/masspanel-panel-legacy; do
  [[ -f "$file" ]] || continue
  cp "$file" "$file.pre-cache-fix-$stamp"
  sed -i 's#location / { try_files $uri $uri/ /index.html; }#location ^~ /assets/ { try_files $uri =404; expires 1y; add_header Cache-Control "public, immutable"; }\nlocation = /index.html { add_header Cache-Control "no-store"; }\nlocation / { try_files $uri $uri/ /index.html; add_header Cache-Control "no-store"; }#' "$file"
done

nginx -t
systemctl reload nginx
