#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

POLICY=/usr/sbin/policy-rc.d
if [[ -e "$POLICY" ]]; then
  echo "Refusing to replace existing $POLICY" >&2
  exit 1
fi
cleanup() { rm -f "$POLICY"; }
trap cleanup EXIT
cat > "$POLICY" <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 0755 "$POLICY"

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  gromox \
  grommunio-web \
  grommunio-admin-api \
  grommunio-sync \
  grommunio-dav

echo "Packages installed with service startup suppressed."
dpkg-query -W -f='${Package}\t${Version}\n' \
  gromox grommunio-web grommunio-admin-api grommunio-sync grommunio-dav
