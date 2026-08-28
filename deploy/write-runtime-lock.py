#!/usr/bin/env python3
"""Record the tested runtime without preventing operating-system security updates."""
import datetime as dt
import json
import subprocess
from pathlib import Path

packages = ["nginx", "python3", "openssl", "sudo", "ca-certificates", "fail2ban", "firewalld", "postfix", "dovecot-core", "mariadb-server"]
versions = {}
for package in packages:
    result = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${Version}", package], text=True, capture_output=True)
    if result.returncode == 0: versions[package] = result.stdout.strip()
requirements = Path("/opt/masspanel/backend/requirements.txt")
payload = {
    "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
    "system_policy": "Versions recorded; Ubuntu security updates remain enabled",
    "python_requirements": "Exact versions pinned in private virtual environment",
    "packages": versions,
    "requirements": requirements.read_text().splitlines() if requirements.is_file() else [],
}
target = Path("/var/lib/masspanel/runtime.lock.json")
target.write_text(json.dumps(payload, indent=2) + "\n")
target.chmod(0o600)
