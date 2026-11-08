#!/usr/bin/env python3
"""Export current identities, including default mailbox hashes omitted by backups.

Run as root on the source. Transfer the resulting private JSON by SSH to
/var/lib/masspanel-imports/directadmin/source-inventory.json on the destination.
Never publish this export, which contains password hashes.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import pwd
import re
import spwd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Run as root on the DirectAdmin source.')
    os.umask(0o077)
    accounts = []; domains = []; mail = []
    for path in sorted(Path('/usr/local/directadmin/data/users').iterdir()):
        if not path.is_dir() or not re.fullmatch(r'[a-z][a-z0-9_-]{2,31}', path.name): continue
        account = pwd.getpwnam(path.name)
        accounts.append({'username': path.name, 'password_hash': spwd.getspnam(path.name).sp_pwdp})
        domain_list = path / 'domains.list'
        for domain in domain_list.read_text().splitlines() if domain_list.exists() else []:
            if not re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,63}', domain): raise SystemExit('Invalid domain name.')
            domains.append({'domain': domain, 'owner': path.name})
            directory = Path('/etc/virtual') / domain
            if not (directory / 'passwd').is_file(): directory = directory.with_name(domain + '_off')
            entries = []
            if (directory / 'passwd').exists():
                for line in (directory / 'passwd').read_text().splitlines():
                    fields = line.split(':')
                    if len(fields) < 2: raise SystemExit('Invalid mailbox record.')
                    entries.append({'localpart': fields[0], 'hash': fields[1]})
            mail.append({'domain': domain, 'accounts': entries, 'suspended': directory.name.endswith('_off')})
    export = {'version': 1, 'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'accounts': accounts, 'domains': domains, 'mail': mail}
    # Refuse an existing output or symlink rather than overwrite an arbitrary file.
    with os.fdopen(os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w') as stream:
        json.dump(export, stream, indent=2)
    print(f'Exported {len(accounts)} accounts and {sum(len(m["accounts"]) for m in mail)} mailbox identities to the private output file.')


if __name__ == '__main__': main()
