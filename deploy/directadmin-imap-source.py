#!/usr/bin/env python3
"""Forced SSH command on the OLD DirectAdmin server; no destination Dovecot.

Accepts one mailbox, exposes only read-only IMAP commands and replaces SELECT
with EXAMINE. Install root-owned and authorize a dedicated restricted SSH key.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import threading


def read_command(line):
    if len(line) > 65536 or not line.endswith(b'\n') or b'\x00' in line:
        raise ValueError('Invalid IMAP command')
    # imapsync uses quoted modified-UTF7 names. Literal client arguments are
    # deliberately unsupported: never reinterpret their contents as commands.
    if re.search(rb'\{[0-9]+\+?\}\r?\n$', line):
        raise ValueError('Client literals are not supported by the read-only bridge')
    parts = line.rstrip(b'\r\n').split(None, 2)
    if len(parts) < 2 or not re.fullmatch(rb'[A-Za-z0-9._-]+', parts[0]):
        raise ValueError('Invalid IMAP command')
    command = parts[1].upper()
    if command == b'SELECT':
        parts[1] = b'EXAMINE'
    elif command == b'UID':
        if len(parts) < 3 or parts[2].split(None, 1)[0].upper() not in {b'FETCH', b'SEARCH'}:
            raise ValueError('Write command rejected')
    elif command not in {b'CAPABILITY', b'EXAMINE', b'LIST', b'LSUB', b'STATUS',
                          b'FETCH', b'SEARCH', b'NAMESPACE', b'NOOP', b'LOGOUT', b'ID'}:
        raise ValueError('Write command rejected')
    return b' '.join(parts) + b'\r\n'


def main():
    address = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    if not re.fullmatch(r'[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,63}', address):
        raise SystemExit('Expected one mailbox address.')
    local, domain = address.split('@')
    # A separate root-owned allowlist bounds the dedicated migration key.
    allowed = set(Path('/root/directadmin-migration/imap-allowlist').read_text().splitlines())
    if address not in allowed:
        raise SystemExit('Mailbox is not approved for this migration.')
    command = ['/usr/bin/doveadm', 'exec', 'imap', '-u', address]
    if (Path('/etc/virtual') / (domain + '_off') / 'passwd').is_file():
        # Suspended domains have no public userdb entry. Read their store as the
        # owning Unix user without unsuspending the domain or changing auth.
        owners = dict((key.removesuffix('_off'), value.strip()) for key, value in
                      (line.split(':', 1) for line in Path('/etc/virtual/domainowners').read_text().splitlines() if ':' in line))
        owner = owners.get(domain, '')
        if not re.fullmatch(r'[a-z][a-z0-9_-]{2,31}', owner): raise SystemExit('Unknown suspended domain owner.')
        home = Path('/home') / owner
        if local != owner: home = home / 'imap' / domain / local
        version = subprocess.check_output(['/usr/sbin/dovecot', '--version'], text=True).strip()
        if version.startswith('2.4.'):
            command = ['/usr/bin/doveadm', '-o', 'mail_home=' + str(home), '-o', 'mail_driver=maildir',
                       '-o', 'mail_path=' + str(home / 'Maildir'), 'exec', 'imap', '-u', owner]
        else:
            command = ['/usr/bin/doveadm', '-o', 'mail_location=maildir:' + str(home / 'Maildir'),
                       'exec', 'imap', '-u', owner]
    proc = subprocess.Popen(command,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    def output():
        try:
            while data := os.read(proc.stdout.fileno(), 65536):
                sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
        except (BrokenPipeError, OSError):
            pass
    thread = threading.Thread(target=output, daemon=True)
    thread.start()
    try:
        while line := sys.stdin.buffer.readline(65537):
            forwarded = read_command(line)
            proc.stdin.write(forwarded); proc.stdin.flush()
            if forwarded.split()[1] == b'LOGOUT':
                thread.join(timeout=10)
                break
    except (ValueError, BrokenPipeError):
        pass
    finally:
        proc.stdin.close()
        if proc.poll() is None: proc.terminate()
        proc.wait(timeout=10)


if __name__ == '__main__':
    main()
