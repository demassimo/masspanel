"""Verify IMAP metadata against imapsync's UID cache without reading message bodies."""
import datetime
import imaplib
from pathlib import Path
import re
import socket
import ssl

from directadmin_import import ImportError, atomic_json


def metadata(client, folder):
    status, count = client.select(client._quote(folder), readonly=True)
    if status != 'OK': raise ImportError('Could not select a mailbox folder for verification.')
    total = int(count[0])
    if not total: return {}
    status, rows = client.uid('FETCH', '1:*', '(UID FLAGS INTERNALDATE RFC822.SIZE)')
    if status != 'OK': raise ImportError('Could not read mailbox metadata for verification.')
    result = {}
    for row in rows:
        if not isinstance(row, bytes): continue
        uid = re.search(rb'\bUID (\d+)\b', row)
        date = re.search(rb'INTERNALDATE "([^"]+)"', row)
        size = re.search(rb'RFC822.SIZE (\d+)', row)
        if not uid or not date or not size: continue
        flags = sorted(flag.decode('ascii').lower() for flag in imaplib.ParseFlags(row) if flag.lower() != b'\\recent')
        timestamp = int(datetime.datetime.strptime(date[1].decode().strip(), '%d-%b-%Y %H:%M:%S %z').timestamp())
        result[int(uid[1])] = {'flags': flags, 'date': timestamp, 'size': int(size[1])}
    if len(result) != total: raise ImportError('Incomplete mailbox metadata response; verification stopped.')
    return result


def folder_mappings(text, workdir):
    mappings = []; pair = None
    for line in text.splitlines():
        match = re.match(r'^Folder\s+\d+/\d+\s+\[(.*)\]\s+->\s+\[(.*)\]\s*$', line)
        if match:
            pair = [match[1], match[2], None]
            mappings.append(pair)
        cache = re.match(r'^Local cache directory: (.*) \( \d+ characters long \)', line)
        if cache and pair:
            path = Path(cache[1]).resolve()
            if not path.is_relative_to((workdir / 'cache').resolve()):
                raise ImportError('Unsafe IMAP cache path in the migration report.')
            pair[2] = path
    summary = re.search(r'^Folders synced\s+: (\d+)/(\d+) synced', text, re.M)
    if not summary or int(summary[1]) != int(summary[2]) or len(mappings) != int(summary[1]):
        raise ImportError('Folder mapping is incomplete; inspect the private migration report.')
    return mappings


def verify_transfer(port, hostname, address, password, workdir, log):
    class LocalTLS(imaplib.IMAP4_SSL):
        def _create_socket(self, timeout):
            return ssl.create_default_context().wrap_socket(
                socket.create_connection(('127.0.0.1', 993), timeout), server_hostname=hostname)
    source = imaplib.IMAP4('127.0.0.1', port, timeout=60)
    target = LocalTLS('127.0.0.1', 993, timeout=60)
    report = {'address': address, 'folders': [], 'errors': [], 'messages_verified': 0}
    try:
        target.login(address, password)
        for source_folder, target_folder, cache in folder_mappings(log.read_text(errors='replace'), workdir):
            original = metadata(source, source_folder); copied = metadata(target, target_folder)
            mapping = {}
            if original and cache is None:
                raise ImportError('A non-empty folder has no UID cache for verification.')
            for path in cache.iterdir() if cache is not None and cache.is_dir() else []:
                match = re.fullmatch(r'(\d+)_(\d+)', path.name)
                if match: mapping[int(match[1])] = int(match[2])
            folder = {'source': source_folder, 'target': target_folder,
                      'source_count': len(original), 'target_count': len(copied), 'differences': []}
            for uid, expected in original.items():
                actual = copied.get(mapping.get(uid))
                if actual is None:
                    folder['differences'].append({'uid': uid, 'fields': ['missing message or UID mapping']})
                    continue
                differences = [key for key in ('flags', 'date', 'size') if expected[key] != actual[key]]
                if differences:
                    folder['differences'].append({'uid': uid, 'fields': differences, 'source': expected, 'target': actual})
                else: report['messages_verified'] += 1
            report['folders'].append(folder)
        report['verified'] = not any(folder['differences'] for folder in report['folders'])
        atomic_json(workdir / 'metadata-verification.json', report)
        if not report['verified']:
            raise ImportError('Mail was copied but metadata verification found a difference for ' + address + '. Review metadata-verification.json before continuing or cutting over.')
        return report
    finally:
        for client in (source, target):
            try: client.logout()
            except (OSError, imaplib.IMAP4.error): pass
