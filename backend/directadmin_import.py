#!/usr/bin/env python3
"""Root-owned, asynchronous DirectAdmin backup inspection and restore jobs.

Archives are staged by an operator over SSH, never fetched from an arbitrary URL.
Public job reports deliberately omit hashes, SQL, private keys and mail contents.
"""
import contextlib
import fcntl
import gzip
import json
import os
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path, PurePosixPath

from passwords import supported_legacy_hash

ROOT = Path('/var/lib/masspanel-imports/directadmin')
INCOMING = ROOT / 'incoming'
JOBS = ROOT / 'jobs'
IDENTITIES = ROOT / 'source-inventory.json'
USER = re.compile(r'[a-z][a-z0-9_-]{2,31}')
DOMAIN = re.compile(r'(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
ARCHIVE = re.compile(r'(?:user|admin|reseller)\.[a-z0-9_-]+\.([a-z][a-z0-9_-]{2,31})\.tar\.(?:gz|zst)')
MAX_METADATA = 16 * 1024 * 1024
MAX_EXPANDED = 1024 ** 4
MAX_MEMBERS = 5_000_000


class ImportError(ValueError):
    """An actionable, non-secret message safe to show to the operator."""


def atomic_json(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.tmp')
    with os.fdopen(os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as stream:
        json.dump(data, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def config(text):
    return dict(line.split('=', 1) for line in text.splitlines()
                if '=' in line and not line.startswith('#'))


def archive_path(name):
    if not isinstance(name, str) or not ARCHIVE.fullmatch(name):
        raise ImportError('Choose a DirectAdmin user, reseller or administrator .tar.gz/.tar.zst backup.')
    path = INCOMING / name
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ImportError('Staged backups must be regular, root-owned files, without group or public write access.')
    if path.resolve().parent != INCOMING.resolve():
        raise ImportError('The backup is outside the staging directory.')
    return path


def fingerprint(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns]


@contextlib.contextmanager
def open_archive(path):
    proc = None
    stream = None
    try:
        if str(path).endswith('.zst'):
            proc = subprocess.Popen(['/usr/bin/zstd', '-qdc', '--', str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            stream = proc.stdout
        else:
            stream = gzip.open(path, 'rb')
        archive = tarfile.open(fileobj=stream, mode='r|')
        with archive:
            yield archive
            # A valid tar EOF can precede a damaged compression trailer. Consume
            # the remainder so gzip/zstd integrity errors cannot be ignored.
            trailing = 0
            while block := stream.read(1024 * 1024):
                trailing += len(block)
                if trailing > MAX_METADATA:
                    raise ImportError('Unexpected trailing data after the backup archive.')
            if proc and proc.wait(timeout=10):
                raise ImportError('The compressed backup failed its integrity check.')
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ImportError('The backup is damaged or its compression is unavailable.') from exc
    finally:
        if stream: stream.close()
        if proc:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)


def safe_member(member, username=None):
    name = PurePosixPath(member.name)
    if name.is_absolute() or '..' in name.parts or '\\' in member.name or '\x00' in member.name:
        raise ImportError('The backup contains an unsafe file path.')
    if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
        raise ImportError('Devices, sockets and named pipes are not accepted in backups.')
    if member.size < 0 or member.size > MAX_EXPANDED:
        raise ImportError('The backup exceeds the supported expansion limit.')
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname)
        if shared_statistics_link(member):
            return name
        if (link.is_absolute() and username and USER.fullmatch(username)
                and link.parts[:3] == ('/', 'home', username) and len(link.parts) > 3
                and '..' not in link.parts and '\\' not in member.linkname and '\x00' not in member.linkname):
            target = '/'.join(link.parts[3:])
            member.linkname = posixpath.relpath(target, str(name.parent)) if member.issym() else target
            link = PurePosixPath(member.linkname)
        if link.is_absolute() or '\\' in member.linkname or '\x00' in member.linkname:
            raise ImportError('The backup contains an absolute or unsafe link; review it before restoring.')
        parts = list(name.parent.parts) if member.issym() else []
        for part in link.parts:
            if part == '..':
                if not parts: raise ImportError('A backup link escapes the account directory.')
                parts.pop()
            elif part != '.': parts.append(part)
    return name


def shared_statistics_link(member):
    """Recognize only DirectAdmin's links to shared AWStats program assets.

    These point outside the account and are never extracted. Statistics data
    files remain in the backup and account tree; no arbitrary link is accepted.
    """
    parts = PurePosixPath(member.name).parts
    targets = {'plugins': '/usr/local/awstats/wwwroot/cgi-bin/plugins',
               'lang': '/usr/local/awstats/wwwroot/cgi-bin/lang',
               'lib': '/usr/local/awstats/wwwroot/cgi-bin/lib',
               'icon': '/usr/local/awstats/wwwroot/icon'}
    return (member.issym() and len(parts) in {4, 5} and parts[0] == 'domains'
            and bool(DOMAIN.fullmatch(parts[1])) and parts[2] == 'awstats'
            and (len(parts) == 4 or bool(re.fullmatch(r'[A-Za-z0-9_-]+', parts[3])))
            and parts[-1] in targets and member.linkname == targets[parts[-1]])


def inspect_archive(path):
    original_fingerprint = fingerprint(path)
    filename = ARCHIVE.fullmatch(path.name)
    if not filename: raise ImportError('Unsupported native backup filename.')
    metadata = {}
    databases = []
    expanded = 0
    skipped_statistics_links = 0
    with open_archive(path) as archive:
        for index, member in enumerate(archive):
            name = safe_member(member, filename[1])
            if shared_statistics_link(member): skipped_statistics_links += 1
            if index > MAX_MEMBERS:
                raise ImportError('The backup contains too many files.')
            expanded += member.size
            if expanded > MAX_EXPANDED:
                raise ImportError('The backup exceeds the supported expansion limit.')
            # Read metadata wherever it occurs. DirectAdmin does not guarantee
            # ordering; even a hostile archive cannot hide a late .shadow file.
            if not member.isfile() or not name.parts or name.parts[0] != 'backup':
                continue
            relative = '/'.join(name.parts[1:])
            if len(name.parts) == 2 and relative.endswith('.sql'):
                databases.append(relative[:-4])
            wanted = relative in {'user.conf', '.shadow', 'user.usage', 'crontab.conf'}
            wanted |= (len(name.parts) == 2 and relative.endswith('.conf'))
            wanted |= (len(name.parts) in {3, 4} and name.name in {
                'domain.conf', 'domain.pointers', 'subdomain.list', 'passwd', 'quota',
                'aliases', 'vacation.conf', 'autoresponder.conf', 'email.conf'})
            if wanted:
                if member.size > MAX_METADATA or sum(map(len, metadata.values())) + member.size > MAX_METADATA * 4:
                    raise ImportError('The backup contains oversized account metadata.')
                if relative in metadata:
                    raise ImportError('Duplicate account metadata found in the backup.')
                metadata[relative] = archive.extractfile(member).read().decode('utf-8', errors='replace')
    account = config(metadata.get('user.conf', ''))
    username = account.get('username', '')
    if not USER.fullmatch(username) or ARCHIVE.fullmatch(path.name)[1] != username:
        raise ImportError('The backup account does not match its filename.')
    encoded = metadata.get('.shadow', '').strip()
    if ':' in encoded:
        fields = encoded.split(':')
        encoded = fields[1] if fields[0] == username else ''
    locked = encoded.startswith('!')
    encoded = encoded.lstrip('!')
    if not supported_legacy_hash(encoded):
        raise ImportError('The account password is not a supported SHA-512-crypt hash; no password was reset.')
    domains = []
    mailboxes = []
    warnings = []
    if skipped_statistics_links:
        warnings.append(f'{skipped_statistics_links} links to shared AWStats program files are omitted; account statistics data remains preserved.')
    for name, value in metadata.items():
        parts = name.split('/')
        if len(parts) == 2 and parts[1] == 'domain.conf':
            domain = parts[0]
            if not DOMAIN.fullmatch(domain):
                raise ImportError('An invalid domain name was found in the backup.')
            dc = config(value)
            domains.append({'domain': domain, 'config': dc})
            if dc.get('php1_select', '1') not in {'', '1'}:
                warnings.append(f'{domain}: uses an additional PHP version; check compatibility before cutover.')
        if len(parts) == 3 and parts[1:] == ['email', 'passwd']:
            domain = parts[0]
            if not DOMAIN.fullmatch(domain):
                raise ImportError('An invalid mail domain was found in the backup.')
            for line in value.splitlines():
                fields = line.split(':')
                if len(fields) < 2 or not re.fullmatch(r'[a-z0-9._%+-]{1,64}', fields[0]):
                    raise ImportError('Invalid mailbox metadata in the backup.')
                hashed = fields[1].removeprefix('{SHA512-CRYPT}')
                if not supported_legacy_hash(hashed.lstrip('!')):
                    raise ImportError('A mailbox has an unsupported password hash; no password was reset.')
                mailboxes.append({'address': fields[0] + '@' + domain, 'hash': hashed})
    if metadata.get('crontab.conf', '').strip():
        warnings.append('Scheduled commands are preserved for review and are not enabled during staging.')
    for name in metadata:
        if name.endswith(('vacation.conf', 'autoresponder.conf')) and metadata[name].strip():
            warnings.append('Mail autoresponders/vacations are preserved and require review before cutover.')
            break
    complete = not domains
    if IDENTITIES.exists():
        info = IDENTITIES.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > MAX_METADATA:
            raise ImportError('The source identity export must be a private, root-owned regular file.')
        identities = json.loads(IDENTITIES.read_text())
        current = next((a for a in identities['accounts'] if a['username'] == username), None)
        if not current or not supported_legacy_hash(current['password_hash'].lstrip('!')):
            raise ImportError('Current account credentials are missing or unsupported in the identity export.')
        encoded = current['password_hash'].lstrip('!'); locked = current['password_hash'].startswith('!')
        owners = {d['domain']: d['owner'] for d in identities['domains']}
        current_mail = {m['domain'].removesuffix('_off'): m for m in identities['mail']}
        mailbox_list = []
        for d in domains:
            domain = d['domain']
            if owners.get(domain) != username or domain not in current_mail:
                raise ImportError('The identity export is incomplete or has a conflicting domain owner.')
            for entry in current_mail[domain]['accounts']:
                if not re.fullmatch(r'[a-z0-9._%+-]{1,64}', entry['localpart']) or not supported_legacy_hash(entry['hash'].lstrip('!')):
                    raise ImportError('Unsupported mailbox credentials in the identity export.')
                mailbox_list.append({'address': entry['localpart'] + '@' + domain, 'hash': entry['hash']})
        mailboxes = mailbox_list
        complete = True
    elif domains:
        warnings.append('Native backups omit default mailbox password records. Export source identities before restoring mail.')
    if fingerprint(path) != original_fingerprint:
        raise ImportError('The backup changed during inspection; stage a completed backup and retry.')
    return {'file': path.name, 'fingerprint': original_fingerprint, 'username': username,
            'account': account, 'hash': encoded, 'locked': locked, 'metadata': metadata,
            'domains': domains, 'databases': sorted(set(databases)), 'mailboxes': mailboxes,
            'mail_inventory_complete': complete,
            'expanded_bytes': expanded, 'warnings': warnings}


def public_account(plan):
    return {'file': plan['file'], 'username': plan['username'],
            'role': plan['account'].get('usertype', 'user'),
            'suspended': plan['account'].get('suspended') == 'yes' or plan['locked'],
            'domains': [d['domain'] for d in plan['domains']],
            'databases': plan['databases'], 'mailboxes': len(plan['mailboxes']),
            'expanded_bytes': plan['expanded_bytes'], 'passwords': 'Preserved (SHA-512)',
            'warnings': plan['warnings']}


def job_path(job):
    if not isinstance(job, str) or not re.fullmatch('[a-f0-9]{32}', job):
        raise ImportError('Invalid import job.')
    return JOBS / job


def report(job, **changes):
    path = job_path(job) / 'status.json'
    state = json.loads(path.read_text()) if path.exists() else {'id': job, 'accounts': [], 'errors': []}
    state.update(changes, updated_at=int(time.time()))
    atomic_json(path, state)
    return state


def spawn(job, phase):
    result = subprocess.run(['/usr/bin/systemd-run', '--collect', '--unit=masspanel-da-' + job + '-' + phase,
                             '--property=Type=exec', '--property=UMask=0077',
                             '--property=ExecStopPost=' + sys.executable + ' ' + str(Path(__file__).resolve()) + ' worker ' + job + ' cleanup',
                             sys.executable, str(Path(__file__).resolve()), 'worker', job, phase],
                            capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ImportError('The background importer could not start. Check systemd on the server.')


def controller(payload):
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    INCOMING.mkdir(mode=0o700, exist_ok=True)
    JOBS.mkdir(mode=0o700, exist_ok=True)
    action = payload.get('action', 'list')
    if action == 'list':
        files = []
        for entry in sorted(INCOMING.iterdir()):
            if ARCHIVE.fullmatch(entry.name):
                try: path = archive_path(entry.name)
                except (ImportError, OSError): continue
                files.append({'name': entry.name, 'size': path.stat().st_size})
        jobs = []
        for path in sorted(JOBS.glob('*/status.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:20]:
            jobs.append(json.loads(path.read_text()))
        return {'files': files, 'jobs': jobs, 'staging_directory': str(INCOMING)}
    if action == 'inspect':
        files = payload.get('files')
        if not isinstance(files, list) or not 1 <= len(files) <= 1000 or any(not isinstance(n, str) for n in files) or len(set(files)) != len(files):
            raise ImportError('Select between 1 and 1000 distinct backup files.')
        for name in files: archive_path(name)
        job = uuid.uuid4().hex
        atomic_json(job_path(job) / 'request.json', {'files': files, 'actor': str(payload.get('actor', 'admin'))[:32]})
        report(job, phase='queued', message='Waiting to inspect the selected backups.', progress=0)
        spawn(job, 'inspect')
        return {'job': job}
    job = payload.get('job')
    path = job_path(job)
    if action == 'status':
        return json.loads((path / 'status.json').read_text())
    if action == 'start':
        state = json.loads((path / 'status.json').read_text())
        if state.get('phase') not in {'ready', 'blocked', 'failed'} or not (path / 'plan.private.json').is_file():
            raise ImportError('Inspect these backups successfully before starting a restore.')
        if payload.get('confirm') is not True:
            raise ImportError('Confirm the reviewed import plan first.')
        atomic_json(path / 'options.json', {'merge_admin': payload.get('merge_admin') is True})
        report(job, phase='queued', message='Checking the destination before restoring.', progress=0)
        spawn(job, 'restore')
        return {'job': job}
    raise ImportError('Unsupported importer action.')


def worker(job, phase):
    path = job_path(job)
    if phase == 'cleanup':
        from directadmin_mail import cleanup_passwords
        cleanup_passwords(path)
        return
    try:
        with open(ROOT / 'worker.lock', 'w') as lock:
            try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ImportError('Another import job is running. Wait for it to finish.')
            if phase == 'inspect':
                request = json.loads((path / 'request.json').read_text())
                plans = []
                for i, name in enumerate(request['files']):
                    report(job, phase='inspecting', message='Inspecting ' + name, progress=round(i * 100 / len(request['files'])))
                    plans.append(inspect_archive(archive_path(name)))
                    report(job, accounts=[public_account(p) for p in plans])
                usernames = [p['username'] for p in plans]
                domains = [d['domain'] for p in plans for d in p['domains']]
                if len(set(usernames)) != len(usernames) or len(set(domains)) != len(domains):
                    raise ImportError('Duplicate accounts or domains occur in the selected backups.')
                atomic_json(path / 'plan.private.json', plans)
                report(job, phase='ready', message='Inspection complete. Review accounts and compatibility notes.', progress=100)
            elif phase == 'restore':
                from directadmin_restore import restore_job
                restore_job(job, path)
            else:
                raise ImportError('Unsupported worker phase.')
    except ImportError as exc:
        report(job, phase='blocked', message=str(exc))
    except Exception:
        # Exception strings from subprocesses/SQL can contain credentials. Keep
        # the public report and journal free of raw SQL or archive content.
        report(job, phase='failed', message='The import stopped unexpectedly. Existing source data is unchanged; review the server and preserved job files.')
        raise SystemExit(1)


if __name__ == '__main__':
    sys.modules['directadmin_import'] = sys.modules[__name__]
    if os.geteuid() != 0:
        raise SystemExit('Run this importer through the privileged MassPanel helper.')
    os.umask(0o077)
    if len(sys.argv) == 4 and sys.argv[1] == 'worker':
        worker(sys.argv[2], sys.argv[3])
    else:
        try:
            payload = json.loads(sys.stdin.read(65537))
            print(json.dumps({'ok': True, **controller(payload)}))
        except (ImportError, OSError, ValueError, KeyError) as exc:
            message = str(exc) if isinstance(exc, ImportError) else 'The import request or staged job is unavailable.'
            print(json.dumps({'ok': False, 'error': message}))
            raise SystemExit(1)
