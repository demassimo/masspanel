"""Password-preserving Grommunio migration using imapsync and a read-only SSH bridge."""
import contextlib
import crypt
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import threading

from directadmin_import import ImportError, atomic_json
from passwords import supported_legacy_hash

CONFIG = Path('/etc/masspanel/directadmin-source.json')
IMAPSYNC = '/usr/local/libexec/masspanel-imapsync'


def run(command, data=None, timeout=60):
    result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ImportError('Mail migration command failed: ' + Path(command[0]).name + '. Review the private migration log.')
    return result.stdout


def sql_literal(value):
    return "X'" + value.encode().hex() + "'"


def source_config():
    info = CONFIG.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ImportError('The source connection file must be root-owned with mode 0600.')
    config = json.loads(CONFIG.read_text())
    for name in ('host', 'target_hostname'):
        if not isinstance(config.get(name), str) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', config[name]):
            raise ImportError('Invalid migration host configuration.')
    for name in ('identity_file', 'known_hosts'):
        value = config.get(name)
        if not isinstance(value, str) or not value.startswith('/'):
            raise ImportError('SSH identity and known-hosts paths must be absolute.')
        p = Path(value); info = p.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ImportError('SSH migration files must be regular, root-owned, and protected from writes.')
        if name == 'identity_file' and info.st_mode & 0o077:
            raise ImportError('The SSH migration identity must have mode 0600.')
    if not Path(IMAPSYNC).is_file() or not shutil.which('nft'):
        raise ImportError('Run deploy/install-directadmin-imapsync.py before restoring email.')
    return config


@contextlib.contextmanager
def source_bridge(config, address):
    """Loopback PREAUTH endpoint accessible only by root; SSH pins the source key."""
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    table = 'mp_migrate_' + secrets.token_hex(6)
    rules = f'table inet {table} {{\n chain output {{\n type filter hook output priority -10; policy accept;\n ip daddr 127.0.0.1 tcp dport {port} meta skuid != 0 reject;\n }}\n}}\n'
    run(['/usr/sbin/nft', '-f', '-'], rules)
    stop = threading.Event()
    connections = []
    processes = []
    def connection(client):
        command = ['/usr/bin/ssh', '-T', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
                   '-oUserKnownHostsFile=' + config['known_hosts'], '-oConnectTimeout=20',
                   '-oServerAliveInterval=30', '-i', config['identity_file'],
                   'root@' + config['host'], address]
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        processes.append(proc)
        def send():
            try:
                while block := os.read(proc.stdout.fileno(), 65536): client.sendall(block)
            except OSError: pass
            finally:
                try: client.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        sender = threading.Thread(target=send, daemon=True); sender.start()
        try:
            while block := client.recv(65536):
                proc.stdin.write(block); proc.stdin.flush()
        except (OSError, BrokenPipeError): pass
        finally:
            client.close()
            if proc.poll() is None: proc.terminate()
            proc.wait(timeout=10)
    def accept():
        while not stop.is_set():
            try: client, _ = listener.accept()
            except (TimeoutError, OSError): continue
            connections.append(client)
            threading.Thread(target=connection, args=(client,), daemon=True).start()
    listener.listen(3); listener.settimeout(1)
    thread = threading.Thread(target=accept, daemon=True); thread.start()
    try:
        yield port
    finally:
        stop.set(); listener.close(); thread.join(timeout=3)
        for client in connections:
            try: client.shutdown(socket.SHUT_RDWR); client.close()
            except OSError: pass
        for proc in processes:
            if proc.poll() is None: proc.terminate()
        run(['/usr/sbin/nft', 'delete', 'table', 'inet', table])


def sync_mailbox(mailbox, workdir, config, suspended=False):
    address = mailbox['address']
    if not re.fullmatch(r'[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,63}', address):
        raise ImportError('Invalid mailbox address.')
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    original = mailbox['hash'].lstrip('!')
    secret = secrets.token_urlsafe(36)
    hashed = crypt.crypt(secret, crypt.mksalt(crypt.METHOD_SHA512))
    recovery = workdir / 'restore-password.json'
    atomic_json(recovery, {'address': address, 'hash': original, 'temporary_hash': hashed,
                          'status': 1 if suspended or mailbox['hash'].startswith('!') else 0})
    password_file = workdir / 'target.pass'
    password_file.write_text(secret + '\n'); password_file.chmod(0o600)
    def set_hash(value):
        run(['/usr/bin/mariadb', 'grommunio'],
            'UPDATE users SET password=' + sql_literal(value) + ', address_status=0 WHERE username=' + sql_literal(address) + ';')
    log = workdir / 'imapsync.log'
    try:
        set_hash(hashed)
        with source_bridge(config, address) as port:
            command = [IMAPSYNC, '--host1', '127.0.0.1', '--port1', str(port),
                       '--user1', address, '--authmech1', 'PREAUTH', '--nossl1', '--notls1',
                       '--host2', '127.0.0.1', '--port2', '993', '--ssl2', '--user2', address,
                       '--passfile2', str(password_file), '--sslargs2', 'SSL_verify_mode=1',
                       '--sslargs2', 'SSL_verifycn_name=' + config['target_hostname'],
                       '--automap', '--syncinternaldates', '--subscribe', '--resyncflags', '--syncflagsaftercopy', '--nofilterflags',
                       '--useuid', '--usecache', '--noreleasecheck', '--nolog',
                       '--tmpdir', str(workdir / 'cache')]
            # No delete/expunge flags: original mail and target-only messages stay.
            sandbox = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                       '--property=ProtectSystem=strict', '--property=ProtectHome=read-only',
                       '--property=PrivateTmp=yes', '--property=NoNewPrivileges=yes',
                       '--property=ReadWritePaths=' + str(workdir), '--working-directory=' + str(workdir)]
            with open(log, 'w') as output:
                proc = subprocess.run(sandbox + command, stdout=output, stderr=subprocess.STDOUT, cwd=workdir, timeout=172800)
            if proc.returncode:
                raise ImportError('Mailbox sync stopped for ' + address + '; inspect its private imapsync log before retrying.')
            from directadmin_mail_verify import verify_transfer
            verify_transfer(port, config['target_hostname'], address, secret, workdir, log)
    finally:
        # Even on failure, never leave the user's account on a temporary password.
        restore_password(recovery)
        password_file.unlink(missing_ok=True)
    atomic_json(workdir / 'result.json', {'address': address, 'status': 'copied',
                'password_recovery_completed': True, 'validation': 'UID mapping, source message coverage, flags, dates and sizes verified.'})


def restore_password(path):
    value = json.loads(path.read_text())
    if not re.fullmatch(r'[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,63}', value['address']):
        raise ImportError('Invalid password recovery record.')
    if not supported_legacy_hash(value['hash']) or not supported_legacy_hash(value['temporary_hash']) or value['status'] not in {0, 1}:
        raise ImportError('Invalid password recovery hash.')
    # Do not overwrite a password changed independently by an administrator.
    run(['/usr/bin/mariadb', 'grommunio'], 'UPDATE users SET password=' + sql_literal(value['hash']) +
        ',address_status=' + str(value['status']) + ' WHERE username=' + sql_literal(value['address']) +
        ' AND password=' + sql_literal(value['temporary_hash']) + ';')
    path.unlink()
    path.with_name('target.pass').unlink(missing_ok=True)


def cleanup_passwords(job_path):
    for path in job_path.glob('accounts/*/mail/*/restore-password.json'):
        restore_password(path)
