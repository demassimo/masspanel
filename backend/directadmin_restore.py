"""Conservative native DirectAdmin restore; never writes to the source server.

Every selected account is preflighted first. Partial account restores stop for
operator review instead of overwriting resources whose ownership is uncertain.
"""
import datetime
import grp
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
from urllib.parse import parse_qs

from directadmin_import import (ImportError, ROOT, archive_path, atomic_json, config,
                               fingerprint, open_archive, report, safe_member, shared_statistics_link, MAX_EXPANDED, MAX_MEMBERS)
from directadmin_mail import source_config, sync_mailbox, sql_literal

DB = Path('/var/lib/masspanel/masspanel.db')
SETTINGS = Path('/etc/masspanel/directadmin-import.json')
IDENTIFIER = re.compile(r'[A-Za-z0-9_-]{1,64}')
PROTECTED = {'root', 'ubuntu', 'masspanel', 'www-data', 'gromox', 'grommunio', 'massimo'}
PRIVILEGES = {'select_priv': 'SELECT', 'insert_priv': 'INSERT', 'update_priv': 'UPDATE',
              'delete_priv': 'DELETE', 'create_priv': 'CREATE', 'drop_priv': 'DROP',
              'index_priv': 'INDEX', 'alter_priv': 'ALTER', 'references_priv': 'REFERENCES',
              'create_tmp_table_priv': 'CREATE TEMPORARY TABLES', 'lock_tables_priv': 'LOCK TABLES',
              'create_view_priv': 'CREATE VIEW', 'show_view_priv': 'SHOW VIEW',
              'create_routine_priv': 'CREATE ROUTINE', 'alter_routine_priv': 'ALTER ROUTINE',
              'execute_priv': 'EXECUTE', 'event_priv': 'EVENT', 'trigger_priv': 'TRIGGER'}


def run(command, data=None, timeout=120):
    result = subprocess.run(command, input=data, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise ImportError('Restore command failed: ' + Path(command[0]).name + '. Source data and the destination snapshot are retained for review.')
    return result.stdout


def sql(statement):
    return run(['/usr/bin/mariadb', '--batch', '--skip-column-names'], statement)


def database_users(plan, database):
    if not IDENTIFIER.fullmatch(database) or database.lower() in {'mysql', 'sys', 'performance_schema', 'information_schema', 'grommunio'}:
        raise ImportError('Unsupported or protected database name in the backup.')
    result = []
    for username, value in config(plan['metadata'].get(database + '.conf', '')).items():
        if username in {'accesshosts', 'db_collation'}: continue
        fields = {k: v[-1] for k, v in parse_qs(value, keep_blank_values=True).items()}
        if not IDENTIFIER.fullmatch(username) or username.lower() in {'root', 'mysql', 'mariadb.sys', 'grommunio'}:
            raise ImportError('Unsupported or protected database username.')
        hashed = fields.get('passwd', '')
        if fields.get('plugin', 'mysql_native_password') != 'mysql_native_password' or not re.fullmatch(r'\*[A-Fa-f0-9]{40}', hashed):
            raise ImportError('A database password uses an unsupported authentication format; no password was reset.')
        hosts = fields.get('accesshosts', 'localhost').split(',')
        for host in hosts:
            if not re.fullmatch(r'[A-Za-z0-9_.:%-]{1,255}', host):
                raise ImportError('Unsupported database access host.')
            privileges = [privilege for key, privilege in PRIVILEGES.items() if fields.get(key) == 'Y']
            if not privileges:
                raise ImportError('Database grants could not be read from the backup.')
            result.append({'username': username, 'host': host, 'hash': hashed.upper(), 'privileges': privileges})
    if not result: raise ImportError('Database credentials are missing from the backup.')
    return result


def runtime_settings():
    if not SETTINGS.exists(): return {'php_versions': {'1': '8.3'}, 'homeserver': 0}
    info = SETTINGS.lstat()
    if SETTINGS.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ImportError('Import settings must be a protected root-owned file.')
    value = json.loads(SETTINGS.read_text())
    if not isinstance(value.get('php_versions'), dict): raise ImportError('Configure the source PHP selector mapping.')
    for selector, version in value['php_versions'].items():
        if not re.fullmatch(r'[1-9][0-9]*', selector) or not re.fullmatch(r'[578]\.[0-9]', version):
            raise ImportError('Invalid PHP selector mapping.')
    if type(value.get('homeserver', 0)) is not int or not 0 <= value.get('homeserver', 0) <= 65535:
        raise ImportError('Invalid Grommunio home server.')
    return value


def database_collation(plan, database):
    value = config(plan['metadata'].get(database + '.conf', '')).get('db_collation', 'utf8mb4_unicode_ci')
    source_charset = None
    if '=' in value:
        fields = parse_qs(value, keep_blank_values=True)
        if any(len(items) != 1 for items in fields.values()) or fields.get('SCHEMA_NAME', [database])[0] != database:
            raise ImportError('Conflicting source database collation metadata.')
        source_charset = fields.get('DEFAULT_CHARACTER_SET_NAME', [''])[0]
        value = fields.get('DEFAULT_COLLATION_NAME', [''])[0]
        if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', source_charset):
            raise ImportError('Invalid source database character set.')
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', value):
        raise ImportError('Invalid source database collation.')
    charset = sql('SELECT CHARACTER_SET_NAME FROM information_schema.COLLATIONS WHERE COLLATION_NAME=' + sql_literal(value)).strip()
    if not re.fullmatch(r'[A-Za-z0-9_]{1,64}', charset):
        raise ImportError('The source database collation is unavailable on the destination: ' + value)
    if source_charset and source_charset != charset and {source_charset, charset} != {'utf8', 'utf8mb3'}:
        raise ImportError('Source and destination database character sets differ.')
    return charset, value


def preflight(plans, options, completed, settings):
    # Re-use the exact signed entitlement validator used by domain creation.
    os.environ.setdefault('MASSPANEL_SECRET_KEY', secrets.token_hex(32))
    import app as panel
    with panel.db() as conn:
        license = panel.license_status(conn)
        new_domains = sum(panel.is_root_domain(site['domain']) for p in plans if p['username'] not in completed
                          for site in p.get('websites', p['domains']))
        if license['domain_limit'] is not None and license['domain_count'] + new_domains > license['domain_limit']:
            raise ImportError(f"This import needs {license['domain_count'] + new_domains} root domains, but the current MassPanel license permits {license['domain_limit']}. Activate sufficient capacity, then retry.")
        for p in plans:
            if not p.get('mail_inventory_complete'):
                raise ImportError('Export current source identities and inspect again so default mailboxes and their original passwords are included.')
            if not p.get('web_inventory_complete'):
                raise ImportError('Export current source website routing and inspect again to preserve subdomain document roots.')
            if fingerprint(archive_path(p['file'])) != p['fingerprint']:
                raise ImportError('A staged archive changed after inspection. Inspect it again.')
            if p['username'] in completed: continue
            forwarders(p)
            username = p['username']
            if username in PROTECTED: raise ImportError('A source username is reserved on the destination.')
            existing = conn.execute('SELECT role FROM accounts WHERE username=?', (username,)).fetchone()
            if existing and not (username == 'admin' and existing['role'] == 'admin' and options.get('merge_admin')):
                raise ImportError('Panel username already exists: ' + username + '. Explicitly review the initial admin merge or resolve the conflict.')
            try: pwd.getpwnam(username)
            except KeyError: pass
            else: raise ImportError('System username already exists: ' + username + '. A partial restore requires operator review.')
            if (Path('/home') / username).exists(): raise ImportError('An account home directory already exists: ' + username)
            selectors = {d['php_selector'] for d in p['websites']}
            if len(selectors) > 1:
                raise ImportError('This account uses multiple PHP selectors. Configure separate per-domain pools before importing ' + username)
            registry = Path('/etc/masspanel/imported-webroots.json')
            roots = {}
            if registry.exists() or registry.is_symlink():
                info = registry.lstat()
                if registry.is_symlink() or not registry.is_file() or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ImportError('Imported website mappings must be a protected root-owned file.')
                roots = json.loads(registry.read_text())
                if not isinstance(roots, dict): raise ImportError('Invalid imported website mappings.')
            for d in p['websites']:
                domain = d['domain']
                if domain in roots: raise ImportError('Imported website mapping already exists: ' + domain)
                if conn.execute('SELECT 1 FROM domains WHERE domain=?', (domain,)).fetchone():
                    raise ImportError('Destination domain already exists: ' + domain)
                for candidate in (Path('/etc/nginx/sites-available') / ('masspanel-domain-' + domain + '.conf'),
                                  Path('/var/lib/bind/masspanel') / (domain + '.zone')):
                    if candidate.exists(): raise ImportError('An existing website or DNS configuration conflicts with ' + domain)
                selector = d['php_selector']
                version = settings['php_versions'].get(selector)
                if not version or not Path('/etc/php', version, 'fpm/pool.d').is_dir():
                    raise ImportError('Install and map PHP selector ' + selector + ' before importing ' + domain + '. No PHP version was silently changed.')
            for database in p['databases']:
                users = database_users(p, database)
                database_collation(p, database)
                if sql('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=' + sql_literal(database)) .strip():
                    raise ImportError('Destination database already exists: ' + database)
                for user in users:
                    if sql('SELECT User FROM mysql.user WHERE User=' + sql_literal(user['username']) + ' AND Host=' + sql_literal(user['host'])).strip():
                        raise ImportError('Destination database username already exists: ' + user['username'])
    required = sum(p['expanded_bytes'] for p in plans if p['username'] not in completed)
    # Conservative: archive expansion, restored copy, database/mail growth and reserve.
    if shutil.disk_usage(ROOT).free < required * 2 + 10 * 1024 ** 3:
        raise ImportError('Not enough free space for extraction, restored data and a 10 GiB reserve.')
    mail = [m for p in plans if p['username'] not in completed for m in p['mailboxes']]
    if mail:
        source_config()
        for unit in ('gromox-http', 'gromox-imap', 'gromox-midb', 'gromox-zcore'):
            run(['/usr/bin/systemctl', 'is-active', '--quiet', unit])
        # Ask the installed admin API for the real effective capacity, including
        # an operator's separately documented Community source customization.
        capacity = int(run(['/usr/bin/python3', '-c',
            "import sys;sys.path.insert(0,'/usr/share/grommunio-admin-api');from tools.license import getLicense;print(getLicense().users)"], timeout=30).strip())
        count = int(sql('SELECT COUNT(*) FROM grommunio.users WHERE domain_id<>0').strip())
        if count + len(mail) > capacity: raise ImportError('Grommunio does not have capacity for every selected mailbox.')
        for mailbox in mail:
            if sql('SELECT username FROM grommunio.users WHERE username=' + sql_literal(mailbox['address'])).strip():
                raise ImportError('Destination mailbox already exists: ' + mailbox['address'])
    return panel


def extract_archive(path, destination, username=None):
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    expanded = 0
    with open_archive(path) as archive:
        for index, member in enumerate(archive):
            safe_member(member, username)
            if shared_statistics_link(member): continue
            expanded += member.size
            if expanded > MAX_EXPANDED or index >= MAX_MEMBERS or shutil.disk_usage(destination).free < member.size + 512 * 1024 ** 2:
                raise ImportError('Archive expansion exceeded its size, file-count or available-space limit.')
            archive.extract(member, path=destination, filter='data')


def restore_database(plan, database, stage, work):
    users = database_users(plan, database)
    charset, collation = database_collation(plan, database)
    sql(f'CREATE DATABASE `{database}` CHARACTER SET {charset} COLLATE {collation};')
    temporary = 'mp_import_' + secrets.token_hex(8)
    password = secrets.token_hex(32)
    cnf = work / 'database.cnf'
    cnf.write_text(f'[client]\nuser={temporary}\npassword={password}\n'); cnf.chmod(0o600)
    try:
        sql(f"CREATE USER '{temporary}'@'localhost' IDENTIFIED BY '{password}'; GRANT ALL ON `{database}`.* TO '{temporary}'@'localhost';")
        with open(stage / 'backup' / (database + '.sql'), 'rb') as source:
            process = subprocess.run(['/usr/bin/mariadb', '--defaults-extra-file=' + str(cnf),
                                     '--binary-mode', '--local-infile=0', database],
                                     stdin=source, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=7200)
        if process.returncode: raise ImportError('Database restore failed for ' + database + '; the partial destination is retained for review.')
        for user in users:
            identity = f"'{user['username']}'@'{user['host']}'"
            # The preflight rejected existing users. Shared users within this
            # account must retain an identical hash; check before reuse.
            existing = sql(f'SELECT authentication_string FROM mysql.user WHERE User={sql_literal(user["username"])} AND Host={sql_literal(user["host"])}').strip()
            if existing and existing != user['hash']: raise ImportError('A shared database username has conflicting passwords.')
            if not existing: sql(f"CREATE USER {identity} IDENTIFIED BY PASSWORD '{user['hash']}';")
            sql(f"GRANT {', '.join(user['privileges'])} ON `{database}`.* TO {identity};")
    finally:
        sql(f"DROP USER IF EXISTS '{temporary}'@'localhost';")
        cnf.unlink(missing_ok=True)


def restore_dns(domain, stage, conn, stamp, actor):
    import dns.zone
    import dns.rdatatype
    source = stage / 'backup' / domain / (domain + '.db')
    if not source.is_file(): raise ImportError('DNS zone is missing for ' + domain)
    text = source.read_text()
    if re.search(r'^\s*\$(?:INCLUDE|GENERATE)\b', text, re.I | re.M):
        raise ImportError('DNS include/generate directives require review for ' + domain)
    zone = dns.zone.from_text(text, origin=domain, allow_include=False)
    records = []; unsupported = []
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            kind = dns.rdatatype.to_text(rdataset.rdtype)
            if kind == 'SOA': continue
            for item in rdataset:
                value = item.to_text(origin=zone.origin, relativize=False)
                if kind in {'TXT', 'SPF'}: value = b''.join(item.strings).decode('utf-8')
                if kind not in {'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SPF', 'SRV'}:
                    unsupported.append(kind); continue
                records.append((domain, kind, name.to_text(), value, rdataset.ttl, stamp, actor))
    target = Path('/var/lib/bind/masspanel') / (domain + '.zone')
    target.parent.mkdir(parents=True, exist_ok=True)
    run(['/usr/bin/named-checkzone', domain, str(source)])
    shutil.copyfile(source, target); target.chmod(0o644)
    conn.executemany('INSERT INTO dns_records(domain,type,name,value,ttl,created_at,created_by) VALUES(?,?,?,?,?,?,?)', records)
    if unsupported:
        # Prevent a later editor save from silently dropping unfamiliar RRs.
        target.with_suffix('.preserve').write_text('Imported records requiring manual DNS management: ' + ', '.join(sorted(set(unsupported))))


def restore_certificate(domain, stage, source_domain=None):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    directory = stage / 'backup' / (source_domain or domain)
    cert = directory / 'domain.cert'; key = directory / 'domain.key'
    if not cert.is_file() or not key.is_file() or not cert.stat().st_size or not key.stat().st_size:
        return 'self'
    certificate = x509.load_pem_x509_certificate(cert.read_bytes())
    private_key = serialization.load_pem_private_key(key.read_bytes(), password=None)
    def public(value):
        return value.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(certificate) != public(private_key): raise ImportError('Certificate/key mismatch for ' + domain)
    try: names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = [value.value for value in certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    if not any(name.lower() == domain or (name.startswith('*.') and domain.endswith(name[1:].lower()) and domain.count('.') == name.count('.')) for name in names):
        return 'self'
    target = Path('/etc/masspanel/imported-tls') / domain
    target.mkdir(mode=0o700, parents=True, exist_ok=False)
    chain = cert.read_bytes().rstrip() + b'\n'
    if (directory / 'domain.cacert').is_file(): chain += (directory / 'domain.cacert').read_bytes()
    (target / 'fullchain.pem').write_bytes(chain); (target / 'fullchain.pem').chmod(0o644)
    (target / 'privkey.pem').write_bytes(key.read_bytes()); (target / 'privkey.pem').chmod(0o600)
    return 'imported'


def forwarders(plan):
    result = []
    for d in plan['domains']:
        domain = d['domain']
        for line in plan['metadata'].get(domain + '/email/aliases', '').splitlines():
            if not line.strip() or ':' not in line: continue
            local, destination = (part.strip() for part in line.split(':', 1))
            if local == '*' and destination in {':fail:', ':blackhole:'}: continue
            if not re.fullmatch(r'[a-z0-9._%+-]{1,64}', local):
                raise ImportError('A catch-all or special mail alias requires manual review for ' + domain)
            destinations = []
            for item in destination.split(','):
                item = item.strip()
                if '@' not in item: item += '@' + domain
                if not re.fullmatch(r'[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,63}', item):
                    raise ImportError('A pipe, file or special mail forwarder requires manual review for ' + domain)
                if item != local + '@' + domain: destinations.append(item)
            if destinations:
                result.append({'address': local + '@' + domain, 'domain': domain, 'local': local,
                               'destination': ','.join(destinations), 'copy': local + '@' + domain in destination.split(',') or local in destination.split(',')})
    return result


def restore_account(plan, stage, work, options, settings, panel, actor):
    import helper
    username = plan['username']; account = plan['account']
    suspended = plan['locked'] or account.get('suspended') == 'yes'
    shell = '/bin/bash' if account.get('ssh') == 'ON' else '/usr/sbin/nologin'
    run(['/usr/sbin/useradd', '--create-home', '--shell', '/usr/sbin/nologin', '--', username])
    system = pwd.getpwnam(username); home = Path(system.pw_dir)
    # Keep logins locked until every account component has been restored.
    run(['/usr/sbin/chpasswd', '-e'], username + ':!' + plan['hash'] + '\n')
    for nested in ('home.tar.zst', 'home.tar.gz'):
        archive = stage / 'backup' / nested
        if archive.exists():
            expanded_home = work / 'home'
            extract_archive(archive, expanded_home, username)
            run(['/usr/bin/rsync', '-a', '--safe-links', '--chown=' + username + ':' + grp.getgrgid(system.pw_gid).gr_name,
                 str(expanded_home) + '/', str(home) + '/'], timeout=14400)
    for name in ('domains', 'imap'):
        source = stage / name
        if source.is_dir():
            run(['/usr/bin/rsync', '-a', '--safe-links', '--chown=' + username + ':' + grp.getgrgid(system.pw_gid).gr_name,
                 str(source), str(home) + '/'], timeout=14400)
    for database in plan['databases']: restore_database(plan, database, stage, work)
    stamp = panel.now()
    with panel.db() as conn:
        role = 'admin' if account.get('usertype') == 'admin' else 'client'
        quota = account.get('quota', '10240')
        quota = int(quota) if quota.isdigit() else 0
        limit = max(len(plan['domains']), int(account.get('vdomains', '10')) if account.get('vdomains', '').isdigit() else 1000)
        if username == 'admin' and options.get('merge_admin'):
            conn.execute('UPDATE accounts SET password_hash=?,system_username=?,active=? WHERE username=?', (plan['hash'], username, int(not suspended), username))
        else:
            conn.execute('INSERT INTO accounts(username,password_hash,role,system_username,active,domain_limit,disk_limit_mb,created_at) VALUES(?,?,?,?,?,?,?,?)',
                         (username, plan['hash'], role, username, int(not suspended), limit, quota, stamp))
        for d in plan['websites']:
            domain = d['domain']; webroot = home / d['relative_webroot']
            if webroot.is_symlink() or not webroot.is_dir(): raise ImportError('Website root is missing or linked: ' + domain)
            registry = Path('/etc/masspanel/imported-webroots.json')
            roots = json.loads(registry.read_text()) if registry.exists() else {}
            if domain in roots: raise ImportError('Imported website mapping already exists: ' + domain)
            roots[domain] = {'owner': username, 'webroot': str(webroot)}
            atomic_json(registry, roots)
            helper.domain_paths(domain, username, webroot)
            version = settings['php_versions'][d['php_selector']]
            socket_path = '/run/php/masspanel-' + username + '.sock'
            pool = Path('/etc/php', version, 'fpm/pool.d', 'masspanel-' + username + '.conf')
            if not pool.exists():
                pool.write_text(f'[{username}]\nuser={username}\ngroup={grp.getgrgid(system.pw_gid).gr_name}\nlisten={socket_path}\nlisten.owner=www-data\nlisten.group=www-data\nlisten.mode=0660\npm=ondemand\npm.max_children=4\npm.process_idle_timeout=10s\n')
                pool.chmod(0o644)
                run(['/usr/bin/systemctl', 'reload', 'php' + version + '-fpm'])
            home.chmod(0o711)
            helper.grant_panel_access(system, webroot)
            ssl_mode = restore_certificate(domain, stage, d['parent'])
            helper.write_domain_config(domain, webroot, ssl_mode, suspended, socket_path)
            conn.execute('INSERT INTO domains(domain,owner,webroot,suspended,ssl_mode,php_enabled,created_at,created_by) VALUES(?,?,?,?,?,1,?,?)',
                         (domain, username, str(webroot), int(suspended), ssl_mode, stamp, actor))
        for d in plan['domains']:
            domain = d['domain']
            restore_dns(domain, stage, conn, stamp, actor)
            if plan['mailboxes']:
                run(['/usr/sbin/grommunio-admin', 'domain', 'create', '--homeserver', str(settings.get('homeserver', 0)), '-u', '1000', domain])
                conn.execute('INSERT INTO mail_domains(domain,zone_domain,owner,status,grommunio_managed,created_at,created_by) VALUES(?,?,?,?,1,?,?)',
                             (domain, domain, username, 'suspended' if suspended else 'active', stamp, actor))
        for database in plan['databases']:
            primary = account.get('domain')
            domains = [d['domain'] for d in plan['domains']]
            if primary not in domains: primary = domains[0] if domains else None
            if not primary: raise ImportError('A database has no owning website domain: ' + database)
            db_users = database_users(plan, database)
            conn.execute('INSERT INTO imported_databases(owner,domain,db_name,db_user,created_at,created_by) VALUES(?,?,?,?,?,?)',
                         (username, primary, database, db_users[0]['username'], stamp, actor))
        conn.commit()
        for mailbox in plan['mailboxes']:
            address = mailbox['address']; local, domain = address.split('@')
            quotas = dict(line.split(':', 1) for line in plan['metadata'].get(domain + '/email/quota', '').splitlines() if ':' in line)
            quota_bytes = int(quotas.get(local, '0'))
            if quota_bytes < 0: raise ImportError('Invalid mailbox quota.')
            quota_kb = (quota_bytes + 1023) // 1024
            run(['/usr/sbin/grommunio-admin', 'user', 'create', '--homeserver', str(settings.get('homeserver', 0)),
                 '--pop3-imap', 'true', '--privWeb', 'true', '--smtp', 'true', '--lang', 'en_US',
                 '--property', 'storagequotalimit=' + str(quota_kb), address], timeout=180)
            sync_mailbox(mailbox, work / 'mail' / address, source_config(), suspended)
            conn.execute('INSERT INTO email_accounts(full_email,domain,localpart,status,created_at,created_by,mail_domain,quota_mb,password_hash) VALUES(?,?,?,?,?,?,?,?,?)',
                         (address, domain, local, 'suspended' if suspended or mailbox['hash'].startswith('!') else 'active', stamp, actor, domain, (quota_bytes + 1048575) // 1048576, '{GROMMUNIO}'))
            conn.commit()
        for entry in forwarders(plan):
            sql('INSERT INTO grommunio.forwards(username,forward_type,destination) VALUES(' + sql_literal(entry['address']) + ',' + ('0' if entry['copy'] else '1') + ',' + sql_literal(entry['destination']) + ');')
            exists = conn.execute('SELECT 1 FROM email_accounts WHERE full_email=?', (entry['address'],)).fetchone()
            if exists:
                conn.execute('UPDATE email_accounts SET destination=? WHERE full_email=?', (entry['destination'], entry['address']))
            else:
                conn.execute('INSERT INTO email_accounts(full_email,domain,localpart,destination,status,created_at,created_by,mail_domain) VALUES(?,?,?,?,?,?,?,?)',
                             (entry['address'], entry['domain'], entry['local'], entry['destination'], 'suspended' if suspended else 'active', stamp, actor, entry['domain']))
        conn.execute('INSERT INTO audit(created_at,actor,action,target,outcome) VALUES(?,?,?,?,?)', (stamp, actor, 'directadmin.restore', username, 'success'))
    helper.rebuild_dns_config()
    run(['/usr/sbin/chpasswd', '-e'], username + ':' + ('!' if suspended else '') + plan['hash'] + '\n')
    if not suspended: run(['/usr/sbin/usermod', '--shell', shell, '--', username])


def restore_job(job, path):
    plans = json.loads((path / 'plan.private.json').read_text())
    options = json.loads((path / 'options.json').read_text())
    request = json.loads((path / 'request.json').read_text())
    ledger_path = path / 'ledger.json'
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else {'completed': [], 'started': None}
    if ledger.get('started'):
        raise ImportError('A previous attempt stopped while restoring ' + ledger['started'] + '. Review its partial destination and snapshot before retrying; automatic overwrite is disabled.')
    settings = runtime_settings()
    panel = preflight(plans, options, ledger['completed'], settings)
    snapshot = path / 'masspanel-before.db'
    if not snapshot.exists():
        with sqlite3.connect(DB) as source, sqlite3.connect(snapshot) as destination: source.backup(destination)
        snapshot.chmod(0o600)
    for i, plan in enumerate(plans):
        username = plan['username']
        if username in ledger['completed']: continue
        report(job, phase='restoring', message='Restoring ' + username, progress=round(i * 100 / len(plans)))
        work = path / 'accounts' / username; work.mkdir(mode=0o700, parents=True, exist_ok=True)
        stage = work / 'archive'
        if stage.exists(): raise ImportError('A previous extraction exists for ' + username + '; review it before retrying.')
        extract_archive(archive_path(plan['file']), stage, username)
        ledger['started'] = username; atomic_json(ledger_path, ledger)
        restore_account(plan, stage, work, options, settings, panel, request['actor'])
        ledger['completed'].append(username); ledger['started'] = None; atomic_json(ledger_path, ledger)
        # Keep native archives and metadata; discard only our private extracted copy.
        shutil.rmtree(stage)
        if (work / 'home').exists(): shutil.rmtree(work / 'home')
    report(job, phase='restored', progress=100,
           message='Selected accounts restored. Validate websites, database grants, mail counts/flags and DNS, then run a final mail delta before cutover. Scheduled tasks and ancillary DirectAdmin settings remain in the backups for review.')
