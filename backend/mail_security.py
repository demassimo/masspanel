"""Recipient-scoped mail review, durable quarantine and optional local-model scoring."""
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import threading
from urllib.request import Request, build_opener, ProxyHandler

from cryptography.fernet import Fernet
from flask import jsonify, request, session
import mail_ai
from mail_security_worker import runtime


POLICY = {'junk_score': 6.0, 'quarantine_score': 15.0, 'accepted_to_junk': False}
MALWARE = {'CLAM_VIRUS', 'CLAMAV_VIRUS', 'VIRUS', 'MALWARE'}


def choose_decision(score, symbols, policy, rule=None, authenticated=False):
    names = set(symbols)
    if names & MALWARE: return 'quarantine', 'Malware detected; sender rules cannot bypass it.'
    if rule == 'block': return 'quarantine', 'Mailbox-specific blocklist.'
    if rule == 'welcome' and authenticated: return 'inbox', 'Authenticated sender on mailbox welcome list.'
    if score >= policy['quarantine_score']: return 'quarantine', 'High spam score.'
    if score >= policy['junk_score'] or policy['accepted_to_junk']: return 'junk', 'Suspected spam or review-all policy.'
    return 'inbox', 'Below the spam threshold.'


def rspamd_scan(raw, metadata):
    headers = {'Content-Type': 'message/rfc822', 'Rcpt': metadata['recipient'],
               'Deliver-To': metadata['recipient'], 'From': metadata['sender'],
               'Queue-Id': metadata['queue_id'], 'IP': metadata['ip'], 'Pass': 'all'}
    if metadata.get('helo'): headers['Helo'] = metadata['helo']
    # Do not use User: that means authenticated SMTP sender, not mailbox recipient.
    opener = build_opener(ProxyHandler({}), mail_ai.NoRedirect())
    with opener.open(Request('http://127.0.0.1:11333/checkv2', data=raw,
                             headers=headers, method='POST'), timeout=30) as response:
        body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024: raise ValueError('Oversized scanner response.')
    result = json.loads(body)
    if type(result.get('score')) not in {int, float} or not math.isfinite(result['score']):
        raise ValueError('Scanner did not return a finite score.')
    if not isinstance(result.get('symbols'), dict): raise ValueError('Scanner did not return symbols.')
    return result


class Security:
    def __init__(self, context):
        self.p = context
        self.db = context['db']
        self.base = context['BASE']
        self.spool = context['QUARANTINE_DIR']
        self.scanner = rspamd_scan
        self.ai_transport = mail_ai.post_json
        self.scan_slots = threading.BoundedSemaphore(2)
        self.init_schema()

    def init_schema(self):
        with self.db() as c:
            c.executescript('''
                CREATE TABLE IF NOT EXISTS mail_security_recipients(
                  event_id TEXT NOT NULL,recipient TEXT NOT NULL,status TEXT NOT NULL,
                  decision TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
                  updated_at TEXT NOT NULL,actor TEXT NOT NULL DEFAULT '',
                  PRIMARY KEY(event_id,recipient));
                CREATE INDEX IF NOT EXISTS mail_security_recipient_status ON mail_security_recipients(status);
                CREATE TABLE IF NOT EXISTS mail_security_details(event_id TEXT PRIMARY KEY,details_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS mail_security_rules(
                  recipient TEXT NOT NULL,sender TEXT NOT NULL,kind TEXT NOT NULL,
                  created_at TEXT NOT NULL,created_by TEXT NOT NULL,PRIMARY KEY(recipient,sender));
                CREATE TABLE IF NOT EXISTS mail_security_config(name TEXT PRIMARY KEY,value TEXT NOT NULL);
            ''')

    def now(self): return self.p['now']()
    def audit(self, action, target): self.p['audit'](action, target)

    def pipeline(self):
        try: return 'active' if runtime().get('enabled') is True else 'staged'
        except (OSError, ValueError): return 'configuration_error'

    def config(self, name, defaults):
        with self.db() as c: row = c.execute('SELECT value FROM mail_security_config WHERE name=?', (name,)).fetchone()
        return {**defaults, **(json.loads(row['value']) if row else {})}

    def save(self, name, value):
        with self.db() as c:
            c.execute('INSERT INTO mail_security_config VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value', (name, json.dumps(value)))

    def ai_config(self, public=False):
        value = self.config('ai', mail_ai.DEFAULTS)
        token = value.pop('encrypted_key', '')
        if public: value['has_key'] = bool(token)
        elif token: value['api_key'] = self.cipher().decrypt(token.encode()).decode()
        return value

    def cipher(self):
        key = str(self.p['app'].secret_key).encode()
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key + b':mail-ai').digest()))

    def trusted(self):
        # Check the socket peer as well as the forwarded address and a private token.
        original = request.environ.get('werkzeug.proxy_fix.orig', {}).get('REMOTE_ADDR', request.remote_addr)
        if original not in {'127.0.0.1', '::1'} or request.remote_addr not in {'127.0.0.1', '::1'}: return False
        try: expected = self.p['RSPAMD_EXPORT_SECRET'].read_text().strip()
        except OSError: return False
        supplied = request.authorization.password if request.authorization else ''
        return bool(expected and hmac.compare_digest(supplied or '', expected))

    def known_recipient(self, address):
        if not self.p['_valid_email_address'](address): return False
        with self.db() as c:
            return c.execute("SELECT 1 FROM email_accounts e JOIN mail_domains m ON m.domain=COALESCE(e.mail_domain,e.domain) WHERE e.full_email=? AND e.status='active' AND m.status='active'", (address,)).fetchone() is not None

    def visible_recipients(self, recipients):
        if session.get('role') == 'admin': return recipients
        with self.db() as c:
            domains = {r['domain'] for r in c.execute('SELECT domain FROM mail_domains WHERE owner=?', (session.get('system_username'),))}
        return [r for r in recipients if r['recipient'].rpartition('@')[2] in domains]

    def detail(self, event_id):
        with self.db() as c:
            row = c.execute('SELECT * FROM mail_security_events WHERE id=?', (event_id,)).fetchone()
            if not row: return None
            recipients = [dict(x) for x in c.execute('SELECT * FROM mail_security_recipients WHERE event_id=?', (event_id,))]
            details = c.execute('SELECT details_json FROM mail_security_details WHERE event_id=?', (event_id,)).fetchone()
        if not recipients:
            # Historical SMTP rejection copies are tracking evidence, not accepted quarantine.
            recipients = [{'recipient': a, 'status': 'tracked', 'decision': row['action']} for a in json.loads(row['recipients_json'])]
        recipients = self.visible_recipients(recipients)
        if not recipients: return None
        value = dict(row)
        value.pop('quarantine_path', None)
        value.pop('recipients_json', None)
        value['recipients'] = [r['recipient'] for r in recipients]
        value['deliveries'] = recipients
        value['symbols'] = json.loads(value.pop('symbols_json'))
        value['details'] = json.loads(details['details_json']) if details else {'accepted': False}
        value['quarantined'] = any(r['status'] == 'quarantined' for r in recipients)
        return value

    def store(self, metadata, raw, result, decision, reason, ai, accepted):
        address = metadata['recipient']
        digest = hashlib.sha256(raw).hexdigest()
        key = hashlib.sha256(json.dumps([metadata['queue_id'], address, metadata['sender'], digest]).encode()).hexdigest()
        with self.db() as c:
            existing = c.execute('SELECT id FROM mail_security_events WHERE message_key=?', (key,)).fetchone()
            if existing: return existing['id']
        event_id = secrets.token_urlsafe(18)
        path = ''
        # Only the queue handoff endpoint can create a releasable, accepted copy.
        if accepted:
            self.spool.mkdir(mode=0o700, parents=True, exist_ok=True)
            file = self.spool / (event_id + '.eml')
            fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            # Persist the directory entry before acknowledging the upstream queue.
            if os.name != 'nt':
                fd = os.open(self.spool, os.O_RDONLY | os.O_DIRECTORY)
                try: os.fsync(fd)
                finally: os.close(fd)
            path = str(file)
        subject = mail_ai.message_text(raw, 1)['subject'] if raw else str(metadata.get('subject', ''))[:500]
        symbols = result.get('symbols', {})
        symbol_list = [{'name': name, 'score': value.get('score', 0)} for name, value in symbols.items() if isinstance(value, dict)]
        details = {'accepted': accepted, 'reason': reason, 'ai': ai, 'rspamd_score': result['score'],
                   'authentication': {k: 'pass' if v in symbols else 'fail' if any(x in symbols for x in fails) else 'unknown'
                     for k, v, fails in [('spf', 'R_SPF_ALLOW', ['R_SPF_FAIL', 'R_SPF_SOFTFAIL']),
                                         ('dkim', 'R_DKIM_ALLOW', ['R_DKIM_REJECT']),
                                         ('dmarc', 'DMARC_POLICY_ALLOW', ['DMARC_POLICY_REJECT', 'DMARC_POLICY_QUARANTINE'])]},
                   'dangerous': bool(set(symbols) & MALWARE)}
        status = 'quarantined' if accepted and decision == 'quarantine' else 'queued' if accepted else 'blocked' if decision == 'reject' else 'tracked'
        try:
            with self.db() as c:
                c.execute('PRAGMA synchronous=FULL')
                c.execute('INSERT INTO mail_security_events(id,message_key,queue_id,sender,recipients_json,subject,source_ip,score,action,symbols_json,size_bytes,quarantine_path,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                          (event_id, key, metadata['queue_id'], metadata['sender'], json.dumps([address]), subject,
                           metadata.get('ip', ''), result['score'] + ai.get('score', 0), decision,
                           json.dumps(symbol_list), len(raw), path, 'quarantined' if status == 'quarantined' else 'tracked', self.now()))
                c.execute('INSERT INTO mail_security_recipients(event_id,recipient,status,decision,updated_at) VALUES(?,?,?,?,?)', (event_id, address, status, decision, self.now()))
                c.execute('INSERT INTO mail_security_details VALUES(?,?)', (event_id, json.dumps(details)))
        except sqlite3.IntegrityError:
            if path: Path(path).unlink(missing_ok=True)
            with self.db() as c:
                row = c.execute('SELECT id FROM mail_security_events WHERE message_key=?', (key,)).fetchone()
            if row: return row['id']
            raise
        return event_id

    def scan(self, metadata, raw):
        required = ('queue_id', 'sender', 'recipient', 'ip')
        if any(not isinstance(metadata.get(k), str) or len(metadata[k]) > 320 or re.search(r'[\r\n\x00]', metadata[k]) for k in required):
            raise ValueError('Invalid trusted envelope metadata.')
        if not re.fullmatch(r'[A-Za-z0-9_-]{5,100}', metadata['queue_id']): raise ValueError('A stable queue ID is required.')
        if metadata['sender'] and not self.p['_valid_email_address'](metadata['sender']): raise ValueError('Invalid envelope sender.')
        if not self.known_recipient(metadata['recipient']): raise ValueError('Unknown local recipient.')
        ipaddress.ip_address(metadata['ip'])
        if metadata.get('helo') and (not isinstance(metadata['helo'], str) or not re.fullmatch(r'[a-zA-Z0-9._:\[\]-]{1,255}', metadata['helo'])):
            raise ValueError('Invalid SMTP greeting.')
        result = self.scanner(raw, metadata)
        if result.get('is_skipped') or result.get('error') or result.get('action') == 'soft reject':
            raise RuntimeError('Scanner requested a temporary hold.')
        if set(result['symbols']) & {'CLAM_VIRUS_FAIL', 'CLAMAV_VIRUS_FAIL'}:
            raise RuntimeError('Malware scan unavailable.')
        config = self.ai_config()
        ai = mail_ai.scan(raw, config, config.get('api_key', ''), self.ai_transport)
        with self.db() as c:
            rule = c.execute('SELECT kind FROM mail_security_rules WHERE recipient=? AND sender=?', (metadata['recipient'], metadata['sender'])).fetchone()
        # SPF validates the exact envelope sender used by our rules, not a displayed From.
        authenticated = 'R_SPF_ALLOW' in result['symbols']
        decision, reason = choose_decision(result['score'] + ai.get('score', 0), result['symbols'],
                                          self.config('policy', POLICY), rule['kind'] if rule else None, authenticated)
        if result.get('action') == 'reject':
            decision, reason = 'quarantine', 'Scanner requested rejection; accepted copy retained for review.'
        event_id = self.store(metadata, raw, result, decision, reason, ai, True)
        return {'id': event_id, 'accepted': True, 'decision': decision}


def register(context):
    service = Security(context)
    app = context['app']
    auth, admin, csrf = (context[k] for k in ('require_auth', 'require_admin', 'require_csrf'))

    @app.get('/api/mail-security/settings')
    @auth
    @admin
    def mail_security_settings():
        return jsonify(ai=service.ai_config(public=True), policy=service.config('policy', POLICY),
                       pipeline=service.pipeline(), message='Mail routing requires explicit server activation.')

    @app.put('/api/mail-security/settings')
    @auth
    @admin
    @csrf
    def mail_security_save_settings():
        value = request.get_json(silent=True)
        if not isinstance(value, dict): return jsonify(error='Invalid settings.'), 400
        updates = {}
        try:
            if 'ai' in value:
                data = value['ai']
                config = mail_ai.validate_config(data)
                old = service.config('ai', {})
                if old.get('encrypted_key'): config['encrypted_key'] = old['encrypted_key']
                key = data.get('api_key', '')
                if not isinstance(key, str) or len(key) > 4096 or re.search(r'[\r\n\x00]', key): raise ValueError('Invalid API key.')
                if key: config['encrypted_key'] = service.cipher().encrypt(key.encode()).decode()
                if data.get('clear_key') is True: config.pop('encrypted_key', None)
                # Never send an old destination's key to a newly configured server.
                if old.get('url') != config['url'] and not key: config.pop('encrypted_key', None)
                updates['ai'] = config
            if 'policy' in value:
                config = value['policy']
                if not isinstance(config, dict): raise ValueError('Invalid routing policy.')
                result = {k: config.get(k, v) for k, v in POLICY.items()}
                if any(type(result[k]) not in {int, float} or not math.isfinite(result[k]) for k in ('junk_score', 'quarantine_score')):
                    raise ValueError('Scores must be finite numbers.')
                if not 0 <= result['junk_score'] < result['quarantine_score'] <= 100 or type(result['accepted_to_junk']) is not bool:
                    raise ValueError('Quarantine must have a higher score than Junk.')
                updates['policy'] = result
        except (ValueError, TypeError): return jsonify(error='Invalid settings; check server URL, model, consent and score limits.'), 400
        with service.db() as c:
            for name, value in updates.items():
                c.execute('INSERT INTO mail_security_config VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value', (name, json.dumps(value)))
        service.audit('mail.security.settings', 'configuration')
        return jsonify(ok=True)

    @app.post('/api/mail-security/ai/test')
    @auth
    @admin
    @csrf
    def mail_security_ai_test():
        if context['limited']((session['username'], 'mail-ai-test'), 5, 60): return jsonify(error='Try again in a minute.'), 429
        config = service.ai_config()
        raw = b'From: fixture@example.invalid\r\nSubject: Synthetic connector test\r\n\r\nThis is an internal test message, not customer email.\r\n'
        result = mail_ai.scan(raw, config, config.get('api_key', ''), service.ai_transport, synthetic=True)
        service.audit('mail.ai.test', result['status'])
        return jsonify(result)

    @app.post('/api/mail-security/ingest/scan')
    def mail_security_scan():
        if not service.trusted(): return jsonify(error='Not authorized.'), 403
        if not service.scan_slots.acquire(blocking=False):
            return jsonify(error='Scanner busy; retain message in the sending queue.'), 503
        try:
            meta = json.loads(request.headers.get('X-MassPanel-Envelope', '{}'))
            raw = request.get_data(cache=False)
            if not isinstance(meta, dict) or not raw or len(raw) > 64 * 1024 * 1024: raise ValueError('Empty or oversized message.')
            return jsonify(service.scan(meta, raw)), 201
        except (ValueError, KeyError): return jsonify(error='Invalid message or envelope metadata.'), 400
        except Exception: return jsonify(error='Scan or durable storage unavailable; retain message in the sending queue.'), 503
        finally: service.scan_slots.release()

    @app.post('/api/mail-security/ingest/event')
    @app.post('/api/mail-security/ingest/quarantine')
    def mail_security_metadata():
        if not service.trusted(): return jsonify(error='Not authorized.'), 403
        # Legacy exports did not acknowledge SMTP acceptance. They must never
        # become releasable solely because a copy of a rejected message exists.
        value = request.get_json(silent=True)
        if not isinstance(value, dict): return jsonify(error='Use the durable queue handoff for quarantine.'), 409
        recipients = value.get('rcpt') or value.get('recipients') or []
        if not isinstance(recipients, list): recipients = [recipients]
        ids = []
        for address in recipients[:100]:
            if not isinstance(address, str) or not service.known_recipient(address.lower()): continue
            try:
                score = float(value.get('score', 0))
                if not math.isfinite(score): raise ValueError()
                meta = {'recipient': address.lower(), 'sender': str(value.get('from', ''))[:320],
                        'queue_id': str(value.get('qid') or value.get('queue_id') or secrets.token_hex(16))[:100],
                        'ip': str(value.get('ip', ''))[:64], 'subject': str(value.get('subject') or value.get('header_subject') or '')[:500]}
                symbols = value.get('symbols', {})
                if not isinstance(symbols, dict): symbols = {}
                ids.append(service.store(meta, b'', {'score': score, 'symbols': symbols}, str(value.get('action', 'tracked'))[:64], 'Scanner metadata only.', {'status': 'not_scanned'}, False))
            except (ValueError, TypeError): return jsonify(error='Invalid scanner metadata.'), 400
        return jsonify(ok=True, ids=ids), 201

    @app.get('/api/mail-security/events')
    @auth
    def mail_security_events():
        with service.db() as c:
            ids = [r['id'] for r in c.execute('SELECT id FROM mail_security_events ORDER BY created_at DESC,id DESC LIMIT 1000')]
        visible = [v for key in ids if (v := service.detail(key)) is not None]
        stats = {'total': len(visible), 'quarantined': 0, 'inbox': 0, 'junk': 0, 'blocked': 0, 'released': 0, 'pending': 0}
        days = {}
        for item in visible:
            statuses = {r['status'] for r in item['deliveries']}
            decisions = {r['decision'] for r in item['deliveries']}
            stats['quarantined'] += 'quarantined' in statuses
            stats['released'] += 'released' in statuses
            stats['blocked'] += 'blocked' in statuses
            stats['inbox'] += 'inbox' in decisions
            stats['junk'] += 'junk' in decisions
            stats['pending'] += bool(statuses & {'queued', 'delivering', 'delivery_uncertain', 'failed'})
            day = item['created_at'][:10]; days[day] = days.get(day, 0) + 1
        selected = request.args.get('status', 'all')
        search = request.args.get('search', '').lower()[:200]
        rows = [v for v in visible if (selected == 'all' or selected == v['action'] or any(selected in (x['status'], x['decision']) for x in v['deliveries']))
                and (not search or search in (v['sender'] + ' ' + v['subject'] + ' ' + ' '.join(v['recipients']) + ' ' + v['queue_id']).lower())]
        return jsonify(events=rows[:250], stats=stats, daily=[{'day': k, 'count': days[k]} for k in sorted(days)],
                       scope='all customers' if session.get('role') == 'admin' else 'your domains',
                       window='Latest 1,000 events; statistics are independent of the selected filter.',
                       pipeline=service.pipeline(), ai_enabled=service.ai_config(public=True)['enabled'] if session.get('role') == 'admin' else None)

    @app.get('/api/mail-security/events/<event_id>/preview')
    @auth
    def mail_security_preview(event_id):
        event = service.detail(event_id)
        if not event: return jsonify(error='Message not found.'), 404
        with service.db() as c: row = c.execute('SELECT quarantine_path FROM mail_security_events WHERE id=?', (event_id,)).fetchone()
        path = Path(row['quarantine_path'])
        if not row['quarantine_path'] or path.parent.resolve() != service.spool.resolve() or path.is_symlink() or not path.is_file():
            return jsonify(error='No retained message body.'), 404
        if path.stat().st_size > 64 * 1024 * 1024: return jsonify(error='Message exceeds preview limit.'), 400
        preview = mail_ai.message_text(path.read_bytes(), 12000)
        service.audit('mail.preview', event_id)
        return jsonify(text=preview['text'], attachments_loaded=False)

    @app.post('/api/mail-security/events/<event_id>/release')
    @auth
    @admin
    @csrf
    def mail_security_release(event_id):
        value = request.get_json(silent=True) or {}
        if not isinstance(value, dict): return jsonify(error='Invalid request.'), 400
        event = service.detail(event_id)
        if not event or event['details'].get('accepted') is not True: return jsonify(error='No accepted quarantined message.'), 404
        recipient = value.get('recipient')
        if recipient not in event['recipients']: return jsonify(error='Select one recipient of this message.'), 400
        if event['details'].get('dangerous') and value.get('confirm_dangerous') is not True:
            return jsonify(error='This message has a malware verdict. Explicit confirmation is required.'), 409
        with service.db() as c:
            claimed = c.execute("UPDATE mail_security_recipients SET status='queued',decision='inbox',actor=?,updated_at=? WHERE event_id=? AND recipient=? AND status='quarantined'", (session['username'], service.now(), event_id, recipient)).rowcount
        if claimed != 1: return jsonify(error='Already handled or not quarantined; no additional delivery was queued.'), 409
        service.audit('mail.deliver_once', event_id + ':' + recipient)
        return jsonify(ok=True, status='queued', recipient=recipient), 202

    @app.post('/api/mail-security/events/<event_id>/retry')
    @auth
    @admin
    @csrf
    def mail_security_retry(event_id):
        value = request.get_json(silent=True)
        if not isinstance(value, dict): return jsonify(error='Invalid request.'), 400
        event = service.detail(event_id)
        if not event or event['details'].get('accepted') is not True: return jsonify(error='Message not found.'), 404
        recipient = value.get('recipient')
        if recipient not in event['recipients']: return jsonify(error='Select a message recipient.'), 400
        with service.db() as c:
            changed = c.execute("UPDATE mail_security_recipients SET status='queued',updated_at=? WHERE event_id=? AND recipient=? AND status='failed'", (service.now(), event_id, recipient)).rowcount
        if changed != 1: return jsonify(error='Only a confirmed failed delivery can be retried. Reconcile uncertain deliveries first.'), 409
        service.audit('mail.retry', event_id + ':' + recipient)
        return jsonify(ok=True, status='queued'), 202

    @app.get('/api/mail-security/rules')
    @auth
    @admin
    def mail_security_rules():
        with service.db() as c:
            rules = [dict(r) for r in c.execute('SELECT * FROM mail_security_rules ORDER BY recipient,sender')]
            addresses = [r['full_email'] for r in c.execute('SELECT full_email FROM email_accounts ORDER BY full_email')]
        return jsonify(rules=rules, recipients=addresses)

    @app.post('/api/mail-security/rules')
    @auth
    @admin
    @csrf
    def mail_security_rule_save():
        value = request.get_json(silent=True)
        if not isinstance(value, dict): return jsonify(error='Invalid rule.'), 400
        recipient, sender, kind = (value.get(k, '') for k in ('recipient', 'sender', 'kind'))
        if not isinstance(recipient, str) or not isinstance(sender, str): return jsonify(error='Invalid addresses.'), 400
        recipient, sender = recipient.lower().strip(), sender.lower().strip()
        if not service.known_recipient(recipient) or not context['_valid_email_address'](sender) or kind not in {'welcome', 'block', 'remove'}:
            return jsonify(error='Select a local mailbox, exact sender address and rule type.'), 400
        with service.db() as c:
            if kind == 'remove': c.execute('DELETE FROM mail_security_rules WHERE recipient=? AND sender=?', (recipient, sender))
            else: c.execute('INSERT INTO mail_security_rules VALUES(?,?,?,?,?) ON CONFLICT(recipient,sender) DO UPDATE SET kind=excluded.kind,created_at=excluded.created_at,created_by=excluded.created_by', (recipient, sender, kind, service.now(), session['username']))
        service.audit('mail.rule.' + kind, recipient + ':' + sender)
        return jsonify(ok=True)

    return service
