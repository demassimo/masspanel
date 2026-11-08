"""Deliver accepted recipient copies to loopback Gromox; never an external relay."""
import json
import os
from pathlib import Path
import re
import smtplib
import stat
from datetime import datetime, timedelta, timezone

RUNTIME = Path('/etc/masspanel/mail-security-delivery.json')


def runtime():
    if not RUNTIME.exists(): return {'enabled': False, 'lda_port': 10024}
    info = RUNTIME.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Delivery configuration must be a protected root-owned regular file.')
    value = json.loads(RUNTIME.read_text())
    if type(value.get('enabled')) is not bool or type(value.get('lda_port', 10024)) is not int:
        raise ValueError('Invalid delivery configuration.')
    if not 1 <= value.get('lda_port', 10024) <= 65535: raise ValueError('Invalid delivery port.')
    days = value.get('delivered_body_days', 7)
    if type(days) is not int or not 1 <= days <= 365: raise ValueError('Invalid delivered-body retention.')
    return value


def prune_delivered_bodies(service, config):
    """Retain event metadata and all undelivered/quarantined copies."""
    if config.get('enabled') is not True: return 0
    cutoff = (datetime.now(timezone.utc) - timedelta(days=config.get('delivered_body_days', 7))).strftime('%Y-%m-%d %H:%M:%S UTC')
    removed = 0
    with service.db() as c:
        rows = c.execute("""SELECT e.id,e.quarantine_path FROM mail_security_events e
          WHERE e.quarantine_path!='' AND EXISTS(SELECT 1 FROM mail_security_recipients r WHERE r.event_id=e.id)
          AND NOT EXISTS(SELECT 1 FROM mail_security_recipients r WHERE r.event_id=e.id
            AND (r.status NOT IN ('inbox','junk','released') OR r.updated_at>=?)) LIMIT 1000""", (cutoff,)).fetchall()
        for row in rows:
            path = Path(row['quarantine_path'])
            if path.parent.resolve() != service.spool.resolve() or path.is_symlink(): continue
            path.unlink(missing_ok=True)
            c.execute("UPDATE mail_security_events SET quarantine_path='' WHERE id=?", (row['id'],))
            removed += 1
    return removed


def delivery_bytes(raw, decision):
    """Replace our private routing headers without re-encoding MIME content."""
    match = re.search(br'\r?\n\r?\n', raw)
    if not match: raise ValueError('Message has no header/body boundary.')
    header, body = raw[:match.start()], raw[match.end():]
    blocks = re.split(br'\r?\n(?![ \t])', header)
    blocks = [b for b in blocks if not b.split(b':', 1)[0].lower().startswith(b'x-masspanel-')]
    return b'X-MassPanel-Spam: ' + (b'Yes' if decision == 'junk' else b'No') + b'\r\n' + b'\r\n'.join(blocks) + b'\r\n\r\n' + body


def process_one(service, config, smtp_factory=smtplib.SMTP):
    if config.get('enabled') is not True: return False
    with service.db() as c:
        c.execute('BEGIN IMMEDIATE')
        row = c.execute("SELECT r.*,e.quarantine_path,e.sender FROM mail_security_recipients r JOIN mail_security_events e ON e.id=r.event_id WHERE r.status='queued' ORDER BY r.updated_at LIMIT 1").fetchone()
        if not row: return False
        row = dict(row)
        c.execute("UPDATE mail_security_recipients SET status='delivering',attempts=attempts+1,updated_at=? WHERE event_id=? AND recipient=?", (service.now(), row['event_id'], row['recipient']))
    # A process crash after this claim leaves 'delivering' for manual reconciliation.
    # It is never automatically claimed again and potentially delivered twice.
    sent_data = False
    accepted = False
    status = 'failed'
    try:
        if not service.known_recipient(row['recipient']): raise ValueError('Local mailbox no longer exists.')
        path = Path(row['quarantine_path'])
        if path.parent.resolve() != service.spool.resolve() or path.is_symlink(): raise ValueError('Invalid spool path.')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            if os.fstat(stream.fileno()).st_size > 64 * 1024 * 1024: raise ValueError('Oversized message.')
            raw = stream.read()
        raw = delivery_bytes(raw, row['decision'])
        with smtp_factory('127.0.0.1', config.get('lda_port', 10024), timeout=30) as smtp:
            smtp.ehlo_or_helo_if_needed()
            code, _ = smtp.mail(row['sender'])
            if code != 250: raise ValueError('Sender refused.')
            code, _ = smtp.rcpt(row['recipient'])
            if code not in {250, 251}: raise ValueError('Recipient refused.')
            sent_data = True
            code, _ = smtp.data(raw)
            if code != 250:
                sent_data = False
                raise ValueError('Message explicitly refused.')
            status = 'released' if row['actor'] else row['decision']
            accepted = True
    except smtplib.SMTPDataError:
        status = 'failed'  # An explicit negative DATA reply is a definite refusal.
    except Exception:
        if not accepted:
            status = 'delivery_uncertain' if sent_data else 'failed'
    with service.db() as c:
        c.execute('UPDATE mail_security_recipients SET status=?,updated_at=? WHERE event_id=? AND recipient=?', (status, service.now(), row['event_id'], row['recipient']))
        if status == 'released':
            c.execute("UPDATE mail_security_events SET status='released',released_at=?,released_by=? WHERE id=?", (service.now(), row['actor'], row['event_id']))
    # No message bodies, subjects, addresses or credentials in daemon output.
    print(json.dumps({'event_id': row['event_id'], 'delivery_status': status}))
    return True


if __name__ == '__main__':
    from app import mail_security
    config = runtime()
    for _ in range(100):
        if not process_one(mail_security, config): break
    prune_delivered_bodies(mail_security, config)
