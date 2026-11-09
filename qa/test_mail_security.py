"""Synthetic fixtures only: no customer messages or external model calls."""
import base64
import json
from pathlib import Path
import smtplib
import importlib.util
import io
import unittest
from unittest.mock import Mock, patch

import test_backend as fixtures
from test_backend import panel, STATE
import mail_ai
from mail_security import choose_decision, POLICY
from mail_security_worker import process_one, delivery_bytes, prune_delivered_bodies

RAW = b'From: Sender <sender@example.org>\r\nSubject: Synthetic example\r\nX-MassPanel-Spam: Yes\r\n\r\nSynthetic message body.\r\n'
META = {'queue_id': 'TEST12345', 'sender': 'sender@example.org', 'recipient': 'alice@alice.example.com', 'ip': '192.0.2.1'}


class PipeTests(unittest.TestCase):
    def test_only_a_positive_durable_acknowledgement_completes_the_postfix_handoff(self):
        spec = importlib.util.spec_from_file_location('mail_pipe', Path(__file__).resolve().parents[1] / 'deploy/mail-security-pipe.py')
        pipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pipe)
        argv = ['pipe', '--queue-id=TEST12345', '--sender=<>', '--recipient=alice@alice.example.com', '--ip=192.0.2.1']
        for acknowledgement, expected in [({'accepted': True}, 0), ({'accepted': False}, 75), ({}, 75)]:
            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = json.dumps(acknowledgement).encode()
            opener = Mock()
            opener.open.return_value = response
            with patch.object(pipe.sys, 'argv', argv), patch.object(pipe.sys, 'stdin', Mock(buffer=io.BytesIO(RAW))), patch.object(pipe.Path, 'read_text', return_value='fixture-token'), patch.object(pipe, 'build_opener', return_value=opener):
                self.assertEqual(pipe.main(), expected)
            request = opener.open.call_args.args[0]
            envelope = json.loads(request.get_header('X-masspanel-envelope'))
            self.assertEqual(envelope['sender'], '')
            self.assertEqual(envelope['recipient'], META['recipient'])


class AITests(unittest.TestCase):
    def config(self, **values):
        return {**mail_ai.DEFAULTS, 'enabled': True, 'content_approved': True,
                'url': 'https://model.example.invalid', 'model': 'owner-model', **values}

    def test_empty_disabled_configuration_never_calls_network(self):
        transport = Mock(side_effect=AssertionError('Must not send mail'))
        self.assertEqual(mail_ai.scan(RAW, mail_ai.DEFAULTS, transport=transport)['status'], 'disabled')
        self.assertEqual(mail_ai.DEFAULTS['url'], '')
        self.assertEqual(mail_ai.DEFAULTS['model'], '')
        transport.assert_not_called()

    def test_native_ollama_contract_and_bounded_signal(self):
        transport = Mock(return_value={'done': True, 'message': {'content': '{"spam_probability":0.9,"reason":"spam example"}'}})
        result = mail_ai.scan(RAW, self.config(), 'secret', transport)
        self.assertEqual(result['score'], 4)
        args, kwargs = transport.call_args
        self.assertEqual(args[0], 'https://model.example.invalid/api/chat')
        self.assertFalse(args[1]['stream'])
        self.assertEqual(args[1]['format'], mail_ai.SCHEMA)
        self.assertEqual(kwargs['headers'], {'Authorization': 'Bearer secret'})
        self.assertIn('untrusted', args[1]['messages'][0]['content'])

    def test_openai_compatible_contract_and_ham_cannot_lower_score(self):
        transport = Mock(return_value={'choices': [{'message': {'content': '{"spam_probability":0,"reason":"ham"}'}}]})
        result = mail_ai.scan(RAW, self.config(provider='openai-compatible', url='https://model.example.invalid/v1'), transport=transport)
        self.assertEqual(result['score'], 0)
        self.assertEqual(transport.call_args.args[0], 'https://model.example.invalid/v1/chat/completions')

    def test_bad_responses_are_nonfatal_and_do_not_echo_private_errors(self):
        for value in [True, -1, 2, float('nan'), '1']:
            with self.subTest(value=value):
                transport = Mock(return_value={'done': True, 'message': {'content': json.dumps({'spam_probability': value, 'reason': 'x'})}})
                self.assertEqual(mail_ai.scan(RAW, self.config(), transport=transport)['status'], 'unavailable')
        for response in [{}, {'done': False}, {'done': True, 'message': {'content': 'not JSON'}}]:
            self.assertEqual(mail_ai.scan(RAW, self.config(), transport=Mock(return_value=response))['score'], 0)
        result = mail_ai.scan(RAW, self.config(), transport=Mock(side_effect=TimeoutError('PRIVATE-KEY-AND-BODY')))
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_consent_url_and_numeric_validation(self):
        for changes in [{'content_approved': False}, {'model': ''}, {'url': 'http://host.invalid'},
                        {'url': 'https://user:password@host.invalid'}, {'timeout': True}, {'max_score': float('inf')}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                mail_ai.validate_config(self.config(**changes))
        self.assertEqual(mail_ai.validate_config(self.config(url='http://host.invalid:11434', allow_http=True))['url'], 'http://host.invalid:11434')

    def test_plaintext_preview_excludes_attachments_and_scripts(self):
        raw = b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/html\r\n\r\n<p>Hello</p><script>SECRET_SCRIPT</script>\r\n--x\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=secret.txt\r\n\r\nSECRET_ATTACHMENT\r\n--x--\r\n'
        text = mail_ai.message_text(raw)['text']
        self.assertIn('Hello', text)
        self.assertNotIn('SECRET', text)

    def test_spf_does_not_bypass_content_and_welcome_never_bypasses_malware(self):
        self.assertEqual(choose_decision(8, {'R_SPF_ALLOW': {}}, POLICY)[0], 'junk')
        self.assertEqual(choose_decision(20, {'R_SPF_ALLOW': {}}, POLICY)[0], 'quarantine')
        self.assertEqual(choose_decision(20, {}, POLICY, 'welcome', False)[0], 'quarantine')
        self.assertEqual(choose_decision(20, {}, POLICY, 'welcome', True)[0], 'inbox')
        self.assertEqual(choose_decision(0, {'CLAM_VIRUS': {}}, POLICY, 'welcome', True)[0], 'quarantine')
        self.assertEqual(choose_decision(0, {}, POLICY, 'block', True)[0], 'quarantine')


class SecurityTests(unittest.TestCase):
    login_as = fixtures.BackendFeatureTests.login_as

    def setUp(self):
        fixtures.BackendFeatureTests.setUp(self)
        self.service = panel.mail_security
        self.original_scanner = self.service.scanner
        self.original_transport = self.service.ai_transport
        self.original_secret = panel.RSPAMD_EXPORT_SECRET
        panel.RSPAMD_EXPORT_SECRET = STATE / 'test-export-secret'
        panel.RSPAMD_EXPORT_SECRET.write_text('fixture-token')
        self.service.scanner = Mock(return_value={'score': 20, 'symbols': {'R_SPF_ALLOW': {'score': -0.2}}})
        self.service.ai_transport = Mock(side_effect=AssertionError('No external AI'))
        with panel.db() as c:
            for table in ('mail_security_events', 'mail_security_recipients', 'mail_security_details', 'mail_security_config', 'mail_security_rules'):
                c.execute('DELETE FROM ' + table)
            for owner in ('alice', 'bob'):
                domain = owner + '.example.com'
                c.execute('INSERT INTO email_accounts(full_email,domain,localpart,created_at,created_by,mail_domain) VALUES(?,?,?,?,?,?)',
                          (owner + '@' + domain, domain, owner, panel.now(), 'admin', domain))
        self.login_as('admin', 'admin')
        self.csrf = {'X-CSRF-Token': 'token'}

    def tearDown(self):
        self.service.scanner = self.original_scanner
        self.service.ai_transport = self.original_transport
        panel.RSPAMD_EXPORT_SECRET = self.original_secret
        fixtures.BackendFeatureTests.tearDown(self)

    def ingest(self, metadata=None, raw=RAW):
        headers = {'Authorization': 'Basic ' + base64.b64encode(b'masspanel:fixture-token').decode(),
                   'X-MassPanel-Envelope': json.dumps(metadata or META)}
        return self.client.post('/api/mail-security/ingest/scan', data=raw, headers=headers, content_type='message/rfc822')

    def status(self, event):
        with panel.db() as c:
            return c.execute('SELECT status FROM mail_security_recipients WHERE event_id=?', (event,)).fetchone()['status']

    def test_durable_handoff_and_deduplication_is_recipient_specific(self):
        first = self.ingest()
        self.assertEqual(first.status_code, 201, first.data)
        event = first.json['id']
        self.assertEqual(self.ingest().json['id'], event)
        other = self.ingest({**META, 'recipient': 'bob@bob.example.com'})
        self.assertNotEqual(event, other.json['id'])
        self.assertEqual(self.status(event), 'quarantined')
        with panel.db() as c:
            row = c.execute('SELECT quarantine_path FROM mail_security_events WHERE id=?', (event,)).fetchone()
        self.assertEqual(Path(row['quarantine_path']).read_bytes(), RAW)
        self.service.ai_transport.assert_not_called()

    def test_private_handoff_rejects_external_peer_and_bad_envelopes(self):
        self.assertEqual(self.client.post('/api/mail-security/ingest/scan', data=RAW).status_code, 403)
        with patch.object(self.service, 'trusted', return_value=False):
            self.assertEqual(self.ingest().status_code, 403)
        for change in [{'recipient': 'outside@example.org'}, {'ip': 'not-an-ip'}, {'queue_id': 'bad\nheader'}]:
            self.assertEqual(self.ingest({**META, **change}).status_code, 400)
        with patch.object(self.service, 'store', side_effect=OSError('disk full')):
            self.assertEqual(self.ingest().status_code, 503)

    def test_temporary_scanner_failure_retains_upstream_queue_and_forced_reject_quarantines(self):
        for result in [{'score': 0, 'symbols': {}, 'action': 'soft reject'},
                       {'score': 0, 'symbols': {'CLAM_VIRUS_FAIL': {}}},
                       {'score': 0, 'symbols': {}, 'is_skipped': True}]:
            self.service.scanner.return_value = result
            self.assertEqual(self.ingest().status_code, 503)
        self.service.scanner.return_value = {'score': 0, 'symbols': {}, 'action': 'reject'}
        self.assertEqual(self.ingest().json['decision'], 'quarantine')

    def test_scan_capacity_keeps_requests_in_upstream_queue(self):
        self.service.scan_slots.acquire(); self.service.scan_slots.acquire()
        try: self.assertEqual(self.ingest().status_code, 503)
        finally: self.service.scan_slots.release(); self.service.scan_slots.release()

    def test_retention_removes_only_old_delivered_body_not_quarantine(self):
        held = self.ingest().json['id']
        delivered = self.ingest({**META, 'queue_id': 'OTHER12345'}).json['id']
        with panel.db() as c:
            c.execute("UPDATE mail_security_recipients SET updated_at='2000-01-01 00:00:00 UTC'")
            c.execute("UPDATE mail_security_recipients SET status='inbox' WHERE event_id=?", (delivered,))
            paths = {r['id']: r['quarantine_path'] for r in c.execute('SELECT id,quarantine_path FROM mail_security_events')}
        self.assertEqual(prune_delivered_bodies(self.service, {'enabled': False}), 0)
        self.assertEqual(prune_delivered_bodies(self.service, {'enabled': True}), 1)
        self.assertTrue(Path(paths[held]).is_file())
        self.assertFalse(Path(paths[delivered]).exists())
        with panel.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM mail_security_events').fetchone()[0], 2)

    def test_customer_visibility_and_admin_only_release(self):
        event = self.ingest().json['id']
        self.login_as('bob', 'client', 'bob')
        self.assertEqual(self.client.get('/api/mail-security/events').json['events'], [])
        self.assertEqual(self.client.get('/api/mail-security/events/' + event + '/preview').status_code, 404)
        self.login_as('alice', 'client', 'alice')
        visible = self.client.get('/api/mail-security/events').json['events']
        self.assertEqual([v['id'] for v in visible], [event])
        self.assertNotIn('quarantine_path', visible[0])
        self.assertEqual(self.client.get('/api/mail-security/settings').status_code, 403)
        self.assertEqual(self.client.post('/api/mail-security/events/' + event + '/release', json={'recipient': META['recipient']}, headers=self.csrf).status_code, 403)

    def test_release_is_csrf_protected_once_only_and_does_not_welcome_sender(self):
        event = self.ingest().json['id']
        url = '/api/mail-security/events/' + event + '/release'
        body = {'recipient': META['recipient']}
        self.assertEqual(self.client.post(url, json=body).status_code, 403)
        self.assertEqual(self.client.post(url, json=body, headers=self.csrf).status_code, 202)
        self.assertEqual(self.client.post(url, json=body, headers=self.csrf).status_code, 409)
        self.assertEqual(self.client.get('/api/mail-security/rules').json['rules'], [])

    def test_rejected_metadata_copy_cannot_be_released(self):
        event = self.service.store(META, b'', {'score': 20, 'symbols': {}}, 'reject', 'SMTP refused', {}, False)
        self.assertEqual(self.client.post('/api/mail-security/events/' + event + '/release', json={'recipient': META['recipient']}, headers=self.csrf).status_code, 404)

    def test_mailbox_welcome_rule_is_isolated(self):
        rule = {**META, 'kind': 'welcome'}
        self.assertEqual(self.client.post('/api/mail-security/rules', json=rule, headers=self.csrf).status_code, 200)
        self.assertEqual(self.ingest().json['decision'], 'inbox')
        self.assertEqual(self.ingest({**META, 'recipient': 'bob@bob.example.com'}).json['decision'], 'quarantine')

    def test_atomic_settings_encrypt_and_redact_key_and_clear_on_destination_change(self):
        config = {**mail_ai.DEFAULTS, 'url': 'https://model.invalid', 'model': 'my-model', 'api_key': 'PRIVATE-API-KEY'}
        url = '/api/mail-security/settings'
        self.assertEqual(self.client.put(url, json={'ai': config}, headers=self.csrf).status_code, 200)
        self.assertNotIn('PRIVATE', json.dumps(self.client.get(url).json))
        self.assertTrue(self.client.get(url).json['ai']['has_key'])
        with panel.db() as c:
            self.assertNotIn('PRIVATE', c.execute("SELECT value FROM mail_security_config WHERE name='ai'").fetchone()['value'])
        self.assertEqual(self.service.ai_config()['api_key'], 'PRIVATE-API-KEY')
        invalid = {'ai': {**config, 'enabled': True, 'content_approved': True}, 'policy': {'junk_score': 20, 'quarantine_score': 5}}
        self.assertEqual(self.client.put(url, json=invalid, headers=self.csrf).status_code, 400)
        self.assertFalse(self.service.ai_config()['enabled'])
        self.assertEqual(self.client.put(url, json={'ai': {**config, 'url': 'https://new-model.invalid', 'api_key': ''}}, headers=self.csrf).status_code, 200)
        self.assertNotIn('api_key', self.service.ai_config())

    def queue(self):
        event = self.ingest().json['id']
        self.client.post('/api/mail-security/events/' + event + '/release', json={'recipient': META['recipient']}, headers=self.csrf)
        return event

    def smtp(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.mail.return_value = (250, b'ok')
        connection.rcpt.return_value = (250, b'ok')
        connection.data.return_value = (250, b'ok')
        return connection

    def test_disabled_worker_never_connects(self):
        event = self.queue()
        smtp = Mock()
        self.assertFalse(process_one(self.service, {'enabled': False}, smtp))
        smtp.assert_not_called()
        self.assertEqual(self.status(event), 'queued')

    def test_successful_local_release_and_quit_failure_are_not_retried(self):
        event = self.queue()
        smtp = self.smtp()
        smtp.__exit__.side_effect = OSError('QUIT lost after accepted DATA')
        factory = Mock(return_value=smtp)
        self.assertTrue(process_one(self.service, {'enabled': True}, factory))
        self.assertEqual(self.status(event), 'released')
        self.assertEqual(factory.call_args.args, ('127.0.0.1', 10024))
        smtp.rcpt.assert_called_once_with(META['recipient'])
        self.assertFalse(process_one(self.service, {'enabled': True}, factory))
        sent = smtp.data.call_args.args[0]
        self.assertIn(b'X-MassPanel-Spam: No', sent)
        self.assertNotIn(b'X-MassPanel-Spam: Yes', sent)
        self.assertEqual(sent.split(b'\r\n\r\n', 1)[1], RAW.split(b'\r\n\r\n', 1)[1])

    def test_uncertain_data_delivery_is_held_and_cannot_retry(self):
        event = self.queue()
        smtp = self.smtp()
        smtp.data.side_effect = OSError('connection lost')
        process_one(self.service, {'enabled': True}, Mock(return_value=smtp))
        self.assertEqual(self.status(event), 'delivery_uncertain')
        self.assertFalse(process_one(self.service, {'enabled': True}, Mock(return_value=smtp)))
        self.assertEqual(self.client.post('/api/mail-security/events/' + event + '/retry', json={'recipient': META['recipient']}, headers=self.csrf).status_code, 409)

    def test_explicit_data_refusal_can_be_retried_once(self):
        event = self.queue()
        smtp = self.smtp()
        smtp.data.side_effect = smtplib.SMTPDataError(451, b'try later')
        process_one(self.service, {'enabled': True}, Mock(return_value=smtp))
        self.assertEqual(self.status(event), 'failed')
        url = '/api/mail-security/events/' + event + '/retry'
        self.assertEqual(self.client.post(url, json={'recipient': META['recipient']}, headers=self.csrf).status_code, 202)
        self.assertEqual(self.client.post(url, json={'recipient': META['recipient']}, headers=self.csrf).status_code, 409)


if __name__ == '__main__': unittest.main()
