import crypt
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
import directadmin_import as importer
from directadmin_restore import database_users
from passwords import supported_legacy_hash, verify_password
from argon2 import PasswordHasher


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


source = load_script('source_bridge', ROOT / 'deploy/directadmin-imap-source.py')
capacity = load_script('community_capacity', ROOT / 'deploy/configure-grommunio-community.py')
HASH = crypt.crypt('Existing-password!', '$6$exampleSalt$')


class DirectAdminTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'user.admin.alice.tar.gz'
        identities = patch.object(importer, 'IDENTITIES', Path(self.directory.name) / 'identities.json')
        identities.start(); self.addCleanup(identities.stop)

    def archive(self, entries=None):
        entries = entries or [('backup/user.conf', b'username=alice\nusertype=user\nsuspended=no\n'),
                              ('backup/.shadow', HASH.encode()),
                              ('backup/example.com/domain.conf', b'php1_select=1\n'),
                              ('backup/example.com/email/passwd', ('info:' + HASH + ':1:1\n').encode())]
        with tarfile.open(self.path, 'w:gz') as archive:
            for name, data in entries:
                member = tarfile.TarInfo(name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return self.path

    def test_import_preserves_and_redacts_hashes(self):
        plan = importer.inspect_archive(self.archive())
        self.assertEqual(plan['hash'], HASH)
        self.assertEqual(plan['mailboxes'][0]['hash'], HASH)
        report = importer.public_account(plan)
        self.assertEqual(report['mailboxes'], 1)
        self.assertNotIn(HASH, json.dumps(report))
        self.assertNotIn('metadata', report)

    def test_wrong_password_and_unsupported_hash_are_rejected(self):
        hasher = PasswordHasher()
        self.assertTrue(verify_password(hasher, HASH, 'Existing-password!'))
        self.assertFalse(verify_password(hasher, HASH, 'wrong-password'))
        self.assertFalse(verify_password(hasher, '!' + HASH, 'Existing-password!'))
        self.assertFalse(supported_legacy_hash('$6$rounds=999999999$salt$' + 'a' * 86))
        self.assertFalse(verify_password(hasher, 'broken-hash', 'password'))

    def test_default_mailbox_keeps_its_separate_current_password(self):
        different = crypt.crypt('Different-mail-password!', '$6$anotherSalt$')
        importer.IDENTITIES.write_text(json.dumps({'accounts':[{'username':'alice','password_hash':HASH}],
            'domains':[{'domain':'example.com','owner':'alice'}],
            'mail':[{'domain':'example.com','accounts':[{'localpart':'alice','hash':different}]}]}))
        importer.IDENTITIES.chmod(0o600)
        plan = importer.inspect_archive(self.archive())
        self.assertTrue(plan['mail_inventory_complete'])
        self.assertEqual(plan['mailboxes'], [{'address':'alice@example.com','hash':different}])

    def test_empty_folders_still_participate_in_metadata_verification(self):
        from directadmin_mail_verify import folder_mappings
        mappings = folder_mappings('Folder 1/2 [INBOX] -> [INBOX]\nFolder 2/2 [Sent] -> [Sent Items]\nFolders synced : 2/2 synced\n', Path(self.directory.name))
        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[1], ['Sent', 'Sent Items', None])

    def test_subdomain_custom_document_root_is_preserved_and_validated(self):
        entries = [('backup/user.conf', b'username=alice\nusertype=user\n'),
            ('backup/.shadow', HASH.encode()), ('backup/example.com/domain.conf', b'php1_select=1\n'),
            ('backup/example.com/subdomain.list', b'billing\n')]
        path = self.archive(entries)
        self.assertFalse(importer.inspect_archive(path)['web_inventory_complete'])
        identities = {'accounts':[{'username':'alice','password_hash':HASH}],
            'domains':[{'domain':'example.com','owner':'alice'}],
            'mail':[{'domain':'example.com','accounts':[]}],
            'websites':[{'owner':'alice','domain':'example.com','parent':'example.com','relative_webroot':'domains/example.com/public_html','php_selector':'1'},
                {'owner':'alice','domain':'billing.example.com','parent':'example.com','relative_webroot':'domains/billing.example.com/app/public','php_selector':'1'}]}
        importer.IDENTITIES.write_text(json.dumps(identities)); importer.IDENTITIES.chmod(0o600)
        plan = importer.inspect_archive(path)
        self.assertTrue(plan['web_inventory_complete'])
        self.assertEqual(plan['websites'][1]['relative_webroot'],'domains/billing.example.com/app/public')
        for unsafe in ('../../etc', 'domains/../../bob/private', 'domains/site;include /etc/nginx/*'):
            identities['websites'][1]['relative_webroot']=unsafe
            importer.IDENTITIES.write_text(json.dumps(identities))
            with self.assertRaises(importer.ImportError): importer.inspect_archive(path)

    def test_metadata_verification_retains_labels_and_ignores_recent(self):
        from directadmin_mail_verify import metadata
        class Client:
            def _quote(self, name): return name
            def select(self, *args, **kwargs): return 'OK', [b'1']
            def uid(self, *args): return 'OK', [b'1 (UID 42 FLAGS (\\Recent \\Seen \\Deleted $Label1) INTERNALDATE "01-Jan-2020 12:34:56 +0200" RFC822.SIZE 100)']
        values = metadata(Client(), 'INBOX')
        self.assertEqual(values[42]['flags'], ['$label1', '\\deleted', '\\seen'])
        self.assertEqual(values[42]['date'], 1577874896)

    def test_traversal_and_escaping_links_rejected(self):
        for name in ('../escape', '/etc/shadow', 'backup/../../escape', 'backup\\escape'):
            with self.subTest(name=name), self.assertRaises(importer.ImportError):
                importer.safe_member(tarfile.TarInfo(name))
        for link in ('/etc/shadow', '../../../escape'):
            member = tarfile.TarInfo('domains/example.com/link'); member.type = tarfile.SYMTYPE; member.linkname = link
            with self.subTest(link=link), self.assertRaises(importer.ImportError): importer.safe_member(member)

    def test_duplicate_metadata_rejected(self):
        path = self.archive([('backup/user.conf', b'username=alice'), ('backup/user.conf', b'username=bob')])
        with self.assertRaises(importer.ImportError): importer.inspect_archive(path)

    def test_only_known_shared_awstats_links_are_skipped(self):
        member = tarfile.TarInfo('domains/example.com/awstats/plugins')
        member.type = tarfile.SYMTYPE; member.linkname = '/usr/local/awstats/wwwroot/cgi-bin/plugins'
        self.assertTrue(importer.shared_statistics_link(member))
        importer.safe_member(member)
        for target in ('/etc/shadow', '/usr/local/awstats/wwwroot/cgi-bin/../../../../etc'):
            member.linkname = target
            self.assertFalse(importer.shared_statistics_link(member))
            with self.assertRaises(importer.ImportError): importer.safe_member(member)

    def test_account_local_absolute_links_become_relative(self):
        member = tarfile.TarInfo('domains/example.com/public_html/storage')
        member.type = tarfile.SYMTYPE
        member.linkname = '/home/alice/domains/example.com/storage/app/public'
        importer.safe_member(member, 'alice')
        self.assertEqual(member.linkname, '../storage/app/public')
        for target in ('/home/bob/private', '/home/alice/../../etc/shadow', '/etc/shadow'):
            member.linkname = target
            with self.assertRaises(importer.ImportError): importer.safe_member(member,'alice')

    def test_fifo_rejected(self):
        member = tarfile.TarInfo('pipe'); member.type = tarfile.FIFOTYPE
        with self.assertRaises(importer.ImportError): importer.safe_member(member)

    def test_readonly_source_bridge_rejects_mutations(self):
        self.assertEqual(source.read_command(b'a SELECT "INBOX"\r\n'), b'a EXAMINE "INBOX"\r\n')
        self.assertEqual(source.read_command(b'a UID FETCH 1:* (FLAGS)\r\n'), b'a UID FETCH 1:* (FLAGS)\r\n')
        for command in (b'a UID STORE 1 +FLAGS (\\Deleted)\r\n', b'a EXPUNGE\r\n', b'a DELETE INBOX\r\n', b'a APPEND INBOX {10}\r\n', b'a LIST "" {8}\r\n'):
            with self.subTest(command=command), self.assertRaises(ValueError): source.read_command(command)

    def test_database_credentials_and_grants_are_preserved(self):
        hashed = '*' + 'A' * 40
        plan = {'metadata': {'alice_wp.conf': 'alice_wp=' + urlencode({'passwd': hashed, 'plugin': 'mysql_native_password', 'accesshosts': 'localhost', 'select_priv': 'Y', 'insert_priv': 'Y'})}}
        user = database_users(plan, 'alice_wp')[0]
        self.assertEqual(user['hash'], hashed)
        self.assertEqual(user['privileges'], ['SELECT', 'INSERT'])
        for invalid in ('mysql', 'grommunio', 'name`; DROP DATABASE mysql;'):
            with self.assertRaises(importer.ImportError): database_users(plan, invalid)

    def test_database_collation_is_retained_and_validated(self):
        from directadmin_restore import database_collation
        plan = {'metadata': {'alice_db.conf':'db_collation=latin1_swedish_ci'}}
        with patch('directadmin_restore.sql', return_value='latin1\n'):
            self.assertEqual(database_collation(plan,'alice_db'),('latin1','latin1_swedish_ci'))
            plan['metadata']['alice_db.conf']='db_collation='+urlencode({'DEFAULT_CHARACTER_SET_NAME':'latin1','DEFAULT_COLLATION_NAME':'latin1_swedish_ci','SCHEMA_NAME':'alice_db'})
            self.assertEqual(database_collation(plan,'alice_db'),('latin1','latin1_swedish_ci'))
        with patch('directadmin_restore.sql', return_value=''):
            with self.assertRaises(importer.ImportError): database_collation(plan,'alice_db')
        plan['metadata']['alice_db.conf']='db_collation=latin1; DROP DATABASE mysql'
        with patch('directadmin_restore.sql') as query:
            with self.assertRaises(importer.ImportError): database_collation(plan,'alice_db')
            query.assert_not_called()

    def test_capacity_patch_only_changes_default(self):
        text = '# SPDX-License-Identifier: AGPL-3.0-or-later\ndef _defaultLicense():\n    return GrommunioLicense(cert=None, users=5)\ndef _processCertificate(data):\n    return verify(data)\n'
        output = capacity.patch_capacity(text, 1000)
        self.assertEqual(output, text.replace('users=5', 'users=1000'))
        self.assertEqual(capacity.patch_capacity(output, 1000), output)
        with self.assertRaises(ValueError): capacity.patch_capacity(text.replace('users=5', 'users=config()'), 1000)
        with self.assertRaises(ValueError): capacity.patch_capacity(text, -1)

    def test_emsmdb_configuration_is_idempotent(self):
        text = 'other = yes\nemsmdb_max_obh_per_session=20\n'
        updated = capacity.settings(text)
        self.assertIn('other = yes', updated)
        self.assertEqual(updated.count('emsmdb_max_obh_per_session'), 1)
        self.assertEqual(capacity.settings(updated), updated)

    def test_license_gate_precedes_destination_mutation(self):
        from directadmin_restore import preflight
        fake = type('Panel', (), {})()
        fake.db = lambda: self.connection
        fake.license_status = lambda conn: {'domain_limit': 20, 'domain_count': 0}
        fake.is_root_domain = lambda domain: True
        import sqlite3
        self.connection = sqlite3.connect(':memory:')
        with patch.dict(sys.modules, {'app': fake}), patch('directadmin_restore.run') as command:
            with self.assertRaisesRegex(importer.ImportError, '25 root domains'):
                preflight([{'username': 'alice', 'domains': [{'domain':'example.com'}] * 25}], {}, [], {})
            command.assert_not_called()


if __name__ == '__main__': unittest.main()
