import base64
import importlib.util
import io
import json
import os
import sqlite3
import tarfile
import tempfile
import unittest
import atexit
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
STATE = Path(tempfile.mkdtemp(prefix="masspanel-tests-"))
atexit.register(lambda: shutil.rmtree(STATE, ignore_errors=True))
os.environ["MASSPANEL_STATE_DIR"] = str(STATE)
os.environ["MASSPANEL_SECRET_KEY"] = "test-secret-key-only"
os.environ["MASSPANEL_HELPER"] = "/does/not/run"
spec = importlib.util.spec_from_file_location("masspanel_test_app", ROOT / "backend" / "app.py")
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


class BackendFeatureTests(unittest.TestCase):
    def setUp(self):
        panel.attempts.clear()
        with panel.db() as c:
            for table in ("wordpress_impersonation_tokens", "mail_impersonation_tokens", "ticket_replies", "support_tickets", "store_orders", "store_products", "account_suspension_domains", "app_installations", "backups", "backup_schedules", "email_accounts", "dns_records", "user_databases", "website_redirects", "mail_domains", "domains", "account_feature_overrides", "accounts", "package_features", "hosting_packages", "audit"):
                c.execute(f"DELETE FROM {table}")
            stamp = panel.now()
            for username, role, system in (("admin", "admin", None), ("alice", "client", "alice"), ("bob", "client", "bob")):
                c.execute("INSERT INTO accounts(username,password_hash,role,system_username,active,created_at) VALUES(?,?,?,?,1,?)", (username, panel.ph.hash("ValidPassword123!"), role, system, stamp))
            c.execute("UPDATE panel_settings SET setting_value='mail.platform.example' WHERE setting_key='mail_hostname'")
            c.execute("UPDATE store_settings SET enabled=0,hostname='',store_name='Hosting Store',currency='USD',contact_email='',template_mode='default',custom_template='',custom_css='',custom_js='',updated_at=? WHERE id=1", (stamp,))
            c.execute("UPDATE license_state SET entitlement_token='',activation_id='',activation_secret='',last_refresh_at='',last_error='' WHERE id=1")
        self.roots = {}
        for owner, domain in (("alice", "alice.example.com"), ("bob", "bob.example.com")):
            root = STATE / owner / "domains" / domain / "public_html"
            root.mkdir(parents=True, exist_ok=True)
            (root / "index.html").write_text("ready", encoding="utf-8")
            self.roots[domain] = root
            with panel.db() as c:
                c.execute("INSERT INTO domains(domain,owner,webroot,suspended,ssl_mode,created_at,created_by) VALUES(?,?,?,0,'disabled',?,?)", (domain, owner, str(root), panel.now(), "admin"))
                c.execute(
                    "INSERT INTO mail_domains(domain,zone_domain,owner,status,created_at,created_by) "
                    "VALUES(?,?,?,'active',?,?)",
                    (domain, domain, owner, panel.now(), "admin"),
                )
        self.helper_calls = []
        self.grommunio_users = {}
        self.cloudflare_connected = False
        self.cloudflare_fail = False
        def fake_helper(payload):
            self.helper_calls.append(payload)
            if payload["operation"] == "list": return {"users": []}
            if payload["operation"] == "service_list": return {"services":[{"name":"nginx","state":"active","sub_state":"running","enabled":True,"critical":True}]}
            if payload["operation"] == "service_action": return {"service":payload["service"],"action":payload["action"],"scheduled":False}
            if payload["operation"] == "wordpress_install":
                return {"version": "6.8.2", "admin_user": payload["admin_user"], "db_name": "mp_test", "db_user": "mpu_test", "ssl_mode": "self"}
            if payload["operation"] == "wordpress_action": return {"version": "6.8.2"}
            if payload["operation"] == "wordpress_sso_install": return {"installed": True}
            if payload["operation"] == "email_hash": return {"password_hash": "{SHA512-CRYPT}$6$test"}
            if payload["operation"] == "grommunio_domain_create": return {"created": True}
            if payload["operation"] == "grommunio_domain_users":
                users = self.grommunio_users.get(payload["domain"], [])
                return {"exists": True, "user_count": len(users), "users": users}
            if payload["operation"] == "cloudflare_status":
                return {"connected": self.cloudflare_connected}
            if payload["operation"] == "cloudflare_connect":
                self.cloudflare_connected = True
                return {"connected": True}
            if payload["operation"] == "cloudflare_sync":
                if self.cloudflare_fail: raise RuntimeError("Cloudflare test failure")
                return {
                    "domain": payload["domain"], "scope": payload.get("scope", payload["domain"]),
                    "zone": payload["domain"], "records_synced": len(payload["records"]),
                    "records_created": 0, "records_updated": len(payload["records"]), "records_deleted": 0,
                }
            if payload["operation"] == "mail_dns_plan":
                domain = payload["domain"]
                hostname = payload["mail_hostname"]
                return {
                    "domain": domain,
                    "selector": "mail",
                    "records": [
                        {"type": "MX", "name": "@", "value": f"10 {hostname}.", "ttl": 300},
                        {"type": "TXT", "name": "@", "value": f"v=spf1 mx a:{hostname} -all", "ttl": 300},
                        {"type": "TXT", "name": "mail._domainkey", "value": "v=DKIM1; k=rsa; p=TEST", "ttl": 300},
                        {"type": "TXT", "name": "_dmarc", "value": f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}", "ttl": 300},
                        {"type": "CNAME", "name": "autodiscover", "value": f"{hostname}.", "ttl": 300},
                        {"type": "CNAME", "name": "autoconfig", "value": f"{hostname}.", "ttl": 300},
                        {"type": "SRV", "name": "_autodiscover._tcp", "value": f"0 0 443 {hostname}.", "ttl": 300},
                    ],
                }
            return {"ok": True}
        panel.helper = fake_helper
        self.original_gethostbyname = panel.socket.gethostbyname
        panel.socket.gethostbyname = lambda hostname: "192.0.2.25"
        self.client = panel.app.test_client()

    def tearDown(self):
        panel.socket.gethostbyname = self.original_gethostbyname

    def login_as(self, username, role, system_username=None):
        with self.client.session_transaction() as s:
            s.clear(); s.update(username=username, role=role, system_username=system_username, csrf="token")

    def test_auth_csrf_and_tenant_boundaries(self):
        self.assertEqual(self.client.get("/api/domains").status_code, 401)
        self.login_as("alice", "client", "alice")
        self.assertEqual(self.client.post("/api/dns", json={}).status_code, 403)
        denied = self.client.get("/api/files?domain=bob.example.com")
        self.assertEqual(denied.status_code, 403)
        visible = self.client.get("/api/domains").get_json()["domains"]
        self.assertEqual([x["domain"] for x in visible], ["alice.example.com"])

    def test_package_feature_defaults_preserve_existing_access(self):
        self.login_as("alice", "client", "alice")
        response = self.client.get("/api/session")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(all(response.get_json()["features"].values()))
        self.assertEqual(self.client.get("/api/files?domain=alice.example.com").status_code, 200)

    def test_package_feature_is_enforced_and_account_override_wins(self):
        with panel.db() as c:
            package_id = c.execute("INSERT INTO hosting_packages(name,created_at,updated_at) VALUES(?,?,?)", ("Restricted",panel.now(),panel.now())).lastrowid
            c.execute("INSERT INTO package_features(package_id,feature_key,enabled) VALUES(?,?,0)", (package_id,"files"))
            c.execute("UPDATE accounts SET package_id=? WHERE username='alice'", (package_id,))
        self.login_as("alice", "client", "alice")
        denied = self.client.get("/api/files?domain=alice.example.com")
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.get_json()["feature"], "files")
        self.login_as("admin", "admin")
        changed = self.client.put("/api/users/alice/features", json={"overrides":{"files":True}}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(changed.status_code, 200)
        self.login_as("alice", "client", "alice")
        self.assertEqual(self.client.get("/api/files?domain=alice.example.com").status_code, 200)

    def test_only_admin_can_change_package_features(self):
        with panel.db() as c:
            package_id = c.execute("INSERT INTO hosting_packages(name,created_at,updated_at) VALUES(?,?,?)", ("Basic",panel.now(),panel.now())).lastrowid
        self.login_as("alice", "client", "alice")
        denied = self.client.put(f"/api/packages/{package_id}/features", json={"features":{"mail":False}}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(denied.status_code, 403)
        self.login_as("admin", "admin")
        allowed = self.client.put(f"/api/packages/{package_id}/features", json={"features":{"mail":False}}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(allowed.status_code, 200)

    def test_impersonation_enforces_target_features_and_custom_unassigns(self):
        with panel.db() as c:
            package_id = c.execute("INSERT INTO hosting_packages(name,created_at,updated_at) VALUES(?,?,?)", ("No mail",panel.now(),panel.now())).lastrowid
            c.execute("INSERT INTO package_features(package_id,feature_key,enabled) VALUES(?,?,0)", (package_id,"mail"))
            c.execute("UPDATE accounts SET package_id=? WHERE username='alice'", (package_id,))
        self.login_as("admin", "admin")
        entered = self.client.post("/api/users/alice/impersonate", headers={"X-CSRF-Token":"token"})
        self.assertEqual(entered.status_code, 200)
        self.assertFalse(entered.get_json()["features"]["mail"])
        self.assertEqual(self.client.get("/api/emails").status_code, 403)
        with self.client.session_transaction() as s: s.clear(); s.update(username="admin",role="admin",system_username=None,csrf="token")
        cleared = self.client.put("/api/users/alice/package", json={"package_id":None}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(cleared.status_code, 200)
        with panel.db() as c: self.assertIsNone(c.execute("SELECT package_id FROM accounts WHERE username='alice'").fetchone()[0])

    def test_website_redirects_are_tenant_scoped_validated_and_synced(self):
        self.login_as("alice", "client", "alice")
        invalid = self.client.post("/api/domains/alice.example.com/redirects", json={"source_path":"/old","target_url":"javascript:alert(1)","status_code":301}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(invalid.status_code, 400)
        created = self.client.post("/api/domains/alice.example.com/redirects", json={"source_path":"/old","target_url":"https://example.net/new","status_code":308}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(self.client.get("/api/domains/alice.example.com/redirects").get_json()["redirects"][0]["status_code"], 308)
        self.assertEqual(self.client.get("/api/domains/bob.example.com/redirects").status_code, 404)
        sync = [call for call in self.helper_calls if call.get("operation") == "website_rules_sync"][-1]
        self.assertEqual(sync["redirects"][0]["source_path"], "/old")
        deleted = self.client.delete(f"/api/domains/alice.example.com/redirects/{created.get_json()['id']}", headers={"X-CSRF-Token":"token"})
        self.assertEqual(deleted.status_code, 200)

    def test_website_redirect_rolls_back_when_nginx_apply_fails(self):
        original_helper = panel.helper
        def failing_helper(payload):
            if payload.get("operation") == "website_rules_sync": raise RuntimeError("nginx rejected test rule")
            return original_helper(payload)
        panel.helper = failing_helper
        try:
            self.login_as("alice", "client", "alice")
            failed = self.client.post("/api/domains/alice.example.com/redirects", json={"source_path":"/will-rollback","target_url":"https://example.net/","status_code":301}, headers={"X-CSRF-Token":"token"})
            self.assertEqual(failed.status_code, 400)
            with panel.db() as c: self.assertFalse(c.execute("SELECT 1 FROM website_redirects WHERE source_path='/will-rollback'").fetchone())
            for source in ("/bad?query=1", "/bad#fragment", "/bad\\path"):
                denied = self.client.post("/api/domains/alice.example.com/redirects", json={"source_path":source,"target_url":"https://example.net/","status_code":301}, headers={"X-CSRF-Token":"token"})
                self.assertEqual(denied.status_code, 400)
        finally:
            panel.helper = original_helper

    def test_application_catalog_and_woocommerce_preset_install(self):
        self.login_as("alice", "client", "alice")
        catalog = self.client.get("/api/apps").get_json()["catalog"]
        self.assertIn("woocommerce", {item["slug"] for item in catalog})
        response = self.client.post("/api/apps/install/woocommerce", json={"domain":"alice.example.com","title":"Alice Store","admin_user":"aliceadmin","admin_email":"alice@example.com","admin_password":"StrongPassword123!"}, headers={"X-CSRF-Token":"token"})
        self.assertEqual(response.status_code, 201)
        install_call = [call for call in self.helper_calls if call.get("operation") == "wordpress_install"][-1]
        self.assertEqual(install_call["application_slug"], "woocommerce")
        with panel.db() as c: self.assertEqual(c.execute("SELECT application_slug FROM app_installations WHERE domain='alice.example.com'").fetchone()[0], "woocommerce")
        inventory = self.client.get("/api/databases?domain=alice.example.com").get_json()["databases"]
        managed = [item for item in inventory if item["engine"] == "mariadb"]
        self.assertEqual(managed[0]["name"], "mp_test")
        self.assertTrue(managed[0]["managed_application"])
        self.assertNotIn("path", managed[0])

    def test_application_install_reservation_releases_on_helper_failure(self):
        self.login_as("alice", "client", "alice")
        self.assertEqual(self.client.post("/api/apps/install/not-real", json={}, headers={"X-CSRF-Token":"token"}).status_code, 404)
        original_helper = panel.helper
        panel.helper = lambda payload: (_ for _ in ()).throw(RuntimeError("installer failed")) if payload.get("operation") == "wordpress_install" else original_helper(payload)
        try:
            failed = self.client.post("/api/apps/install/elementor", json={"domain":"alice.example.com","title":"Alice","admin_user":"aliceadmin","admin_email":"alice@example.com","admin_password":"StrongPassword123!"}, headers={"X-CSRF-Token":"token"})
            self.assertEqual(failed.status_code, 400)
            with panel.db() as c: self.assertFalse(c.execute("SELECT 1 FROM app_installations WHERE domain='alice.example.com'").fetchone())
        finally: panel.helper = original_helper

    def test_community_limit_blocks_only_new_root_domains(self):
        with panel.db() as c:
            c.execute("UPDATE accounts SET domain_limit=100 WHERE username='alice'")
            for index in range(18):
                domain = f"community-{index}.example"
                root = STATE / "alice" / "domains" / domain / "public_html"
                root.mkdir(parents=True, exist_ok=True)
                c.execute(
                    "INSERT INTO domains(domain,owner,webroot,suspended,ssl_mode,created_at,created_by) VALUES(?,?,?,0,'disabled',?,?)",
                    (domain, "alice", str(root), panel.now(), "admin"),
                )
            c.execute(
                "INSERT INTO mail_domains(domain,zone_domain,owner,status,created_at,created_by) VALUES(?,?,?,'active',?,?)",
                ("mail.community-0.example", "community-0.example", "alice", panel.now(), "admin"),
            )
        status = panel.license_status()
        self.assertEqual(status["edition"], "community")
        self.assertEqual(status["domain_count"], 20)
        self.assertFalse(status["can_add_domain"])
        self.login_as("admin", "admin")
        denied = self.client.post(
            "/api/domains",
            json={"domain": "twenty-one.example", "owner": "alice"},
            headers={"X-CSRF-Token": "token"},
        )
        self.assertEqual(denied.status_code, 402)
        self.assertIn("existing services remain online", denied.get_json()["error"])
        with panel.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 20)

    def test_signed_unlimited_entitlement_and_safe_expiry(self):
        private = Ed25519PrivateKey.generate()
        public_path = STATE / "qa-license-public.pem"
        public_path.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        original_public_key = panel.LICENSE_PUBLIC_KEY
        panel.LICENSE_PUBLIC_KEY = public_path
        try:
            with panel.db() as c:
                installation_id = c.execute("SELECT installation_id FROM license_state WHERE id=1").fetchone()[0]
                for index in range(18):
                    domain = f"unlimited-{index}.example"
                    c.execute(
                        "INSERT INTO domains(domain,owner,webroot,suspended,ssl_mode,created_at,created_by) VALUES(?,?,?,0,'disabled',?,?)",
                        (domain, "alice", str(STATE / domain), panel.now(), "admin"),
                    )

            def token(expires, grace):
                payload = {
                    "v": 1, "issuer": "MassPanel Licensing", "plan": "unlimited",
                    "domain_limit": None, "installation_id": installation_id, "license_id": 42,
                    "issued_at": expires.isoformat(),
                    "subscription_expires_at": expires.isoformat().replace("+00:00", "Z"),
                    "grace_until": grace.isoformat().replace("+00:00", "Z"),
                }
                encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
                signature = base64.urlsafe_b64encode(private.sign(encoded.encode())).rstrip(b"=").decode()
                return encoded + "." + signature

            current = datetime.now(timezone.utc)
            with panel.db() as c:
                c.execute("UPDATE license_state SET entitlement_token=? WHERE id=1", (token(current + timedelta(days=30), current + timedelta(days=44)),))
            active = panel.license_status()
            self.assertEqual(active["edition"], "unlimited")
            self.assertIsNone(active["domain_limit"])
            self.assertTrue(active["can_add_domain"])

            with panel.db() as c:
                c.execute("UPDATE license_state SET entitlement_token=? WHERE id=1", (token(current - timedelta(days=30), current - timedelta(days=1)),))
            expired = panel.license_status()
            self.assertEqual(expired["edition"], "community")
            self.assertEqual(expired["status"], "expired")
            self.assertFalse(expired["can_add_domain"])
            with panel.db() as c:
                self.assertEqual(c.execute("SELECT COUNT(*) FROM domains").fetchone()[0], 20)
        finally:
            panel.LICENSE_PUBLIC_KEY = original_public_key

    def test_dns_email_ticket_file_database_and_backup_crud(self):
        self.login_as("alice", "client", "alice")
        headers = {"X-CSRF-Token": "token"}
        dns = self.client.post("/api/dns", json={"domain": "alice.example.com", "type": "A", "name": "@", "value": "192.0.2.10", "ttl": 300}, headers=headers)
        self.assertEqual(dns.status_code, 201)
        email = self.client.post("/api/emails", json={"domain": "alice.example.com", "localpart": "info", "quota_mb": 500, "password": "MailboxPassword123!", "confirm_password": "MailboxPassword123!"}, headers=headers)
        self.assertEqual(email.status_code, 201)
        ticket = self.client.post("/api/tickets", json={"domain": "alice.example.com", "subject": "Help", "body": "Please help", "priority": "normal"}, headers=headers)
        self.assertEqual(ticket.status_code, 201)
        written = self.client.post("/api/files", json={"domain": "alice.example.com", "path": "hello.txt", "action": "create_file", "content": "hello"}, headers=headers)
        self.assertEqual(written.status_code, 200)
        content = self.client.get("/api/files/content?domain=alice.example.com&path=hello.txt").get_json()
        self.assertEqual(content["content"], "hello")
        database = self.client.post("/api/databases", json={"domain": "alice.example.com", "name": "site_db"}, headers=headers)
        self.assertEqual(database.status_code, 201)
        query = self.client.post(f"/api/databases/{database.get_json()['id']}/query", json={"sql": "SELECT 1 AS ok"}, headers=headers)
        self.assertEqual(query.get_json()["rows"], [{"ok": 1}])
        backup = self.client.post("/api/backups", json={"domain": "alice.example.com"}, headers=headers)
        self.assertEqual(backup.status_code, 200)
        response = self.client.get(f"/api/backups/{backup.get_json()['id']}/download", buffered=True)
        self.assertEqual(response.status_code, 200)
        response.close()

    def test_service_controls_and_backup_schedules(self):
        self.login_as("admin", "admin")
        services = self.client.get("/api/tools/services")
        self.assertEqual(services.status_code, 200)
        self.assertEqual(services.get_json()["services"][0]["name"], "nginx")
        restart = self.client.post("/api/tools/services/nginx/restart", headers={"X-CSRF-Token":"token"})
        self.assertEqual(restart.status_code, 200)

        created = self.client.post("/api/backup-schedules", json={
            "domain":"alice.example.com", "frequency":"weekly", "hour":3, "minute":15,
            "weekday":2, "monthday":1, "retention":2, "destination_type":"sftp",
            "remote_path":"MassPanel/nightly", "destination_config":{"host":"backup.example.com","port":22,"username":"alice","password":"Secret123!"},
        }, headers={"X-CSRF-Token":"token"})
        self.assertEqual(created.status_code, 201)
        schedule_id = created.get_json()["id"]
        listed = self.client.get("/api/backup-schedules").get_json()["schedules"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["frequency"], "weekly")
        self.assertEqual(listed[0]["destination_type"], "sftp")
        self.assertNotIn("destination_config", listed[0])
        uploaded = []
        original_rclone = panel._rclone_backup
        panel._rclone_backup = lambda row, filename: uploaded.append((row["destination_type"], filename))
        try:
            run = self.client.post(f"/api/backup-schedules/{schedule_id}/run", headers={"X-CSRF-Token":"token"})
        finally:
            panel._rclone_backup = original_rclone
        self.assertEqual(run.status_code, 200)
        self.assertEqual(uploaded[0][0], "sftp")
        self.assertTrue(Path(self.client.get("/api/backups").get_json()["backups"][0]["filename"]).is_file())
        toggled = self.client.post(f"/api/backup-schedules/{schedule_id}/toggle", headers={"X-CSRF-Token":"token"})
        self.assertEqual(toggled.status_code, 200)
        deleted = self.client.delete(f"/api/backup-schedules/{schedule_id}", headers={"X-CSRF-Token":"token"})
        self.assertEqual(deleted.status_code, 200)

    def test_forwarding_accepts_normal_addresses_and_rejects_unsafe_input(self):
        self.login_as("alice", "client", "alice")
        headers = {"X-CSRF-Token": "token"}
        valid = self.client.post(
            "/api/emails",
            json={
                "domain": "alice.example.com",
                "localpart": "sales",
                "quota_mb": 0,
                "destination": "team+sales@example.net",
            },
            headers=headers,
        )
        self.assertEqual(valid.status_code, 201)
        self.assertEqual(self.helper_calls[-1]["destination"], "team+sales@example.net")

        unsafe = self.client.post(
            "/api/emails",
            json={
                "domain": "alice.example.com",
                "localpart": "unsafe",
                "quota_mb": 0,
                "destination": "attacker'--@example.net",
            },
            headers=headers,
        )
        self.assertEqual(unsafe.status_code, 400)
        self.assertIn("destination", unsafe.get_json()["error"].lower())

    def test_cloudflare_auto_syncs_dns_and_preserves_local_changes_on_failure(self):
        self.login_as("alice", "client", "alice")
        headers = {"X-CSRF-Token": "token"}
        self.cloudflare_connected = True
        created = self.client.post(
            "/api/dns",
            json={"domain":"alice.example.com", "type":"TXT", "name":"verify", "value":"first", "ttl":300},
            headers=headers,
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.get_json()["cloudflare"]["status"], "synced")
        synced = [call for call in self.helper_calls if call["operation"] == "cloudflare_sync"][-1]
        self.assertTrue(synced["prune"])
        self.assertTrue(synced["ensure_apex"])
        self.assertEqual(synced["scope"], "alice.example.com")
        self.assertEqual(synced["records"][0]["name"], "verify")

        self.cloudflare_fail = True
        failed = self.client.post(
            "/api/dns",
            json={"domain":"alice.example.com", "type":"TXT", "name":"still-saved", "value":"yes", "ttl":300},
            headers=headers,
        )
        self.assertEqual(failed.status_code, 201)
        self.assertEqual(failed.get_json()["cloudflare"]["status"], "failed")
        with panel.db() as c:
            stored = c.execute(
                "SELECT value FROM dns_records WHERE domain=? AND name=?",
                ("alice.example.com", "still-saved"),
            ).fetchone()
        self.assertEqual(stored["value"], "yes")

    def test_mail_only_subdomain_mailbox_dns_mapping_and_tenant_guards(self):
        headers = {"X-CSRF-Token": "token"}
        mail_domain = "staff.alice.example.com"

        self.login_as("alice", "client", "alice")
        created = self.client.post("/api/mail/domains", json={"domain": mail_domain}, headers=headers)
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.get_json()["dns_parent"], "alice.example.com")
        with panel.db() as c:
            stored_domain = c.execute(
                "SELECT domain,zone_domain,owner,status,grommunio_managed FROM mail_domains WHERE domain=?",
                (mail_domain,),
            ).fetchone()
        self.assertEqual(dict(stored_domain), {
            "domain": mail_domain,
            "zone_domain": "alice.example.com",
            "owner": "alice",
            "status": "active",
            "grommunio_managed": 1,
        })

        self.grommunio_users[mail_domain] = [f"outside@{mail_domain}"]
        external_guard = self.client.delete(f"/api/mail/domains/{mail_domain}", headers=headers)
        self.assertEqual(external_guard.status_code, 409)
        self.assertIn("Grommunio users", external_guard.get_json()["error"])
        self.grommunio_users[mail_domain] = []

        self.login_as("bob", "client", "bob")
        denied_create = self.client.post(
            "/api/mail/domains",
            json={"domain": "other.alice.example.com"},
            headers=headers,
        )
        self.assertEqual(denied_create.status_code, 400)
        denied_mailbox = self.client.post(
            "/api/emails",
            json={
                "domain": mail_domain,
                "localpart": "intruder",
                "quota_mb": 100,
                "password": "MailboxPassword123!",
                "confirm_password": "MailboxPassword123!",
            },
            headers=headers,
        )
        self.assertEqual(denied_mailbox.status_code, 403)
        denied_dns = self.client.post("/api/dns/mail-plan", json={"domain": mail_domain}, headers=headers)
        self.assertEqual(denied_dns.status_code, 403)

        self.login_as("alice", "client", "alice")
        mailbox = self.client.post(
            "/api/emails",
            json={
                "domain": mail_domain,
                "localpart": "info",
                "quota_mb": 500,
                "password": "MailboxPassword123!",
                "confirm_password": "MailboxPassword123!",
            },
            headers=headers,
        )
        self.assertEqual(mailbox.status_code, 201)
        with panel.db() as c:
            stored_mailbox = c.execute(
                "SELECT full_email,domain,mail_domain,localpart FROM email_accounts WHERE id=?",
                (mailbox.get_json()["id"],),
            ).fetchone()
        self.assertEqual(dict(stored_mailbox), {
            "full_email": f"info@{mail_domain}",
            "domain": "alice.example.com",
            "mail_domain": mail_domain,
            "localpart": "info",
        })

        generated = self.client.post("/api/dns/mail-plan", json={"domain": mail_domain}, headers=headers)
        self.assertEqual(generated.status_code, 200)
        self.assertEqual(
            [record["zone_name"] for record in generated.get_json()["records"]],
            [
                "staff",
                "staff",
                "mail._domainkey.staff",
                "_dmarc.staff",
                "autodiscover.staff",
                "autoconfig.staff",
                "_autodiscover._tcp.staff",
            ],
        )
        with panel.db() as c:
            records = [dict(row) for row in c.execute(
                "SELECT domain,mail_domain,type,name,value FROM dns_records WHERE mail_domain=? ORDER BY id",
                (mail_domain,),
            ).fetchall()]
        self.assertEqual(len(records), 7)
        self.assertTrue(all(record["domain"] == "alice.example.com" for record in records))
        self.assertTrue(all(record["mail_domain"] == mail_domain for record in records))
        self.assertEqual(records[0]["name"], "staff")
        self.assertEqual(records[0]["value"], "10 mail.platform.example.")

        self.login_as("admin", "admin")
        settings = panel.product_settings()
        settings["mail_hostname"] = "mail.changed.example"
        settings["show_powered_by"] = settings.get("show_powered_by") == "1"
        changed = self.client.put("/api/settings", json=settings, headers=headers)
        self.assertEqual(changed.status_code, 200)
        self.assertTrue(changed.get_json()["mail_hostname_changed"])
        self.assertGreaterEqual(changed.get_json()["mail_dns_updated"], 4)
        with panel.db() as c:
            changed_values = {
                (row["type"], row["name"]): row["value"]
                for row in c.execute(
                    "SELECT type,name,value FROM dns_records WHERE mail_domain=?",
                    (mail_domain,),
                ).fetchall()
            }
        self.assertEqual(changed_values[("MX", "staff")], "10 mail.changed.example.")
        self.assertEqual(changed_values[("CNAME", "autodiscover.staff")], "mail.changed.example.")

        guarded = self.client.delete(f"/api/mail/domains/{mail_domain}", headers=headers)
        self.assertEqual(guarded.status_code, 409)
        self.assertIn("mailboxes", guarded.get_json()["error"])

    def test_ssl_suspension_lock_and_delete_guards_change_real_control_state(self):
        self.login_as("alice", "client", "alice")
        headers = {"X-CSRF-Token": "token"}
        ssl = self.client.post("/api/domains/alice.example.com/ssl", json={"mode": "self"}, headers=headers)
        self.assertEqual(ssl.status_code, 200)
        self.assertEqual(self.helper_calls[-1]["operation"], "domain_config")
        self.login_as("admin", "admin")
        suspended = self.client.post("/api/domains/alice.example.com/suspend", headers=headers)
        self.assertEqual(suspended.status_code, 200)
        self.assertTrue(self.helper_calls[-1]["suspended"])
        self.assertEqual(self.client.post("/api/users/alice/lock", headers=headers).status_code, 200)
        with panel.db() as c:
            self.assertEqual(c.execute("SELECT active FROM accounts WHERE username='alice'").fetchone()["active"], 0)
        self.assertEqual(self.client.delete("/api/users/alice", headers=headers).status_code, 409)

    def test_account_suspension_blocks_web_and_smtp_but_preserves_incoming_mail(self):
        with panel.db() as c:
            c.execute("INSERT INTO email_accounts(full_email,domain,mail_domain,localpart,destination,quota_mb,created_at,created_by) VALUES(?,?,?,?,NULL,?,?,?)", ("bob@bob.example.com","bob.example.com","bob.example.com","bob",500,panel.now(),"admin"))
        self.login_as("admin", "admin")
        headers = {"X-CSRF-Token":"token"}
        locked = self.client.post("/api/users/bob/lock", headers=headers)
        self.assertEqual(locked.status_code, 200)
        self.assertTrue(locked.get_json()["incoming_mail"])
        self.assertEqual(locked.get_json()["mailboxes_restricted"], 1)
        mail_call = next(call for call in self.helper_calls if call["operation"] == "grommunio_account_access")
        self.assertFalse(mail_call["enabled"])
        self.assertEqual(mail_call["addresses"], ["bob@bob.example.com"])
        with panel.db() as c:
            self.assertEqual(c.execute("SELECT suspended FROM domains WHERE domain='bob.example.com'").fetchone()["suspended"], 1)
        unlocked = self.client.post("/api/users/bob/unlock", headers=headers)
        self.assertEqual(unlocked.status_code, 200)
        with panel.db() as c:
            self.assertEqual(c.execute("SELECT suspended FROM domains WHERE domain='bob.example.com'").fetchone()["suspended"], 0)
        self.assertTrue([call for call in self.helper_calls if call["operation"] == "grommunio_account_access"][-1]["enabled"])

    def test_wordpress_install_and_management_are_tenant_scoped(self):
        self.login_as("alice", "client", "alice")
        headers = {"X-CSRF-Token": "token"}
        result = self.client.post("/api/apps/wordpress", json={"domain": "alice.example.com", "title": "Alice", "admin_user": "aliceadmin", "admin_email": "alice@example.com", "admin_password": "LongPassword123!"}, headers=headers)
        self.assertEqual(result.status_code, 201)
        with panel.db() as c:
            self.assertEqual(c.execute("SELECT ssl_mode FROM domains WHERE domain='alice.example.com'").fetchone()["ssl_mode"], "self")
        self.login_as("bob", "client", "bob")
        denied = self.client.post(f"/api/apps/{result.get_json()['id']}/action", json={"action": "update"}, headers=headers)
        self.assertEqual(denied.status_code, 404)

    def test_wordpress_impersonation_is_owner_scoped_bound_and_one_time(self):
        self.login_as("alice", "client", "alice")
        headers = {"X-CSRF-Token": "token"}
        installed = self.client.post("/api/apps/wordpress", json={"domain": "alice.example.com", "title": "Alice", "admin_user": "aliceadmin", "admin_email": "alice@example.com", "admin_password": "LongPassword123!"}, headers=headers)
        app_id = installed.get_json()["id"]
        issued = self.client.post(f"/api/apps/{app_id}/impersonate", headers=headers)
        self.assertEqual(issued.status_code, 200)
        token = issued.get_json()["launch_url"].split("token=", 1)[1]
        launch = self.client.get(issued.get_json()["launch_url"])
        self.assertEqual(launch.status_code, 200)
        self.assertIn(b"Opening WordPress securely", launch.data)
        self.login_as("bob", "client", "bob")
        self.assertEqual(self.client.post(f"/api/apps/{app_id}/impersonate", headers=headers).status_code, 404)
        self.assertEqual(self.client.post("/api/apps/impersonation/exchange", json={"token": token, "domain": "wrong.example.com"}, base_url="http://127.0.0.1:8100", environ_base={"REMOTE_ADDR":"127.0.0.1"}).status_code, 410)
        opened = self.client.post("/api/apps/impersonation/exchange", json={"token": token, "domain": "alice.example.com"}, base_url="http://127.0.0.1:8100", environ_base={"REMOTE_ADDR":"127.0.0.1"})
        self.assertEqual(opened.status_code, 200)
        self.assertEqual(opened.get_json()["username"], "aliceadmin")
        self.assertEqual(self.client.post("/api/apps/impersonation/exchange", json={"token": token, "domain": "alice.example.com"}, base_url="http://127.0.0.1:8100", environ_base={"REMOTE_ADDR":"127.0.0.1"}).status_code, 410)

    def test_custom_store_exposes_enabled_package_data_to_jinja_js_and_json(self):
        with panel.db() as c:
            package_id = c.execute(
                "INSERT INTO hosting_packages(name,domain_limit,disk_mb,bandwidth_mb,database_limit,mailbox_limit,cron_limit,backup_limit,allow_php,allow_ssh,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                ("Starter", 3, 2048, 10000, 4, 10, 2, 2, 1, 0, panel.now(), panel.now()),
            ).lastrowid
            c.execute(
                "INSERT INTO store_products(package_id,display_name,description,monthly_price_cents,yearly_price_cents,enabled,featured,sort_order) VALUES(?,?,?,?,?,1,1,0)",
                (package_id, "Starter Web", "For a small site", 599, 5990),
            )
        self.login_as("admin", "admin")
        saved = self.client.put("/api/store/settings", headers={"X-CSRF-Token":"token"}, json={
            "enabled": True, "hostname": "shop.example.com", "store_name": "Example Hosting", "currency": "USD",
            "contact_email": "sales@example.com", "template_mode": "custom",
            "custom_template": "<!doctype html><html><head></head><body>{% for product in packages %}<b>{{ product.display_name }}</b>{% endfor %}</body></html>",
            "custom_css": "body{color:navy}", "custom_js": "document.body.dataset.packages=MassPanelStore.packages.length;",
        })
        self.assertEqual(saved.status_code, 200)
        page = self.client.get("/store/", headers={"Host":"shop.example.com"})
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Starter Web", page.data)
        self.assertIn(b"masspanel-custom-css", page.data)
        self.assertIn(b"masspanel-custom-js", page.data)
        self.assertIn(b"window.MassPanelStore", page.data)
        data = self.client.get("/store/data.json", headers={"Host":"shop.example.com"})
        self.assertEqual(data.status_code, 200)
        self.assertEqual(data.get_json()["packages"][0]["monthly_price"], "5.99")
        self.assertEqual(data.get_json()["order_url"], "/order")

    def test_restore_rejects_archive_path_traversal(self):
        malicious = STATE / "malicious.tar.gz"
        with tarfile.open(malicious, "w:gz") as archive:
            info = tarfile.TarInfo("../../escape.txt"); data = b"escape"; info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        with panel.db() as c:
            cursor = c.execute("INSERT INTO backups(domain,filename,size_bytes,created_by,created_at) VALUES(?,?,?,?,?)", ("alice.example.com", str(malicious), malicious.stat().st_size, "admin", panel.now()))
            backup_id = cursor.lastrowid
        self.login_as("admin", "admin")
        response = self.client.post(f"/api/backups/{backup_id}/restore", headers={"X-CSRF-Token": "token"})
        self.assertEqual(response.status_code, 500)
        self.assertFalse((STATE.parent / "escape.txt").exists())


if __name__ == "__main__":
    unittest.main()
