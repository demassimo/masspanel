import base64
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization


class LicensingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        env = {
            "MASSPANEL_LICENSE_STATE": self.temp.name,
            "MASSPANEL_LICENSE_ADMIN_PASSWORD": "test-password",
        }
        with patch.dict(os.environ, env):
            spec = importlib.util.spec_from_file_location("licensing_test_app", Path(__file__).with_name("app.py"))
            self.panel = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.panel)
        self.client = self.panel.app.test_client()
        token = base64.b64encode(b"admin:test-password").decode()
        self.admin = {"Authorization": "Basic " + token}

    def tearDown(self):
        self.temp.cleanup()

    def create_key(self, days=30):
        csrf = self.panel.admin_csrf()
        response = self.client.post("/admin/licenses", data={
            "customer_name": "Example Host", "customer_email": "host@example.com",
            "days": days, "max_installations": 1, "csrf": csrf,
        }, headers=self.admin, follow_redirects=False)
        self.assertEqual(response.status_code, 200)
        return response.headers["X-MassPanel-License-Key"]

    def test_health_admin_and_signed_activation(self):
        self.assertEqual(self.client.get("/health").status_code, 200)
        self.assertEqual(self.client.get("/").status_code, 401)
        key = self.create_key()
        activated = self.client.post("/v1/activate", json={
            "license_key": key, "installation_id": "installation-123456789", "instance_url": "https://panel.example.com",
        })
        self.assertEqual(activated.status_code, 200)
        body = activated.get_json()
        encoded, signature = body["entitlement_token"].split(".")
        public = serialization.load_pem_public_key(self.panel.PUBLIC_KEY_PATH.read_bytes())
        public.verify(base64.urlsafe_b64decode(signature + "=="), encoded.encode())
        self.assertEqual(body["entitlement"]["plan"], "unlimited")
        refreshed = self.client.post("/v1/refresh", json={
            "activation_id": body["activation_id"], "activation_secret": body["activation_secret"],
            "installation_id": "installation-123456789",
        })
        self.assertEqual(refreshed.status_code, 200)

    def test_key_is_bound_to_installation_and_revocation_blocks_refresh(self):
        key = self.create_key()
        first = self.client.post("/v1/activate", json={"license_key": key, "installation_id": "installation-aaaaaaaa"})
        self.assertEqual(first.status_code, 200)
        second = self.client.post("/v1/activate", json={"license_key": key, "installation_id": "installation-bbbbbbbb"})
        self.assertEqual(second.status_code, 409)
        with self.panel.db() as c:
            license_id = c.execute("SELECT id FROM licenses").fetchone()[0]
        self.client.post(f"/admin/licenses/{license_id}/revoke", data={"csrf": self.panel.admin_csrf()}, headers=self.admin)
        body = first.get_json()
        refreshed = self.client.post("/v1/refresh", json={
            "activation_id": body["activation_id"], "activation_secret": body["activation_secret"],
            "installation_id": "installation-aaaaaaaa",
        })
        self.assertEqual(refreshed.status_code, 403)


if __name__ == "__main__":
    unittest.main()
