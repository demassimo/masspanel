import base64
import hmac
import hashlib
import html
import ipaddress
import json
import os
import re
import secrets
import configparser
import tempfile
import shutil
import socket
import ssl
import sqlite3
import subprocess
import tarfile
import time
from email import policy
from email.parser import BytesParser
from collections import defaultdict, deque
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import psutil
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request, session, send_file, Response, make_response, redirect
from werkzeug.middleware.proxy_fix import ProxyFix
from jinja2 import BaseLoader, StrictUndefined, TemplateError, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

BASE = Path(os.environ.get("MASSPANEL_STATE_DIR", "/var/lib/masspanel"))
DB_PATH = BASE / "masspanel.db"
BACKUP_DIR = BASE / "backups"
QUARANTINE_DIR = BASE / "mail-quarantine"
RSPAMD_EXPORT_SECRET = Path(os.environ.get("MASSPANEL_RSPAMD_EXPORT_SECRET", "/etc/masspanel/rspamd-export-secret"))
HELPER = os.environ.get("MASSPANEL_HELPER", "/usr/local/libexec/masspanel-helper")
LICENSE_SERVER_URL = os.environ.get("MASSPANEL_LICENSE_SERVER_URL", "https://masspanel.masscomputing.co.za").rstrip("/")
LICENSE_PUBLIC_KEY = Path(os.environ.get("MASSPANEL_LICENSE_PUBLIC_KEY", Path(__file__).with_name("license_public.pem")))
COMMUNITY_DOMAIN_LIMIT = 20

USERNAME = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DNS_RECORD_NAME = re.compile(r"^(?:\*|@|_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\._?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
EMAIL_LOCALPART = re.compile(r"^[a-z0-9._%+-]{1,64}$")
CRON_FIELD = re.compile(r"^[0-9*/?,\-]+$")
DB_NAME = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
DNS_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SPF", "SRV"}
SHELLS = {"/bin/bash", "/bin/sh", "/usr/sbin/nologin"}
SSL_MODES = {"disabled", "self", "letsencrypt"}
TICKET_PRIORITIES = {"low", "normal", "high", "urgent"}
TICKET_STATUS = {"open", "in_progress", "closed"}
PUBLIC_SUFFIX_FILE = Path("/usr/share/publicsuffix/public_suffix_list.dat")
_PSL_CACHE = None

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
attempts = defaultdict(deque)

app = Flask(__name__)
# nginx is the only process able to reach this loopback-bound application.
# Trust its single forwarded hop so rate limits and security logs use the client.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ["MASSPANEL_SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_NAME="masspanel_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=67108864,
)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def is_root_domain(domain):
    """Return true only for a registrable apex, using the system Public Suffix List."""
    global _PSL_CACHE
    labels = str(domain).lower().strip(".").split(".")
    if len(labels) < 2: return False
    if _PSL_CACHE is None:
        exact, wildcard, exceptions = set(), set(), set()
        try: lines = PUBLIC_SUFFIX_FILE.read_text(encoding="utf-8").splitlines()
        except OSError: lines = ["com", "net", "org", "co.za", "org.za", "net.za", "co.uk", "com.au"]
        for raw in lines:
            rule = raw.strip().lower()
            if not rule or rule.startswith("//"): continue
            if rule.startswith("!"): exceptions.add(rule[1:])
            elif rule.startswith("*."): wildcard.add(rule[2:])
            else: exact.add(rule)
        _PSL_CACHE = exact, wildcard, exceptions
    exact, wildcard, exceptions = _PSL_CACHE
    suffix_size = 1
    for offset in range(len(labels)):
        candidate = ".".join(labels[offset:])
        if candidate in exceptions:
            suffix_size = len(labels) - offset - 1
            break
        if candidate in exact: suffix_size = max(suffix_size, len(labels) - offset)
        if offset and candidate in wildcard: suffix_size = max(suffix_size, len(labels) - offset + 1)
    return len(labels) == suffix_size + 1


def registrable_domain(hostname):
    """Return the registrable apex containing a service hostname."""
    labels = str(hostname or "").lower().strip(".").split(".")
    for offset in range(max(0, len(labels) - 1)):
        candidate = ".".join(labels[offset:])
        if is_root_domain(candidate):
            return candidate
    return ""


def dns_service_nameservers(settings=None):
    settings = settings or product_settings()
    panel_hostname = (urlparse(settings.get("public_url", "")).hostname or "").lower()
    apex = registrable_domain(panel_hostname)
    return (f"ns1.{apex}", f"ns2.{apex}") if apex else ("", "")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _table_has_col(c, table, column):
    cols = c.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in cols)


def _ensure_table(conn):
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins(
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts(
              username TEXT PRIMARY KEY,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('admin','client')),
              system_username TEXT,
              active INTEGER NOT NULL DEFAULT 1,
              domain_limit INTEGER NOT NULL DEFAULT 10,
              disk_limit_mb INTEGER NOT NULL DEFAULT 10240,
              allow_domain_creation INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domains(
              domain TEXT PRIMARY KEY,
              owner TEXT NOT NULL,
              webroot TEXT NOT NULL,
              suspended INTEGER NOT NULL DEFAULT 0,
              ssl_mode TEXT NOT NULL DEFAULT 'disabled',
              created_at TEXT NOT NULL,
              created_by TEXT NOT NULL DEFAULT 'admin'
            );

            CREATE TABLE IF NOT EXISTS mail_domains(
              domain TEXT PRIMARY KEY,
              zone_domain TEXT NOT NULL,
              owner TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'active',
              grommunio_managed INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              created_by TEXT NOT NULL,
              FOREIGN KEY(zone_domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              created_at TEXT NOT NULL,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              target TEXT,
              outcome TEXT NOT NULL,
              remote_addr TEXT
            );

            CREATE TABLE IF NOT EXISTS dns_records(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL,
              type TEXT NOT NULL CHECK(type IN ('A','AAAA','CNAME','MX','TXT','NS','SPF','SRV')),
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              ttl INTEGER NOT NULL DEFAULT 3600,
              created_at TEXT NOT NULL,
              created_by TEXT NOT NULL,
              mail_domain TEXT,
              forward_copy TEXT NOT NULL DEFAULT '',
              allow_smtp INTEGER NOT NULL DEFAULT 1,
              allow_imap INTEGER NOT NULL DEFAULT 1,
              allow_web INTEGER NOT NULL DEFAULT 1,
              allow_dav INTEGER NOT NULL DEFAULT 1,
              allow_eas INTEGER NOT NULL DEFAULT 1,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS email_accounts(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              full_email TEXT NOT NULL UNIQUE,
              domain TEXT NOT NULL,
              localpart TEXT NOT NULL,
              destination TEXT,
              quota_mb INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'active',
              created_at TEXT NOT NULL,
              created_by TEXT NOT NULL,
              mail_domain TEXT,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS support_tickets(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT,
              requester TEXT NOT NULL,
              subject TEXT NOT NULL,
              body TEXT NOT NULL,
              priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('low','normal','high','urgent')),
              status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','closed')),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ticket_replies(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ticket_id INTEGER NOT NULL,
              author TEXT NOT NULL,
              message TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(ticket_id) REFERENCES support_tickets(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS backups(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL,
              filename TEXT NOT NULL UNIQUE,
              size_bytes INTEGER NOT NULL DEFAULT 0,
              created_by TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_databases(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              owner TEXT NOT NULL,
              domain TEXT NOT NULL,
              name TEXT NOT NULL,
              path TEXT NOT NULL UNIQUE,
              created_by TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS panel_settings(
              setting_key TEXT PRIMARY KEY,
              setting_value TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS license_state(
              id INTEGER PRIMARY KEY CHECK(id=1),
              installation_id TEXT NOT NULL,
              entitlement_token TEXT NOT NULL DEFAULT '',
              activation_id TEXT NOT NULL DEFAULT '',
              activation_secret TEXT NOT NULL DEFAULT '',
              last_refresh_at TEXT NOT NULL DEFAULT '',
              last_error TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS app_installations(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL UNIQUE,
              owner TEXT NOT NULL,
              app_type TEXT NOT NULL CHECK(app_type IN ('wordpress')),
              version TEXT NOT NULL,
              admin_user TEXT NOT NULL,
              db_name TEXT NOT NULL,
              db_user TEXT NOT NULL,
              maintenance INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'active',
              installed_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              installed_by TEXT NOT NULL,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scheduled_tasks(
              id TEXT PRIMARY KEY,
              owner TEXT NOT NULL,
              domain TEXT,
              name TEXT NOT NULL,
              schedule TEXT NOT NULL,
              command TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS backup_schedules(
              id TEXT PRIMARY KEY,
              owner TEXT NOT NULL,
              domain TEXT NOT NULL,
              frequency TEXT NOT NULL CHECK(frequency IN ('daily','weekly','monthly')),
              hour INTEGER NOT NULL CHECK(hour BETWEEN 0 AND 23),
              minute INTEGER NOT NULL CHECK(minute BETWEEN 0 AND 59),
              weekday INTEGER NOT NULL DEFAULT 0 CHECK(weekday BETWEEN 0 AND 6),
              monthday INTEGER NOT NULL DEFAULT 1 CHECK(monthday BETWEEN 1 AND 28),
              retention INTEGER NOT NULL DEFAULT 3 CHECK(retention BETWEEN 1 AND 30),
              destination_type TEXT NOT NULL DEFAULT 'local',
              destination_config TEXT NOT NULL DEFAULT '',
              remote_path TEXT NOT NULL DEFAULT 'MassPanel',
              enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
              last_run_at TEXT NOT NULL DEFAULT '',
              last_status TEXT NOT NULL DEFAULT 'never',
              last_error TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS website_redirects(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              domain TEXT NOT NULL,
              source_path TEXT NOT NULL,
              target_url TEXT NOT NULL,
              status_code INTEGER NOT NULL DEFAULT 301 CHECK(status_code IN (301,302,307,308)),
              created_at TEXT NOT NULL,
              created_by TEXT NOT NULL,
              UNIQUE(domain,source_path),
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS website_security_settings(
              domain TEXT PRIMARY KEY,
              hotlink_enabled INTEGER NOT NULL DEFAULT 0 CHECK(hotlink_enabled IN (0,1)),
              hotlink_extensions TEXT NOT NULL DEFAULT 'jpg,jpeg,png,gif,webp,svg,mp4',
              allowed_referrers TEXT NOT NULL DEFAULT '',
              error_404_path TEXT NOT NULL DEFAULT '',
              updated_at TEXT NOT NULL,
              updated_by TEXT NOT NULL,
              FOREIGN KEY(domain) REFERENCES domains(domain) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS hosting_packages(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              domain_limit INTEGER NOT NULL DEFAULT 10,
              disk_mb INTEGER NOT NULL DEFAULT 10240,
              bandwidth_mb INTEGER NOT NULL DEFAULT 102400,
              database_limit INTEGER NOT NULL DEFAULT 10,
              mailbox_limit INTEGER NOT NULL DEFAULT 25,
              cron_limit INTEGER NOT NULL DEFAULT 10,
              backup_limit INTEGER NOT NULL DEFAULT 5,
              allow_php INTEGER NOT NULL DEFAULT 1,
              allow_ssh INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS package_features(
              package_id INTEGER NOT NULL, feature_key TEXT NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
              PRIMARY KEY(package_id,feature_key),
              FOREIGN KEY(package_id) REFERENCES hosting_packages(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS account_feature_overrides(
              username TEXT NOT NULL, feature_key TEXT NOT NULL,
              enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
              PRIMARY KEY(username,feature_key),
              FOREIGN KEY(username) REFERENCES accounts(username) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS store_settings(
              id INTEGER PRIMARY KEY CHECK(id=1),
              enabled INTEGER NOT NULL DEFAULT 0,
              hostname TEXT NOT NULL DEFAULT '',
              store_name TEXT NOT NULL DEFAULT 'Hosting Store',
              currency TEXT NOT NULL DEFAULT 'USD',
              contact_email TEXT NOT NULL DEFAULT '',
              template_mode TEXT NOT NULL DEFAULT 'default' CHECK(template_mode IN ('default','custom')),
              custom_template TEXT NOT NULL DEFAULT '',
              custom_css TEXT NOT NULL DEFAULT '',
              custom_js TEXT NOT NULL DEFAULT '',
              updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS store_products(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              package_id INTEGER NOT NULL UNIQUE,
              display_name TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              monthly_price_cents INTEGER NOT NULL DEFAULT 0,
              yearly_price_cents INTEGER NOT NULL DEFAULT 0,
              enabled INTEGER NOT NULL DEFAULT 1,
              featured INTEGER NOT NULL DEFAULT 0,
              sort_order INTEGER NOT NULL DEFAULT 0,
              FOREIGN KEY(package_id) REFERENCES hosting_packages(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS store_orders(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              order_number TEXT NOT NULL UNIQUE,
              product_id INTEGER,
              package_name TEXT NOT NULL,
              customer_name TEXT NOT NULL,
              customer_email TEXT NOT NULL,
              company TEXT NOT NULL DEFAULT '',
              phone TEXT NOT NULL DEFAULT '',
              requested_domain TEXT NOT NULL DEFAULT '',
              billing_cycle TEXT NOT NULL CHECK(billing_cycle IN ('monthly','yearly')),
              notes TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','contacted','approved','rejected','completed')),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              remote_addr TEXT,
              FOREIGN KEY(product_id) REFERENCES store_products(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS mail_impersonation_tokens(
              token_hash TEXT PRIMARY KEY,
              mailbox TEXT NOT NULL,
              admin_username TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at TEXT,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS wordpress_impersonation_tokens(
              token_hash TEXT PRIMARY KEY,
              app_id INTEGER NOT NULL,
              domain TEXT NOT NULL,
              admin_user TEXT NOT NULL,
              admin_username TEXT NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at TEXT,
              created_at TEXT NOT NULL,
              FOREIGN KEY(app_id) REFERENCES app_installations(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS account_suspension_domains(
              username TEXT NOT NULL,
              domain TEXT NOT NULL,
              was_suspended INTEGER NOT NULL DEFAULT 0 CHECK(was_suspended IN (0,1)),
              PRIMARY KEY(username,domain)
            );

            CREATE TABLE IF NOT EXISTS mail_security_events(
              id TEXT PRIMARY KEY,
              message_key TEXT NOT NULL UNIQUE,
              queue_id TEXT NOT NULL DEFAULT '',
              sender TEXT NOT NULL DEFAULT '',
              recipients_json TEXT NOT NULL DEFAULT '[]',
              subject TEXT NOT NULL DEFAULT '',
              source_ip TEXT NOT NULL DEFAULT '',
              score REAL NOT NULL DEFAULT 0,
              action TEXT NOT NULL DEFAULT 'no action',
              symbols_json TEXT NOT NULL DEFAULT '[]',
              direction TEXT NOT NULL DEFAULT 'incoming',
              size_bytes INTEGER NOT NULL DEFAULT 0,
              quarantine_path TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'tracked' CHECK(status IN ('tracked','quarantined','released','deleted')),
              created_at TEXT NOT NULL,
              released_at TEXT,
              released_by TEXT
            );
            CREATE INDEX IF NOT EXISTS mail_security_events_created_idx ON mail_security_events(created_at DESC);
            CREATE INDEX IF NOT EXISTS mail_security_events_status_idx ON mail_security_events(status,created_at DESC);
            """
        )
        conn.execute("INSERT OR IGNORE INTO store_settings(id,updated_at) VALUES(1,?)", (now(),))

        defaults = {
            "panel_name": "MassPanel",
            "company_name": "",
            "support_email": "",
            "support_url": "",
            "public_url": "",
            "footer_text": "Free and self-hosted hosting control panel",
            "show_powered_by": "1",
            "mail_hostname": "",
            "owner_mailbox": "",
            "system_mail_domain": "",
            "system_mailbox": "",
        }
        for setting_key, setting_value in defaults.items():
            conn.execute(
                "INSERT OR IGNORE INTO panel_settings(setting_key,setting_value,updated_at) VALUES(?,?,?)",
                (setting_key, setting_value, now()),
            )
        conn.execute(
            "INSERT OR IGNORE INTO license_state(id,installation_id) VALUES(1,?)",
            (secrets.token_urlsafe(24),),
        )

        if not _table_has_col(conn, "domains", "suspended"):
            conn.execute("ALTER TABLE domains ADD COLUMN suspended INTEGER NOT NULL DEFAULT 0")
        if not _table_has_col(conn, "domains", "ssl_mode"):
            conn.execute("ALTER TABLE domains ADD COLUMN ssl_mode TEXT NOT NULL DEFAULT 'disabled'")
        if not _table_has_col(conn, "domains", "created_by"):
            conn.execute("ALTER TABLE domains ADD COLUMN created_by TEXT NOT NULL DEFAULT 'admin'")
        if not _table_has_col(conn, "domains", "created_at"):
            conn.execute("ALTER TABLE domains ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
        if not _table_has_col(conn, "domains", "php_enabled"):
            conn.execute("ALTER TABLE domains ADD COLUMN php_enabled INTEGER NOT NULL DEFAULT 0")
        if not _table_has_col(conn, "domains", "php_memory_limit"):
            conn.execute("ALTER TABLE domains ADD COLUMN php_memory_limit INTEGER NOT NULL DEFAULT 256")
        if not _table_has_col(conn, "domains", "php_upload_limit"):
            conn.execute("ALTER TABLE domains ADD COLUMN php_upload_limit INTEGER NOT NULL DEFAULT 64")
        if not _table_has_col(conn, "domains", "php_execution_time"):
            conn.execute("ALTER TABLE domains ADD COLUMN php_execution_time INTEGER NOT NULL DEFAULT 120")
        if not _table_has_col(conn, "accounts", "active"):
            conn.execute("ALTER TABLE accounts ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        if not _table_has_col(conn, "accounts", "domain_limit"):
            conn.execute("ALTER TABLE accounts ADD COLUMN domain_limit INTEGER NOT NULL DEFAULT 10")
        if not _table_has_col(conn, "accounts", "allow_domain_creation"):
            conn.execute("ALTER TABLE accounts ADD COLUMN allow_domain_creation INTEGER NOT NULL DEFAULT 1")
        if not _table_has_col(conn, "accounts", "package_id"):
            conn.execute("ALTER TABLE accounts ADD COLUMN package_id INTEGER")
        if not _table_has_col(conn, "accounts", "disk_limit_mb"):
            conn.execute("ALTER TABLE accounts ADD COLUMN disk_limit_mb INTEGER NOT NULL DEFAULT 10240")
        if not _table_has_col(conn, "support_tickets", "target_role"):
            conn.execute("ALTER TABLE support_tickets ADD COLUMN target_role TEXT NOT NULL DEFAULT 'provider'")
        if not _table_has_col(conn, "app_installations", "application_slug"):
            conn.execute("ALTER TABLE app_installations ADD COLUMN application_slug TEXT NOT NULL DEFAULT 'wordpress'")
        if not _table_has_col(conn, "user_databases", "created_by"):
            conn.execute("ALTER TABLE user_databases ADD COLUMN created_by TEXT NOT NULL DEFAULT 'admin'")
        if not _table_has_col(conn, "email_accounts", "password_hash"):
            conn.execute("ALTER TABLE email_accounts ADD COLUMN password_hash TEXT")
        if not _table_has_col(conn, "email_accounts", "mail_domain"):
            conn.execute("ALTER TABLE email_accounts ADD COLUMN mail_domain TEXT")
        for column in ("allow_smtp", "allow_imap", "allow_web", "allow_dav", "allow_eas"):
            if not _table_has_col(conn, "email_accounts", column):
                conn.execute(f"ALTER TABLE email_accounts ADD COLUMN {column} INTEGER NOT NULL DEFAULT 1")
        if not _table_has_col(conn, "email_accounts", "forward_copy"):
            conn.execute("ALTER TABLE email_accounts ADD COLUMN forward_copy TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE email_accounts SET mail_domain=domain WHERE mail_domain IS NULL")
        if not _table_has_col(conn, "dns_records", "mail_domain"):
            conn.execute("ALTER TABLE dns_records ADD COLUMN mail_domain TEXT")
        if not _table_has_col(conn, "mail_domains", "grommunio_managed"):
            conn.execute("ALTER TABLE mail_domains ADD COLUMN grommunio_managed INTEGER NOT NULL DEFAULT 0")
        if not _table_has_col(conn, "store_settings", "custom_js"):
            conn.execute("ALTER TABLE store_settings ADD COLUMN custom_js TEXT NOT NULL DEFAULT ''")
        if not _table_has_col(conn, "backups", "schedule_id"):
            conn.execute("ALTER TABLE backups ADD COLUMN schedule_id TEXT")

        conn.execute(
            "INSERT OR IGNORE INTO mail_domains(domain,zone_domain,owner,status,created_at,created_by) "
            "SELECT domain,domain,owner,'active',created_at,created_by FROM domains"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mail_domains_owner ON mail_domains(owner,domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_dns_records_mail_domain ON dns_records(mail_domain,domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_email_accounts_mail_domain ON email_accounts(mail_domain,domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_owner ON scheduled_tasks(owner,domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_schedules_owner ON backup_schedules(owner,domain)")
        for column, definition in (("destination_type", "TEXT NOT NULL DEFAULT 'local'"), ("destination_config", "TEXT NOT NULL DEFAULT ''"), ("remote_path", "TEXT NOT NULL DEFAULT 'MassPanel'")):
            if column not in {item[1] for item in conn.execute("PRAGMA table_info(backup_schedules)").fetchall()}:
                conn.execute(f"ALTER TABLE backup_schedules ADD COLUMN {column} {definition}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_backups_schedule ON backups(schedule_id,id DESC)")
        conn.execute("UPDATE domains SET php_enabled=1 WHERE domain IN (SELECT domain FROM app_installations)")

        conn.execute(
            "INSERT OR IGNORE INTO accounts(username,password_hash,role,system_username,active,created_at) "
            "SELECT username,password_hash,'admin',NULL,active,created_at FROM admins"
        )


def init_db():
    BASE.mkdir(mode=0o750, parents=True, exist_ok=True)
    BACKUP_DIR.mkdir(mode=0o750, parents=True, exist_ok=True)
    with db() as c:
        _ensure_table(c)


def audit(action, target=None, outcome="success", actor=None):
    with db() as c:
        cursor = c.execute(
            """
            INSERT INTO audit(created_at,actor,action,target,outcome,remote_addr)
            VALUES(?,?,?,?,?,?)
            """,
            (now(), actor or session.get("username", "anonymous"), action, target, outcome, request.remote_addr),
        )


def product_settings():
    with db() as c:
        rows = c.execute("SELECT setting_key,setting_value FROM panel_settings").fetchall()
    values = {row["setting_key"]: row["setting_value"] for row in rows}
    values["show_powered_by"] = values.get("show_powered_by", "1") == "1"
    return values


def _decode_entitlement(token):
    try:
        encoded, signature = token.split(".", 1)
        padding = "=" * (-len(signature) % 4)
        key = serialization.load_pem_public_key(LICENSE_PUBLIC_KEY.read_bytes())
        key.verify(base64.urlsafe_b64decode(signature + padding), encoded.encode("ascii"))
        payload_padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + payload_padding))
        if payload.get("v") != 1 or payload.get("issuer") != "MassPanel Licensing":
            raise ValueError("Unsupported entitlement.")
        return payload
    except (OSError, ValueError, KeyError, InvalidSignature, json.JSONDecodeError) as exc:
        raise RuntimeError("The licence entitlement is invalid.") from exc


def _entitlement_time(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def license_status(connection=None):
    owns_connection = connection is None
    c = connection or db()
    try:
        state = c.execute("SELECT * FROM license_state WHERE id=1").fetchone()
        domain_count = c.execute("SELECT COUNT(*) AS total FROM domains").fetchone()["total"]
        result = {
            "edition": "community",
            "status": "active",
            "domain_limit": COMMUNITY_DOMAIN_LIMIT,
            "domain_count": domain_count,
            "remaining_domains": max(COMMUNITY_DOMAIN_LIMIT - domain_count, 0),
            "can_add_domain": domain_count < COMMUNITY_DOMAIN_LIMIT,
            "installation_id": state["installation_id"],
            "subscription_expires_at": "",
            "grace_until": "",
            "last_refresh_at": state["last_refresh_at"],
            "last_error": state["last_error"],
            "license_server_url": LICENSE_SERVER_URL,
        }
        if not state["entitlement_token"]:
            return result
        try:
            entitlement = _decode_entitlement(state["entitlement_token"])
            if entitlement.get("installation_id") != state["installation_id"]:
                raise RuntimeError("The entitlement belongs to another installation.")
            current = datetime.now(timezone.utc)
            expires = _entitlement_time(entitlement["subscription_expires_at"])
            grace = _entitlement_time(entitlement["grace_until"])
            result.update(
                subscription_expires_at=entitlement["subscription_expires_at"],
                grace_until=entitlement["grace_until"],
            )
            if current <= grace:
                result.update(
                    edition="unlimited",
                    status="active" if current <= expires else "grace",
                    domain_limit=None,
                    remaining_domains=None,
                    can_add_domain=True,
                )
            else:
                result.update(status="expired", can_add_domain=domain_count < COMMUNITY_DOMAIN_LIMIT)
        except RuntimeError as exc:
            result.update(status="invalid", last_error=str(exc))
        return result
    finally:
        if owns_connection:
            c.close()


def _license_request(path, payload):
    request_data = json.dumps(payload).encode("utf-8")
    req = Request(
        LICENSE_SERVER_URL + path,
        data=request_data,
        headers={"Content-Type": "application/json", "User-Agent": "MassPanel/1.0"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=15) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        try: message = json.loads(exc.read()).get("error", "Licence server rejected the request.")
        except (ValueError, json.JSONDecodeError): message = "Licence server rejected the request."
        raise RuntimeError(message) from exc
    except (OSError, URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("The MassPanel licence server is currently unavailable.") from exc


def limited(key, maximum, window):
    stamp = time.monotonic()
    q = attempts[key]
    while q and q[0] < stamp - window:
        q.popleft()
    if len(q) >= maximum:
        return True
    q.append(stamp)
    return False


def require_auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("username"):
            return jsonify(error="Authentication required."), 401
        return fn(*args, **kwargs)

    return wrapped


def require_admin(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get("role") != "admin":
            return jsonify(error="Administrator access required."), 403
        return fn(*args, **kwargs)

    return wrapped


def require_csrf(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        token = request.headers.get("X-CSRF-Token", "")
        if not token or not hmac.compare_digest(token, session.get("csrf", "")):
            return jsonify(error="Invalid request token."), 403
        return fn(*args, **kwargs)

    return wrapped


@app.get("/api/system/updates")
@require_auth
@require_admin
def system_updates():
    action = "check" if request.args.get("refresh") == "1" else "status"
    try: result = helper({"operation":"updater_control", "action":action})
    except RuntimeError as exc: return jsonify(error=str(exc)), 502
    return jsonify(result)


@app.post("/api/system/updates/apply")
@require_auth
@require_admin
@require_csrf
def system_updates_apply():
    try: result = helper({"operation":"updater_control", "action":"apply"})
    except RuntimeError as exc: return jsonify(error=str(exc)), 502
    audit("system.update", "apply")
    return jsonify(result), 202


@app.post("/api/system/updates/rollback")
@require_auth
@require_admin
@require_csrf
def system_updates_rollback():
    snapshot = str((request.get_json(silent=True) or {}).get("snapshot", ""))
    try: result = helper({"operation":"updater_control", "action":"rollback", "snapshot":snapshot})
    except RuntimeError as exc: return jsonify(error=str(exc)), 502
    audit("system.update", f"rollback:{snapshot}")
    return jsonify(result), 202


def helper(payload):
    operation = payload.get("operation")
    if operation in {"wordpress_install", "application_install", "wordpress_action", "application_action", "domain_config", "domain_certificate_regenerate", "mail_certificate", "panel_certificate", "storefront_certificate"}:
        timeout = 420
    elif operation == "grommunio_domain_delete":
        timeout = 420
    elif operation in {"grommunio_email_create", "grommunio_email_update", "grommunio_email_delete", "grommunio_account_access"}:
        timeout = 300
    elif operation == "grommunio_domain_create":
        timeout = 240
    elif operation == "cloudflare_sync":
        timeout = 300
    elif operation in {"dns_sync", "email_sync", "email_hash", "grommunio_domain_users", "website_rules_sync"}:
        timeout = 90
    else:
        timeout = 30
    try:
        proc = subprocess.run(["/usr/bin/sudo", HELPER], input=json.dumps(payload), text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"The privileged {operation or 'operation'} task timed out.") from exc
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise RuntimeError("Privileged helper returned an invalid response.")
    if proc.returncode or not data.get("ok"):
        raise RuntimeError(data.get("error", "Operation failed."))
    return data


def _validate_schedule(value):
    fields = str(value or "").strip().split()
    if len(fields) != 5 or any(len(field) > 32 or not CRON_FIELD.fullmatch(field) for field in fields):
        raise RuntimeError("Use a valid five-field cron schedule, for example: 0 2 * * *")
    return " ".join(fields)


def _validate_task_command(value):
    command = str(value or "").strip()
    if not command or len(command) > 1000 or any(ch in command for ch in "\r\n\x00"):
        raise RuntimeError("Enter a single command of no more than 1000 characters.")
    return command


def _sync_owner_tasks(c, owner):
    tasks = [dict(row) for row in c.execute(
        "SELECT id,name,schedule,command,enabled FROM scheduled_tasks WHERE owner=? ORDER BY created_at,id",
        (owner,),
    ).fetchall()]
    return helper({"operation": "cron_sync", "owner": owner, "tasks": tasks})


def _package_limit(c, owner, column):
    if column not in {"database_limit", "mailbox_limit", "cron_limit", "backup_limit", "disk_mb", "bandwidth_mb"}:
        raise ValueError("Unsupported package limit.")
    row = c.execute(f"SELECT p.{column} AS value FROM accounts a JOIN hosting_packages p ON p.id=a.package_id WHERE a.system_username=?", (owner,)).fetchone()
    return row["value"] if row else None


FEATURE_CATALOG = {
    "websites": "Websites", "dns": "DNS management", "mail": "Email & groupware",
    "files": "File manager", "databases": "Databases", "backups": "Backups",
    "wordpress": "WordPress manager", "cron": "Cron jobs", "php": "PHP controls",
    "ssh": "SSH access", "ssl": "SSL certificates", "cloudflare": "Cloudflare sync",
    "support": "Support tickets",
}
APP_CATALOG = {
    "nextcloud": {"slug":"nextcloud","name":"Nextcloud","category":"Collaboration","summary":"Private file sync, sharing, calendars and collaboration.","engine":"nextcloud","icon":"NC","featured":True,"admin_path":"/settings/admin/overview","requirements":"PHP 8.3 · MariaDB · 1 GB storage"},
    "wordpress": {"slug":"wordpress","name":"WordPress","category":"CMS","summary":"Flexible publishing and website platform.","engine":"wordpress","icon":"W","featured":False,"admin_path":"/wp-admin/","requirements":"PHP 8.3 · MariaDB"},
    "joomla": {"slug":"joomla","name":"Joomla","category":"CMS","summary":"Full-featured content management and portal platform.","engine":"joomla","icon":"J!","featured":False,"admin_path":"/administrator/","requirements":"PHP 8.3 · MariaDB"},
    "woocommerce": {"slug":"woocommerce","name":"WooCommerce","category":"E-commerce","summary":"WordPress with WooCommerce installed and activated.","engine":"wordpress","icon":"Woo","featured":False,"admin_path":"/wp-admin/","requirements":"PHP 8.3 · MariaDB"},
    "elementor": {"slug":"elementor","name":"WordPress + Elementor","category":"Site builder","summary":"WordPress with the Elementor visual builder ready to use.","engine":"wordpress","icon":"E","featured":False,"admin_path":"/wp-admin/","requirements":"PHP 8.3 · MariaDB"},
    "bbpress": {"slug":"bbpress","name":"bbPress Forum","category":"Community","summary":"WordPress with bbPress forums installed and activated.","engine":"wordpress","icon":"bb","featured":False,"admin_path":"/wp-admin/","requirements":"PHP 8.3 · MariaDB"},
}
FEATURE_ENDPOINTS = {
    "create_domain":"websites", "suspend_domain":"websites", "unsuspend_domain":"websites", "delete_domain":"websites", "list_website_redirects":"websites", "create_website_redirect":"websites", "delete_website_redirect":"websites", "get_website_security":"websites", "update_website_security":"websites",
    "list_apps":"wordpress", "install_wordpress":"wordpress", "manage_app":"wordpress", "impersonate_wordpress":"wordpress", "launch_wordpress_impersonation":"wordpress", "exchange_wordpress_impersonation":"wordpress",
    "list_dns":"dns", "dns_server_status":"dns", "create_dns":"dns", "delete_dns":"dns", "generate_mail_dns":"dns",
    "cloudflare_status":"cloudflare", "cloudflare_connect":"cloudflare", "cloudflare_disconnect":"cloudflare", "sync_cloudflare_dns":"cloudflare",
    "list_files":"files", "read_file":"files", "mutate_files":"files", "upload_file":"files", "download_file":"files",
    "list_databases":"databases", "create_database":"databases", "delete_database":"databases", "query_database":"databases",
    "list_mail_domains":"mail", "create_mail_domain":"mail", "delete_mail_domain":"mail", "list_emails":"mail", "mail_status":"mail", "impersonate_mailbox":"mail", "launch_mail_impersonation":"mail", "exchange_mail_impersonation":"mail", "create_email":"mail", "delete_email":"mail",
    "list_scheduled_tasks":"cron", "create_scheduled_task":"cron", "toggle_scheduled_task":"cron", "run_scheduled_task":"cron", "delete_scheduled_task":"cron",
    "update_domain_php":"php", "website_logs":"websites",
    "list_backups":"backups", "create_backup":"backups", "download_backup":"backups", "restore_backup":"backups", "delete_backup":"backups",
    "set_domain_ssl":"ssl", "list_ssl":"ssl", "regenerate_ssl":"ssl",
    "list_tickets":"support", "get_ticket":"support", "create_ticket":"support", "update_ticket_status":"support", "reply_ticket":"support", "delete_ticket":"support",
}


def _effective_features(c, username):
    result = {key: True for key in FEATURE_CATALOG}
    account = c.execute("SELECT package_id FROM accounts WHERE username=?", (username,)).fetchone()
    if not account: return result
    if account["package_id"] is not None:
        for row in c.execute("SELECT feature_key,enabled FROM package_features WHERE package_id=?", (account["package_id"],)):
            if row["feature_key"] in result: result[row["feature_key"]] = bool(row["enabled"])
    for row in c.execute("SELECT feature_key,enabled FROM account_feature_overrides WHERE username=?", (username,)):
        if row["feature_key"] in result: result[row["feature_key"]] = bool(row["enabled"])
    return result


def _session_features():
    if session.get("role") == "admin": return {key: True for key in FEATURE_CATALOG}
    with db() as c: return _effective_features(c, session.get("username", ""))


@app.before_request
def enforce_package_feature():
    feature = FEATURE_ENDPOINTS.get(request.endpoint)
    if not feature or not session.get("username") or session.get("role") == "admin": return None
    if not _session_features().get(feature, False):
        return jsonify(error="This feature is not included in your hosting package.", feature=feature), 403
    return None


def _validate_record_value(rtype, value):
    if rtype == "A":
        ipaddress.ip_address(value)
        return True
    if rtype == "AAAA":
        ipaddress.ip_address(value)
        return True
    if rtype == "MX":
        parts = value.split()
        if len(parts) != 2:
            return False
        if not parts[0].isdigit() or not (0 <= int(parts[0]) <= 65535):
            return False
        return bool(DOMAIN.fullmatch(parts[1].rstrip(".")))
    if rtype in {"CNAME", "NS", "TXT", "SPF", "SRV"}:
        return bool(value) and len(value) <= 255
    return False


def _can_access_domain(c, domain, username):
    row = c.execute("SELECT owner FROM domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        return None
    if session.get("role") == "admin" or row["owner"] == username:
        return True
    return False


def _parent_website_domain(c, domain, owner):
    rows = c.execute("SELECT domain FROM domains WHERE owner=?", (owner,)).fetchall()
    matches = [row["domain"] for row in rows if domain == row["domain"] or domain.endswith("." + row["domain"])]
    return max(matches, key=len) if matches else ""


def _mail_domain_context(c, domain, username):
    row = c.execute("SELECT domain,zone_domain,owner FROM mail_domains WHERE domain=? AND status='active'", (domain,)).fetchone()
    if not row or (session.get("role") != "admin" and row["owner"] != username): return None
    return row


def _mail_record_name(mail_domain, zone_domain, name):
    if mail_domain == zone_domain: return name
    prefix = mail_domain[:-(len(zone_domain) + 1)]
    return prefix if name == "@" else name + "." + prefix


def _valid_email_address(value):
    localpart, separator, domain = str(value).lower().rpartition("@")
    return bool(separator and EMAIL_LOCALPART.fullmatch(localpart) and DOMAIN.fullmatch(domain))


def _domain_context(c, domain, username):
    row = c.execute(
        "SELECT * FROM domains WHERE domain=?",
        (domain,),
    ).fetchone()
    if not row:
        return None
    if session.get("role") != "admin" and row["owner"] != username:
        return None
    return row


def _sync_dns(c, domain, nameservers=None):
    records = [dict(row) for row in c.execute("SELECT type,name,value,ttl FROM dns_records WHERE domain=? ORDER BY id", (domain,)).fetchall()]
    primary_ns, secondary_ns = nameservers or dns_service_nameservers()
    return helper({"operation": "dns_sync", "domain": domain, "records": records,
                   "primary_ns": primary_ns, "secondary_ns": secondary_ns})


def _save_cloudflare_sync_state(status, domain="", error=""):
    values = {
        "cloudflare_last_sync_at": now(),
        "cloudflare_last_sync_status": status,
        "cloudflare_last_sync_domain": domain,
        "cloudflare_last_sync_error": str(error)[:300],
    }
    try:
        with db() as c:
            for key, value in values.items():
                c.execute(
                    "INSERT INTO panel_settings(setting_key,setting_value,updated_at) VALUES(?,?,?) "
                    "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at",
                    (key, value, now()),
                )
    except sqlite3.Error:
        pass


def _auto_cloudflare_sync(domain, records=None, ensure_apex=True, prune=True, adopt_legacy=True, scope=None):
    try:
        status = helper({"operation":"cloudflare_status"})
        if not status.get("connected"):
            return {"connected":False, "automatic":True, "status":"not_connected"}
        if records is None:
            with db() as c:
                records = [dict(row) for row in c.execute(
                    "SELECT type,name,value,ttl FROM dns_records WHERE domain=? ORDER BY id", (domain,)
                ).fetchall()]
        result = helper({
            "operation":"cloudflare_sync", "domain":domain, "scope":scope or domain,
            "records":records, "ensure_apex":ensure_apex, "prune":prune,
            "adopt_legacy":adopt_legacy,
        })
        _save_cloudflare_sync_state("synced", domain)
        return {"connected":True, "automatic":True, "status":"synced", **result}
    except RuntimeError as exc:
        _save_cloudflare_sync_state("failed", domain, exc)
        return {"connected":True, "automatic":True, "status":"failed", "domain":domain, "error":str(exc)}


def _auto_cloudflare_service_hostname(hostname, remove=False):
    hostname = str(hostname or "").lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(hostname):
        return {"connected":False, "automatic":True, "status":"skipped"}
    return _auto_cloudflare_sync(
        hostname, records=[], ensure_apex=not remove, prune=True,
        adopt_legacy=False, scope=hostname,
    )


def _sync_email(c):
    accounts = [dict(row) for row in c.execute(
        "SELECT full_email,COALESCE(mail_domain,domain) AS domain,localpart,destination,password_hash,quota_mb,status "
        "FROM email_accounts ORDER BY full_email"
    ).fetchall()]
    return helper({"operation": "email_sync", "accounts": accounts})


def _resolve_webroot_path(c, domain, rel_path, username, create_parent=False):
    row = _domain_context(c, domain, username)
    if not row:
        return None, None
    root = Path(row["webroot"]).resolve()
    rel = str(rel_path or "").lstrip("/").strip()
    candidate = (root / rel).resolve()
    if root in candidate.parents or candidate == root:
        if candidate.exists() and candidate.is_dir() and create_parent:
            return row, candidate
        if candidate.exists() or rel == "":
            return row, candidate
        if create_parent:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            return row, candidate
        return row, candidate
    raise RuntimeError("Invalid file path.")


def _list_directory_items(path):
    items = []
    with os.scandir(path) as it:
        for entry in it:
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            items.append(
                {
                    "name": entry.name,
                    "type": "dir" if entry.is_dir(follow_symlinks=False) else "file",
                    "size": st.st_size if entry.is_file(follow_symlinks=False) else 0,
                    "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                }
            )
    items.sort(key=lambda r: (r["type"] != "dir", r["name"].lower()))
    return items


def _read_file_preview(path):
    with open(path, "rb") as h:
        data = h.read(262144)
    if b"\x00" in data[:16384]:
        return {"is_binary": True, "content": None, "size": len(data)}
    try:
        return {"is_binary": False, "content": data.decode("utf-8"), "size": len(data)}
    except UnicodeDecodeError:
        return {"is_binary": True, "content": None, "size": len(data)}


def _database_path(root, domain, name):
    return root / "databases" / f"{name}.sqlite"


def _start_impersonation(target):
    if not target["system_username"]:
        raise RuntimeError("Cannot impersonate an account without system mapping.")
    session["_impersonator_username"] = session["username"]
    session["_impersonator_role"] = session["role"]
    session["_impersonator_system_username"] = session.get("system_username")
    session["_impersonating_as"] = target["username"]
    session["username"] = target["username"]
    session["role"] = "client"
    session["system_username"] = target["system_username"]


def _stop_impersonation():
    if "_impersonator_username" not in session:
        return False
    session["username"] = session.pop("_impersonator_username")
    session["role"] = session.pop("_impersonator_role")
    session["system_username"] = session.pop("_impersonator_system_username", None)
    session.pop("_impersonating_as", None)
    return True


def _domain_record(c, domain):
    return c.execute("SELECT domain, owner, webroot, suspended, ssl_mode FROM domains WHERE domain=?", (domain,)).fetchone()


def _sync_website_rules(c, domain):
    row = c.execute("SELECT domain,owner,webroot,suspended,ssl_mode,php_enabled FROM domains WHERE domain=?", (domain,)).fetchone()
    if not row: raise RuntimeError("Website not found.")
    redirects = [dict(item) for item in c.execute("SELECT source_path,target_url,status_code FROM website_redirects WHERE domain=? ORDER BY source_path", (domain,))]
    settings_row = c.execute("SELECT hotlink_enabled,hotlink_extensions,allowed_referrers,error_404_path FROM website_security_settings WHERE domain=?", (domain,)).fetchone()
    settings = dict(settings_row) if settings_row else {"hotlink_enabled":0,"hotlink_extensions":"jpg,jpeg,png,gif,webp,svg,mp4","allowed_referrers":"","error_404_path":""}
    wordpress = bool(c.execute("SELECT 1 FROM app_installations WHERE domain=? AND app_type='wordpress'", (domain,)).fetchone())
    helper({"operation":"domain_config", "domain":domain, "owner":row["owner"], "webroot":row["webroot"], "ssl_mode":row["ssl_mode"], "suspended":bool(row["suspended"]), "wordpress":wordpress or bool(row["php_enabled"])})
    return helper({"operation":"website_rules_sync", "domain":domain, "owner":row["owner"], "webroot":row["webroot"], "redirects":redirects, "settings":settings})


def _require_json_fields(payload, fields):
    missing = [f for f in fields if f not in payload]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")


@app.after_request
def headers(resp):
    resp.headers.update(
        {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
        }
    )
    return resp


@app.get("/api/live")
def live():
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    if limited((request.remote_addr, "login"), 8, 900):
        return jsonify(error="Too many sign-in attempts. Try again later."), 429

    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    with db() as c:
        row = c.execute(
            "SELECT username,password_hash,role,system_username "
            "FROM accounts WHERE username=? AND active=1",
            (username,),
        ).fetchone()
    valid = False
    if row:
        try:
            valid = ph.verify(row["password_hash"], password)
        except VerifyMismatchError:
            pass

    if not valid:
        app.logger.warning("MASSPANEL_AUTH_FAILURE ip=%s username=%s", request.remote_addr, str(username)[:64])
        audit("login", outcome="failed", actor=username[:64] or "anonymous")
        return jsonify(error="Invalid username or password."), 401

    session.clear()
    session.permanent = True
    session.update(
        username=row["username"],
        role=row["role"],
        system_username=row["system_username"],
        csrf=secrets.token_urlsafe(32),
    )
    audit("login")
    if row["role"] == "admin":
        try: helper({"operation":"firewall_trust_admin_ip", "ip":request.remote_addr})
        except RuntimeError as exc: app.logger.warning("Could not refresh administrator firewall trust: %s", exc)
    return jsonify(username=row["username"], role=row["role"], csrf=session["csrf"], features=_session_features())


@app.get("/api/session")
@require_auth
def get_session():
    if session.get("role") == "admin":
        try: helper({"operation":"firewall_trust_admin_ip", "ip":request.remote_addr})
        except RuntimeError as exc: app.logger.warning("Could not refresh administrator firewall trust: %s", exc)
    return jsonify(
        username=session["username"],
        role=session["role"],
        system_username=session.get("system_username"),
        csrf=session["csrf"],
        impersonating_as=session.get("_impersonating_as"),
        impersonator=session.get("_impersonator_username"),
        features=_session_features(),
    )


@app.post("/api/logout")
@require_auth
@require_csrf
def logout():
    audit("logout")
    session.clear()
    return jsonify(ok=True)


@app.get("/api/health")
@require_auth
def health():
    return jsonify(
        cpu=round(psutil.cpu_percent(interval=0.15)),
        memory=round(psutil.virtual_memory().percent),
        disk=round(psutil.disk_usage("/").percent),
    )


@app.get("/api/storage")
@require_auth
@require_admin
def storage_overview():
    """Owner-only physical storage and customer allocation overview."""
    grouped = {}
    for part in psutil.disk_partitions(all=False):
        if not part.mountpoint:
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        identity = (part.device, part.fstype or "unknown", usage.total)
        drive = grouped.setdefault(identity, {
            "device": part.device,
            "mountpoint": part.mountpoint,
            "mountpoints": [],
            "filesystem": part.fstype or "unknown",
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "percent": usage.percent,
            "hosting": False,
        })
        if part.mountpoint not in drive["mountpoints"]: drive["mountpoints"].append(part.mountpoint)
        if part.mountpoint == "/" or len(part.mountpoint) < len(drive["mountpoint"]): drive["mountpoint"] = part.mountpoint
        if part.mountpoint == "/" or part.mountpoint == "/home" or part.mountpoint.startswith("/home/"):
            drive["hosting"] = True
    drives = sorted(grouped.values(), key=lambda item: (not item["hosting"], item["mountpoint"], item["device"]))
    for drive in drives: drive["mountpoints"].sort(key=lambda path: (path != "/", len(path), path))
    with db() as c:
        allocation = c.execute("SELECT COALESCE(SUM(disk_limit_mb),0) AS total_mb,COUNT(*) AS accounts FROM accounts WHERE role='client' AND active=1").fetchone()
        domains = c.execute("SELECT COUNT(*) AS total FROM domains").fetchone()["total"]
    return jsonify(
        drives=drives,
        allocated_bytes=int(allocation["total_mb"] or 0) * 1024 * 1024,
        active_accounts=allocation["accounts"],
        hosted_domains=domains,
        hosting_root="/home",
        note="MassPanel groups bind mounts and temporary mount points by their underlying physical filesystem. Customer limits are allocations, not the full physical disk size.",
    )


@app.get("/api/product")
def get_product_settings():
    return jsonify(**product_settings())


@app.get("/api/settings")
@require_auth
def get_settings():
    values = product_settings()
    values.update(
        server_hostname=os.uname().nodename,
        panel_port=request.host.split(":")[-1] if ":" in request.host else "443",
        account_username=session["username"],
        account_role=session["role"],
    )
    return jsonify(**values)


@app.get("/api/license")
@require_auth
@require_admin
def get_license():
    return jsonify(**license_status())


@app.post("/api/license/activate")
@require_auth
@require_admin
@require_csrf
def activate_license():
    license_key = str((request.get_json(silent=True) or {}).get("license_key", "")).strip()
    if not re.fullmatch(r"MPU-[A-Za-z0-9_-]{30,80}", license_key):
        return jsonify(error="Enter a valid MassPanel Unlimited licence key."), 400
    with db() as c:
        state = c.execute("SELECT installation_id FROM license_state WHERE id=1").fetchone()
    try:
        result = _license_request("/v1/activate", {
            "license_key": license_key,
            "installation_id": state["installation_id"],
            "instance_url": product_settings().get("public_url", ""),
        })
        entitlement = _decode_entitlement(result["entitlement_token"])
        if entitlement.get("installation_id") != state["installation_id"] or entitlement.get("plan") != "unlimited":
            raise RuntimeError("The licence server returned an entitlement for another installation.")
        with db() as c:
            c.execute(
                "UPDATE license_state SET entitlement_token=?,activation_id=?,activation_secret=?,last_refresh_at=?,last_error='' WHERE id=1",
                (result["entitlement_token"], str(result["activation_id"]), result["activation_secret"], now()),
            )
        audit("license.activate", str(entitlement.get("license_id", "unlimited")))
        return jsonify(ok=True, **license_status())
    except (KeyError, RuntimeError, sqlite3.Error) as exc:
        with db() as c:
            c.execute("UPDATE license_state SET last_error=? WHERE id=1", (str(exc)[:300],))
        audit("license.activate", "unlimited", "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/license/refresh")
@require_auth
@require_admin
@require_csrf
def refresh_license():
    with db() as c:
        state = c.execute("SELECT installation_id,activation_id,activation_secret FROM license_state WHERE id=1").fetchone()
    if not state["activation_id"] or not state["activation_secret"]:
        return jsonify(error="Activate an Unlimited licence before refreshing it."), 400
    try:
        result = _license_request("/v1/refresh", {
            "activation_id": state["activation_id"],
            "activation_secret": state["activation_secret"],
            "installation_id": state["installation_id"],
        })
        entitlement = _decode_entitlement(result["entitlement_token"])
        if entitlement.get("installation_id") != state["installation_id"]:
            raise RuntimeError("The refreshed entitlement belongs to another installation.")
        with db() as c:
            c.execute(
                "UPDATE license_state SET entitlement_token=?,last_refresh_at=?,last_error='' WHERE id=1",
                (result["entitlement_token"], now()),
            )
        audit("license.refresh", str(entitlement.get("license_id", "unlimited")))
        return jsonify(ok=True, **license_status())
    except (KeyError, RuntimeError, sqlite3.Error) as exc:
        with db() as c:
            c.execute("UPDATE license_state SET last_error=? WHERE id=1", (str(exc)[:300],))
        audit("license.refresh", "unlimited", "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/license/remove")
@require_auth
@require_admin
@require_csrf
def remove_license():
    """Forget the paid entitlement locally without changing hosted services or the server identity."""
    try:
        with db() as c:
            c.execute(
                "UPDATE license_state SET entitlement_token='',activation_id='',activation_secret='',last_refresh_at='',last_error='' WHERE id=1"
            )
        audit("license.remove", "local entitlement")
        return jsonify(ok=True, **license_status())
    except sqlite3.Error as exc:
        audit("license.remove", "local entitlement", "failed")
        return jsonify(error=f"The licence could not be removed: {exc}"), 400


def _public_dns(record_type, name):
    """Query a public resolver so local /etc/hosts entries cannot produce false passes."""
    try:
        query_name = ipaddress.ip_address(name).reverse_pointer if record_type == "PTR" else name
        request_url = "https://cloudflare-dns.com/dns-query?name=" + query_name + "&type=" + record_type
        req = Request(request_url, headers={"Accept":"application/dns-json", "User-Agent":"MassPanel/1.0"})
        with urlopen(req, timeout=8) as response: result = json.loads(response.read())
        return [str(item.get("data", "")).strip().strip('"').rstrip(".") for item in result.get("Answer", []) if item.get("data")]
    except (OSError, ValueError, TimeoutError):
        return []


def _server_ipv4():
    try:
        route = subprocess.run(["/usr/sbin/ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5).stdout.split()
        return route[route.index("src") + 1]
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return ""


def _tls_ready(hostname, server_ip):
    if not hostname or not server_ip: return False
    try:
        context = ssl.create_default_context()
        with socket.create_connection((server_ip, 443), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname): return True
    except (OSError, ssl.SSLError):
        return False


def service_domain_status():
    settings = product_settings()
    parsed = urlparse(settings.get("public_url", ""))
    panel_hostname = (parsed.hostname or "").lower()
    mail_hostname = settings.get("mail_hostname", "").lower().rstrip(".")
    server_ip = _server_ipv4()
    primary_ns, secondary_ns = dns_service_nameservers(settings)
    panel_a = _public_dns("A", panel_hostname) if panel_hostname else []
    mail_a = _public_dns("A", mail_hostname) if mail_hostname else []
    primary_ns_a = _public_dns("A", primary_ns) if primary_ns else []
    secondary_ns_a = _public_dns("A", secondary_ns) if secondary_ns else []
    ptr = _public_dns("PTR", server_ip) if server_ip else []
    ptr_ok = bool(mail_hostname and any(item.lower() == mail_hostname for item in ptr))
    checks = {
        "panel_a": bool(server_ip and server_ip in panel_a),
        "mail_a": bool(server_ip and server_ip in mail_a),
        "mail_ptr": ptr_ok,
        "panel_tls": _tls_ready(panel_hostname, server_ip),
        "mail_tls": _tls_ready(mail_hostname, server_ip),
        "primary_ns_a": bool(server_ip and server_ip in primary_ns_a),
        "secondary_ns_a": bool(server_ip and server_ip in secondary_ns_a),
    }
    warnings = []
    if panel_hostname and not checks["panel_a"]: warnings.append(f"The panel domain {panel_hostname} must point to {server_ip} before enabling its certificate.")
    if mail_hostname and not checks["mail_a"]: warnings.append(f"The mail server {mail_hostname} must point to {server_ip}; customer MX records depend on it.")
    if mail_hostname and not ptr_ok: warnings.append(f"Ask the IP provider to set PTR for {server_ip} to {mail_hostname}. Cloudflare cannot set PTR.")
    if primary_ns and not checks["primary_ns_a"]: warnings.append(f"The DNS server {primary_ns} must have an unproxied A record pointing to {server_ip}.")
    if secondary_ns and not checks["secondary_ns_a"]: warnings.append(f"The DNS server {secondary_ns} must have an unproxied A record pointing to {server_ip}.")
    return {"server_ip":server_ip, "panel_hostname":panel_hostname, "panel_url":settings.get("public_url", ""),
            "mail_hostname":mail_hostname, "panel_a":panel_a, "mail_a":mail_a, "ptr":ptr,
            "primary_ns":primary_ns, "secondary_ns":secondary_ns,
            "primary_ns_a":primary_ns_a, "secondary_ns_a":secondary_ns_a,
            "checks":checks, "warnings":warnings,
            "discovery":["Autodiscover", "Autoconfig", "EWS", "ActiveSync", "CalDAV", "CardDAV", "MAPI", "OAB"]}


@app.get("/api/service-domains/status")
@require_auth
def get_service_domain_status():
    return jsonify(**service_domain_status())


@app.get("/api/firewall")
@require_auth
@require_admin
def get_firewall():
    try: return jsonify(**helper({"operation":"firewall_status"}))
    except RuntimeError as exc: return jsonify(error=str(exc)), 400


@app.post("/api/firewall/block")
@require_auth
@require_admin
@require_csrf
def block_firewall_address():
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    try: result = helper({"operation":"firewall_block", "ip":ip, "admin_ip":request.remote_addr})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("firewall.block", ip)
    return jsonify(**result)


@app.delete("/api/firewall/block/<path:ip>")
@require_auth
@require_admin
@require_csrf
def unblock_firewall_address(ip):
    try: result = helper({"operation":"firewall_unblock", "ip":ip, "admin_ip":request.remote_addr})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("firewall.unblock", ip)
    return jsonify(**result)


@app.post("/api/firewall/ignore")
@require_auth
@require_admin
@require_csrf
def ignore_firewall_address():
    ip = str((request.get_json(silent=True) or {}).get("ip", "")).strip()
    try: result = helper({"operation":"firewall_ignore", "ip":ip})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("firewall.ignore", ip)
    return jsonify(**result)


@app.delete("/api/firewall/ignore/<path:ip>")
@require_auth
@require_admin
@require_csrf
def unignore_firewall_address(ip):
    try: result = helper({"operation":"firewall_unignore", "ip":ip})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("firewall.unignore", ip)
    return jsonify(**result)


@app.put("/api/settings")
@require_auth
@require_admin
@require_csrf
def update_settings():
    payload = request.get_json(silent=True) or {}
    allowed = {
        "panel_name": 48,
        "company_name": 80,
        "support_email": 160,
        "support_url": 300,
        "public_url": 300,
        "footer_text": 180,
        "mail_hostname": 253,
        "system_mail_domain": 253,
    }
    cleaned = {}
    for key, maximum in allowed.items():
        value = str(payload.get(key, "")).strip()
        if len(value) > maximum:
            return jsonify(error=f"{key.replace('_', ' ').title()} is too long."), 400
        cleaned[key] = value
    if not cleaned["panel_name"]:
        return jsonify(error="Panel name is required."), 400
    if cleaned["support_email"] and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", cleaned["support_email"]):
        return jsonify(error="Support email is invalid."), 400
    for key in ("support_url", "public_url"):
        if cleaned[key] and not re.fullmatch(r"https://[^\s]+", cleaned[key]):
            return jsonify(error=f"{key.replace('_', ' ').title()} must use HTTPS."), 400
    if cleaned["public_url"]:
        parsed = urlparse(cleaned["public_url"])
        if not parsed.hostname or not DOMAIN.fullmatch(parsed.hostname.lower()) or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            return jsonify(error="Public panel URL must be a hostname-only HTTPS URL, for example https://panel.example.com."), 400
    if cleaned["mail_hostname"]:
        cleaned["mail_hostname"] = cleaned["mail_hostname"].lower().rstrip(".")
        if not DOMAIN.fullmatch(cleaned["mail_hostname"]):
            return jsonify(error="Mail hostname must be a valid domain name."), 400
    if cleaned["system_mail_domain"]:
        cleaned["system_mail_domain"] = cleaned["system_mail_domain"].lower().rstrip(".")
        if not DOMAIN.fullmatch(cleaned["system_mail_domain"]):
            return jsonify(error="Owner system mail domain must be a valid domain name."), 400
    previous_system_domain = product_settings().get("system_mail_domain", "")
    system_mailbox_changed = previous_system_domain != cleaned["system_mail_domain"]
    if system_mailbox_changed and cleaned["system_mail_domain"]:
        try:
            provisioned = helper({"operation":"grommunio_system_mailbox_configure", "domain":cleaned["system_mail_domain"]})
            cleaned["system_mailbox"] = provisioned["mailbox"]
        except RuntimeError as exc:
            audit("settings.system-mailbox", cleaned["system_mail_domain"], "failed")
            return jsonify(error=str(exc)), 400
    elif not cleaned["system_mail_domain"]:
        cleaned["system_mailbox"] = ""
    else:
        cleaned["system_mailbox"] = product_settings().get("system_mailbox", "")
    cleaned["show_powered_by"] = "1" if bool(payload.get("show_powered_by", True)) else "0"
    mail_hostname_changed = False
    mail_dns_updated = 0
    zones = []
    nameserver_zones = []
    previous_mail = ""
    previous_public_url = ""
    try:
        with db() as c:
            previous_mail = c.execute(
                "SELECT setting_value FROM panel_settings WHERE setting_key='mail_hostname'"
            ).fetchone()
            previous_mail = previous_mail["setting_value"] if previous_mail else ""
            previous_public = c.execute(
                "SELECT setting_value FROM panel_settings WHERE setting_key='public_url'"
            ).fetchone()
            previous_public_url = previous_public["setting_value"] if previous_public else ""
            for key, value in cleaned.items():
                c.execute(
                    "INSERT INTO panel_settings(setting_key,setting_value,updated_at) VALUES(?,?,?) "
                    "ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=excluded.updated_at",
                    (key, value, now()),
                )
            mail_hostname_changed = previous_mail != cleaned["mail_hostname"]
            previous_nameservers = dns_service_nameservers({"public_url": previous_public_url})
            next_nameservers = dns_service_nameservers(cleaned)
            if mail_hostname_changed and cleaned["mail_hostname"]:
                hostname = cleaned["mail_hostname"]
                generated = c.execute(
                    "SELECT id,type,name,value FROM dns_records WHERE mail_domain IS NOT NULL"
                ).fetchall()
                for record in generated:
                    value = None
                    if record["type"] == "MX":
                        value = f"10 {hostname}."
                    elif record["type"] == "TXT" and record["value"].startswith("v=spf1"):
                        value = f"v=spf1 mx a:{hostname} -all"
                    elif record["type"] == "CNAME" and ("autodiscover" in record["name"] or "autoconfig" in record["name"]):
                        value = hostname + "."
                    elif record["type"] == "SRV" and "autodiscover" in record["name"]:
                        value = f"0 0 443 {hostname}."
                    if value is not None and value != record["value"]:
                        c.execute("UPDATE dns_records SET value=? WHERE id=?", (value, record["id"]))
                        mail_dns_updated += 1
                zones = [row["domain"] for row in c.execute(
                    "SELECT DISTINCT domain FROM dns_records WHERE mail_domain IS NOT NULL"
                ).fetchall()]
                for zone in zones:
                    _sync_dns(c, zone, next_nameservers)
            if previous_nameservers != next_nameservers:
                nameserver_zones = [row["domain"] for row in c.execute("SELECT domain FROM domains ORDER BY domain").fetchall()]
                for zone in nameserver_zones:
                    if zone not in zones:
                        _sync_dns(c, zone, next_nameservers)
    except (RuntimeError, sqlite3.Error) as exc:
        audit("settings.update", cleaned["panel_name"], "failed")
        return jsonify(error=str(exc)), 400
    cloudflare_results = []
    for zone in zones:
        cloudflare_results.append(_auto_cloudflare_sync(zone))
    if previous_mail != cleaned["mail_hostname"]:
        if previous_mail: cloudflare_results.append(_auto_cloudflare_service_hostname(previous_mail, remove=True))
        if cleaned["mail_hostname"]: cloudflare_results.append(_auto_cloudflare_service_hostname(cleaned["mail_hostname"]))
    previous_panel_hostname = urlparse(previous_public_url).hostname if previous_public_url else ""
    next_panel_hostname = urlparse(cleaned["public_url"]).hostname if cleaned["public_url"] else ""
    if previous_panel_hostname != next_panel_hostname:
        if previous_panel_hostname: cloudflare_results.append(_auto_cloudflare_service_hostname(previous_panel_hostname, remove=True))
        if next_panel_hostname: cloudflare_results.append(_auto_cloudflare_service_hostname(next_panel_hostname))
    previous_nameservers = dns_service_nameservers({"public_url": previous_public_url})
    next_nameservers = dns_service_nameservers(cleaned)
    if previous_nameservers != next_nameservers:
        for hostname in previous_nameservers:
            if hostname: cloudflare_results.append(_auto_cloudflare_service_hostname(hostname, remove=True))
    for hostname in next_nameservers:
        if hostname: cloudflare_results.append(_auto_cloudflare_service_hostname(hostname))
    owner_routes = None
    if system_mailbox_changed and cleaned.get("system_mailbox"):
        try: owner_routes = _refresh_owner_service_routes(cleaned["system_mailbox"], session["username"])
        except (RuntimeError, sqlite3.Error) as exc:
            audit("settings.system-mail-routes", cleaned["system_mail_domain"], "failed")
            return jsonify(error=f"The owner mailbox was created, but service-address routing failed: {exc}"), 400
    audit("settings.update", cleaned["panel_name"])
    return jsonify(ok=True, mail_hostname_changed=mail_hostname_changed, system_mailbox_changed=system_mailbox_changed, owner_routes=owner_routes, mail_dns_updated=mail_dns_updated, cloudflare_sync=cloudflare_results, **product_settings())


@app.get("/api/users")
@require_auth
@require_admin
def users():
    system_users = helper({"operation": "list"})["users"]
    with db() as c:
        accounts = {
            row["system_username"]: dict(row)
            for row in c.execute(
                "SELECT a.username,a.role,a.system_username,a.active,a.domain_limit,a.allow_domain_creation,"
                "COUNT(d.domain) AS domain_count FROM accounts a LEFT JOIN domains d ON d.owner=a.system_username "
                "WHERE a.system_username IS NOT NULL GROUP BY a.username"
            ).fetchall()
        }
    for user in system_users:
        account = accounts.get(user.get("username"))
        user["panel_username"] = account["username"] if account else None
        user["panel_role"] = account["role"] if account else None
        user["panel_active"] = bool(account and account["active"])
        user["domain_limit"] = account["domain_limit"] if account else 0
        user["domain_count"] = account["domain_count"] if account else 0
        user["allow_domain_creation"] = bool(account and account["allow_domain_creation"])
        user["can_impersonate"] = bool(
            account and account["role"] == "client" and account["active"] and not user.get("protected")
        )
    return jsonify(users=system_users)


@app.get("/api/users/<username>/hosting")
@require_auth
@require_admin
def get_user_hosting(username):
    with db() as c:
        account = c.execute(
            "SELECT username,system_username,active,domain_limit,disk_limit_mb,allow_domain_creation,package_id "
            "FROM accounts WHERE username=? AND role='client'",
            (username,),
        ).fetchone()
        if not account:
            return jsonify(error="Client account not found."), 404
        linked = c.execute(
            "SELECT domain,suspended,ssl_mode,created_at FROM domains WHERE owner=? ORDER BY domain",
            (account["system_username"],),
        ).fetchall()
        overrides = {row["feature_key"]: bool(row["enabled"]) for row in c.execute("SELECT feature_key,enabled FROM account_feature_overrides WHERE username=?", (username,))}
        effective = _effective_features(c, username)
    return jsonify(account=dict(account), domains=[dict(row) for row in linked], feature_catalog=FEATURE_CATALOG, feature_overrides=overrides, effective_features=effective)


@app.put("/api/users/<username>/hosting")
@require_auth
@require_admin
@require_csrf
def update_user_hosting(username):
    payload = request.get_json(silent=True) or {}
    try:
        domain_limit = int(payload.get("domain_limit", 10))
        disk_limit_mb = int(payload.get("disk_limit_mb", 10240))
    except (TypeError, ValueError):
        return jsonify(error="Domain and storage limits must be numbers."), 400
    if domain_limit < 0 or domain_limit > 1000:
        return jsonify(error="Domain limit must be between 0 and 1000."), 400
    if disk_limit_mb < 128 or disk_limit_mb > 10485760:
        return jsonify(error="Storage allocation must be between 128 MB and 10 TB."), 400
    with db() as c:
        account = c.execute(
            "SELECT system_username FROM accounts WHERE username=? AND role='client'",
            (username,),
        ).fetchone()
        if not account:
            return jsonify(error="Client account not found."), 404
        current_count = c.execute(
            "SELECT COUNT(*) AS total FROM domains WHERE owner=?", (account["system_username"],)
        ).fetchone()["total"]
        if domain_limit < current_count:
            return jsonify(error="Domain limit cannot be lower than the client's current domain count."), 400
        c.execute(
            "UPDATE accounts SET domain_limit=?,disk_limit_mb=?,allow_domain_creation=? WHERE username=?",
            (domain_limit, disk_limit_mb, 1 if payload.get("allow_domain_creation", True) else 0, username),
        )
    audit("user.hosting_update", username)
    return jsonify(ok=True)


@app.post("/api/users")
@require_auth
@require_admin
@require_csrf
def create_user():
    if limited((session["username"], "create-user"), 10, 3600):
        return jsonify(error="User creation rate limit reached."), 429

    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    password = payload.get("password", "")
    shell = payload.get("shell", "/usr/sbin/nologin")
    if not USERNAME.fullmatch(username) or shell not in SHELLS:
        return jsonify(error="Invalid account details."), 400
    if password != payload.get("confirm_password") or len(password) < 12:
        return jsonify(error="Passwords must match and contain at least 12 characters."), 400

    with db() as c:
        if c.execute("SELECT 1 FROM accounts WHERE username=?", (username,)).fetchone():
            return jsonify(error="That panel username already exists."), 409

    try:
        helper(
            {
                "operation": "create",
                "username": username,
                "display_name": payload.get("display_name", ""),
                "password": password,
                "shell": shell,
            }
        )
        try:
            with db() as c:
                c.execute(
                    "INSERT INTO accounts(username,password_hash,role,system_username,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (username, ph.hash(password), "client", username, now()),
                )
        except Exception:
            helper({"operation": "remove", "username": username})
            raise
        audit("user.create", username)
        return jsonify(ok=True), 201
    except (RuntimeError, sqlite3.Error) as exc:
        audit("user.create", username, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/users/<username>/impersonate")
@require_auth
@require_admin
@require_csrf
def impersonate_user(username):
    if session.get("_impersonating_as"):
        return jsonify(error="You are already impersonating a user. Stop that session first."), 409
    admin_username = session["username"]
    with db() as c:
        target = c.execute(
            "SELECT username,system_username FROM accounts WHERE username=? AND role='client' AND active=1",
            (username,),
        ).fetchone()
        if not target:
            return jsonify(error="Client account not found."), 404
    try:
        _start_impersonation(target)
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 400
    audit("user.impersonate", username, actor=admin_username)
    return jsonify(
        username=session["username"],
        role=session["role"],
        system_username=session["system_username"],
        csrf=session["csrf"],
        impersonating_as=session["_impersonating_as"],
        impersonator=admin_username,
        features=_session_features(),
    )


@app.post("/api/impersonation/stop")
@require_auth
@require_csrf
def stop_impersonation():
    if session.get("role") == "admin" and not session.get("_impersonating_as"):
        return jsonify(error="No impersonation session active."), 400
    actor = session.get("_impersonator_username", session.get("username"))
    if _stop_impersonation():
        audit("user.impersonation_stop", session.get("username", "unknown"), actor=actor)
        return jsonify(
            username=session["username"],
            role=session["role"],
            system_username=session["system_username"],
            csrf=session["csrf"],
            impersonating_as=None,
            impersonator=None,
            features=_session_features(),
        )
    return jsonify(error="No impersonation session active."), 400


@app.post("/api/users/<username>/lock")
@require_auth
@require_admin
@require_csrf
def lock_user(username):
    configured = []
    try:
        with db() as c:
            account = c.execute("SELECT username,system_username,active FROM accounts WHERE system_username=? AND role='client'", (username,)).fetchone()
            if not account: return jsonify(error="Client account not found."), 404
            domains = [dict(row) for row in c.execute(
                "SELECT d.domain,d.owner,d.webroot,d.ssl_mode,d.suspended,EXISTS(SELECT 1 FROM app_installations a WHERE a.domain=d.domain AND a.app_type='wordpress') AS wordpress FROM domains d WHERE d.owner=? ORDER BY d.domain",
                (username,),
            )]
            addresses = [row["full_email"] for row in c.execute(
                "SELECT e.full_email FROM email_accounts e JOIN mail_domains m ON m.domain=COALESCE(e.mail_domain,e.domain) WHERE m.owner=? ORDER BY e.full_email",
                (username,),
            )]
        helper({"operation":"grommunio_account_access", "addresses":addresses, "enabled":False})
        for row in domains:
            helper({"operation":"domain_config", "domain":row["domain"], "owner":row["owner"], "webroot":row["webroot"], "ssl_mode":row["ssl_mode"], "suspended":True, "wordpress":bool(row["wordpress"])})
            configured.append(row)
        helper({"operation": "lock", "username": username})
        with db() as c:
            c.execute("DELETE FROM account_suspension_domains WHERE username=?", (username,))
            for row in domains:
                c.execute("INSERT INTO account_suspension_domains(username,domain,was_suspended) VALUES(?,?,?)", (username,row["domain"],int(bool(row["suspended"]))))
            c.execute("UPDATE domains SET suspended=1 WHERE owner=?", (username,))
            c.execute("UPDATE accounts SET active=0 WHERE system_username=? AND role='client'", (username,))
        audit("user.lock", username)
        return jsonify(ok=True, websites_suspended=len(domains), mailboxes_restricted=len(addresses), incoming_mail=True)
    except RuntimeError as exc:
        for row in reversed(configured):
            try: helper({"operation":"domain_config", "domain":row["domain"], "owner":row["owner"], "webroot":row["webroot"], "ssl_mode":row["ssl_mode"], "suspended":bool(row["suspended"]), "wordpress":bool(row["wordpress"])})
            except RuntimeError: pass
        try: helper({"operation":"grommunio_account_access", "addresses":addresses if 'addresses' in locals() else [], "enabled":True})
        except RuntimeError: pass
        audit("user.lock", username, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/users/<username>/unlock")
@require_auth
@require_admin
@require_csrf
def unlock_user(username):
    configured = []
    try:
        with db() as c:
            account = c.execute("SELECT username,system_username,active FROM accounts WHERE system_username=? AND role='client'", (username,)).fetchone()
            if not account: return jsonify(error="Client account not found."), 404
            domains = [dict(row) for row in c.execute(
                "SELECT d.domain,d.owner,d.webroot,d.ssl_mode,COALESCE(s.was_suspended,0) AS restore_suspended,EXISTS(SELECT 1 FROM app_installations a WHERE a.domain=d.domain AND a.app_type='wordpress') AS wordpress FROM domains d LEFT JOIN account_suspension_domains s ON s.username=? AND s.domain=d.domain WHERE d.owner=? ORDER BY d.domain",
                (username,username),
            )]
            addresses = [row["full_email"] for row in c.execute(
                "SELECT e.full_email FROM email_accounts e JOIN mail_domains m ON m.domain=COALESCE(e.mail_domain,e.domain) WHERE m.owner=? ORDER BY e.full_email",
                (username,),
            )]
        helper({"operation": "unlock", "username": username})
        helper({"operation":"grommunio_account_access", "addresses":addresses, "enabled":True})
        for row in domains:
            helper({"operation":"domain_config", "domain":row["domain"], "owner":row["owner"], "webroot":row["webroot"], "ssl_mode":row["ssl_mode"], "suspended":bool(row["restore_suspended"]), "wordpress":bool(row["wordpress"])})
            configured.append(row)
        with db() as c:
            for row in domains: c.execute("UPDATE domains SET suspended=? WHERE domain=?", (int(bool(row["restore_suspended"])),row["domain"]))
            c.execute("DELETE FROM account_suspension_domains WHERE username=?", (username,))
            c.execute("UPDATE accounts SET active=1 WHERE system_username=? AND role='client'", (username,))
        audit("user.unlock", username)
        return jsonify(ok=True, websites_restored=len(domains), mailboxes_restored=len(addresses))
    except RuntimeError as exc:
        for row in reversed(configured):
            try: helper({"operation":"domain_config", "domain":row["domain"], "owner":row["owner"], "webroot":row["webroot"], "ssl_mode":row["ssl_mode"], "suspended":True, "wordpress":bool(row["wordpress"])})
            except RuntimeError: pass
        try: helper({"operation":"grommunio_account_access", "addresses":addresses if 'addresses' in locals() else [], "enabled":False})
        except RuntimeError: pass
        try: helper({"operation":"lock", "username":username})
        except RuntimeError: pass
        audit("user.unlock", username, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/users/<username>/password")
@require_auth
@require_admin
@require_csrf
def set_user_password(username):
    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    confirm = payload.get("confirm_password", "")
    if password != confirm or len(password) < 12:
        return jsonify(error="Passwords must match and contain at least 12 characters."), 400
    try:
        helper({"operation": "password", "username": username, "password": password})
        with db() as c:
            c.execute("UPDATE accounts SET password_hash=? WHERE username=?", (ph.hash(password), username))
        audit("user.password", username)
        return jsonify(ok=True)
    except (RuntimeError, sqlite3.Error) as exc:
        audit("user.password", username, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/account/password")
@require_auth
@require_csrf
def set_account_password():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", session["username"])
    current_password = payload.get("current_password", "")
    password = payload.get("password", "")
    confirm = payload.get("confirm_password", "")

    if username != session["username"] and session.get("role") != "admin":
        return jsonify(error="Administrator access required to change another account."), 403
    if password != confirm or len(password) < 12:
        return jsonify(error="Passwords must match and contain at least 12 characters."), 400

    with db() as c:
        row = c.execute(
            "SELECT username,system_username,role,password_hash FROM accounts WHERE username=?",
            (username,),
        ).fetchone()
        if not row:
            return jsonify(error="Account not found."), 404

        if session["role"] != "admin" and row["username"] == session["username"]:
            if not current_password:
                return jsonify(error="Current password is required."), 400
            try:
                if not ph.verify(row["password_hash"], current_password):
                    return jsonify(error="Current password is incorrect."), 401
            except VerifyMismatchError:
                return jsonify(error="Current password is incorrect."), 401

        try:
            if row["role"] == "client" and row["system_username"]:
                helper({
                    "operation": "password",
                    "username": username,
                    "password": password,
                })
            with db() as writer:
                writer.execute("UPDATE accounts SET password_hash=? WHERE username=?", (ph.hash(password), username))
        except RuntimeError as exc:
            audit("account.password", username, "failed")
            return jsonify(error=str(exc)), 400
        except sqlite3.Error as exc:
            audit("account.password", username, "failed")
            return jsonify(error=str(exc)), 400

    audit("account.password", username)
    return jsonify(ok=True)


@app.delete("/api/users/<username>")
@require_auth
@require_admin
@require_csrf
def delete_user(username):
    with db() as c:
        account = c.execute("SELECT system_username FROM accounts WHERE username=? AND role='client'", (username,)).fetchone()
        if not account:
            return jsonify(error="Client account not found."), 404
        domain_count = c.execute("SELECT COUNT(*) AS total FROM domains WHERE owner=?", (account["system_username"],)).fetchone()["total"]
        if domain_count:
            return jsonify(error="Remove this client's websites before deleting the account."), 409
    try:
        helper({"operation": "remove", "username": username})
    except RuntimeError as exc:
        audit("user.delete", username, "failed")
        return jsonify(error=str(exc)), 400
    with db() as c:
        c.execute("DELETE FROM accounts WHERE username=?", (username,))
    audit("user.delete", username)
    return jsonify(ok=True)


@app.get("/api/domains")
@require_auth
def domains():
    with db() as c:
        if session["role"] == "admin":
            rows = c.execute(
                "SELECT domain,owner,webroot,suspended,ssl_mode,created_at "
                "FROM domains ORDER BY domain"
            ).fetchall()
            limits = None
        else:
            rows = c.execute(
                "SELECT domain,owner,webroot,suspended,ssl_mode,created_at "
                "FROM domains WHERE owner=? ORDER BY domain",
                (session.get("system_username"),),
            ).fetchall()
            limits = c.execute(
                "SELECT domain_limit,allow_domain_creation FROM accounts WHERE username=?",
                (session["username"],),
            ).fetchone()
    return jsonify(
        domains=[{**dict(r), "is_root": is_root_domain(r["domain"])} for r in rows],
        domain_limit=limits["domain_limit"] if limits else None,
        allow_domain_creation=bool(limits["allow_domain_creation"]) if limits else True,
    )


@app.get("/api/mail/domains")
@require_auth
def list_mail_domains():
    with db() as c:
        if session["role"] == "admin":
            rows = c.execute("SELECT domain,zone_domain,owner,status,grommunio_managed,created_at FROM mail_domains ORDER BY domain").fetchall()
        else:
            rows = c.execute("SELECT domain,zone_domain,owner,status,grommunio_managed,created_at FROM mail_domains WHERE owner=? ORDER BY domain", (session.get("system_username"),)).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["is_root"] = is_root_domain(row["domain"])
            item["dns_parent"] = row["zone_domain"]
            item["mail_only"] = row["domain"] != row["zone_domain"]
            items.append(item)
    return jsonify(domains=items)


@app.post("/api/mail/domains")
@require_auth
@require_csrf
def create_mail_domain():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    owner = str(payload.get("owner", "")) if session["role"] == "admin" else session.get("system_username", "")
    if not DOMAIN.fullmatch(domain) or not USERNAME.fullmatch(owner):
        return jsonify(error="Enter a valid email domain and owner."), 400
    with db() as c:
        if c.execute("SELECT 1 FROM mail_domains WHERE domain=?", (domain,)).fetchone():
            return jsonify(error="That domain is already available for email."), 409
        account = c.execute("SELECT 1 FROM accounts WHERE system_username=? AND role='client' AND active=1", (owner,)).fetchone()
        if not account: return jsonify(error="Owner must be an active panel client."), 400
        parent = _parent_website_domain(c, domain, owner)
        if not parent or domain == parent:
            return jsonify(error="A mail-only domain must be a subdomain of one of this client's hosted website domains."), 400
        if domain == product_settings().get("mail_hostname", ""):
            return jsonify(error="The central mail server domain cannot also be a customer email domain."), 409
    mail_created = False
    try:
        mail_created = bool(helper({"operation":"grommunio_domain_create", "domain":domain}).get("created"))
        with db() as c:
            c.execute("INSERT INTO mail_domains(domain,zone_domain,owner,status,grommunio_managed,created_at,created_by) VALUES(?,?,?,'active',?,?,?)",
                      (domain, parent, owner, int(mail_created), now(), session["username"]))
        audit("mail.domain.create", domain)
        return jsonify(ok=True, domain=domain, dns_parent=parent), 201
    except (RuntimeError, sqlite3.Error) as exc:
        if mail_created:
            try: helper({"operation":"grommunio_domain_delete", "domain":domain})
            except RuntimeError: pass
        audit("mail.domain.create", domain, "failed")
        return jsonify(error=str(exc)), 400


@app.delete("/api/mail/domains/<path:domain>")
@require_auth
@require_csrf
def delete_mail_domain(domain):
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = c.execute("SELECT owner,zone_domain,grommunio_managed FROM mail_domains WHERE domain=?", (domain,)).fetchone()
        if not row or row["zone_domain"] == domain: return jsonify(error="Mail-only subdomain not found."), 404
        if session["role"] != "admin" and row["owner"] != session.get("system_username"): return jsonify(error="No access to that email domain."), 403
        if c.execute("SELECT 1 FROM email_accounts WHERE mail_domain=?", (domain,)).fetchone():
            return jsonify(error="Delete this domain's mailboxes and forwarding addresses first."), 409
    grommunio_purged = False
    try:
        grommunio = helper({"operation":"grommunio_domain_users", "domain":domain})
        if grommunio.get("user_count", 0):
            return jsonify(error="This email domain still contains Grommunio users. Delete or move them before removing the domain."), 409
        if row["grommunio_managed"]:
            helper({"operation":"grommunio_domain_delete", "domain":domain})
            grommunio_purged = True
        with db() as c:
            c.execute("DELETE FROM dns_records WHERE mail_domain=?", (domain,))
            c.execute("DELETE FROM mail_domains WHERE domain=?", (domain,))
            _sync_dns(c, row["zone_domain"])
        cloudflare = _auto_cloudflare_sync(row["zone_domain"])
        audit("mail.domain.delete", domain)
        return jsonify(ok=True, cloudflare=cloudflare)
    except (RuntimeError, sqlite3.Error) as exc:
        if grommunio_purged:
            try: helper({"operation":"grommunio_domain_create", "domain":domain})
            except RuntimeError: pass
        audit("mail.domain.delete", domain, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/domains")
@require_auth
@require_csrf
def create_domain():
    if limited((session["username"], "create-domain"), 20, 3600):
        return jsonify(error="Website creation rate limit reached."), 429

    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    owner = payload.get("owner", "") if session["role"] == "admin" else session.get("system_username", "")
    if not DOMAIN.fullmatch(domain) or not USERNAME.fullmatch(owner):
        return jsonify(error="Enter a valid domain and owner."), 400
    if not is_root_domain(domain):
        return jsonify(error="Website domains must be registrable root domains. Add subdomains from Email & Groupware when they are only used for mail."), 400
    with db() as c:
        entitlement = license_status(c)
        if not entitlement["can_add_domain"]:
            return jsonify(
                error=f"MassPanel Community supports up to {COMMUNITY_DOMAIN_LIMIT} hosted domains. Activate Unlimited to add more; existing services remain online.",
                license=entitlement,
            ), 402
        account = c.execute(
            "SELECT domain_limit,allow_domain_creation FROM accounts "
            "WHERE system_username=? AND role='client' AND active=1",
            (owner,),
        ).fetchone()
        exists = c.execute("SELECT 1 FROM domains WHERE domain=?", (domain,)).fetchone()
        if not account:
            return jsonify(error="Owner must be an active panel client."), 400
        if exists:
            return jsonify(error="That domain already exists."), 409
        if session["role"] != "admin" and not account["allow_domain_creation"]:
            return jsonify(error="Your hosting plan does not allow adding domains."), 403
        count = c.execute("SELECT COUNT(*) AS total FROM domains WHERE owner=?", (owner,)).fetchone()["total"]
        if count >= account["domain_limit"]:
            return jsonify(error="This account has reached its domain limit."), 409

    result = None
    mail_created = False
    try:
        result = helper({"operation": "domain_create", "domain": domain, "owner": owner})
        mail_created = bool(helper({"operation": "grommunio_domain_create", "domain": domain}).get("created"))
        with db() as c:
            c.execute(
                "INSERT INTO domains(domain,owner,webroot,suspended,ssl_mode,created_at,created_by) "
                "VALUES(?,?,?,?,?,?,?)",
                (domain, owner, result["webroot"], 0, "disabled", now(), session["username"]),
            )
            c.execute(
                "INSERT OR IGNORE INTO mail_domains(domain,zone_domain,owner,status,grommunio_managed,created_at,created_by) VALUES(?,?,?,'active',?,?,?)",
                (domain, domain, owner, int(mail_created), now(), session["username"]),
            )
            _sync_dns(c, domain)
        cloudflare = _auto_cloudflare_sync(domain)
        audit("domain.create", domain)
        return jsonify(ok=True, cloudflare=cloudflare), 201
    except (RuntimeError, sqlite3.Error) as exc:
        if result and result.get("webroot"):
            try:
                helper({"operation": "domain_delete", "domain": domain, "owner": owner, "webroot": result["webroot"]})
                if mail_created: helper({"operation": "grommunio_domain_delete", "domain": domain})
            except RuntimeError:
                pass
        audit("domain.create", domain, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/domains/<path:domain>/suspend")
@require_auth
@require_admin
@require_csrf
def suspend_domain(domain):
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = c.execute("SELECT domain,owner,webroot,ssl_mode FROM domains WHERE domain=?", (domain,)).fetchone()
        if not row:
            return jsonify(error="Domain not found."), 404
        wordpress = bool(c.execute("SELECT 1 FROM app_installations WHERE domain=? AND app_type='wordpress'", (domain,)).fetchone())
        try:
            helper({"operation": "domain_config", "domain": domain, "owner": row["owner"], "webroot": row["webroot"], "ssl_mode": row["ssl_mode"], "suspended": True, "wordpress": wordpress})
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        c.execute("UPDATE domains SET suspended=1 WHERE domain=?", (domain,))
    audit("domain.suspend", domain)
    return jsonify(ok=True)


@app.post("/api/domains/<path:domain>/unsuspend")
@require_auth
@require_admin
@require_csrf
def unsuspend_domain(domain):
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = c.execute("SELECT domain,owner,webroot,ssl_mode FROM domains WHERE domain=?", (domain,)).fetchone()
        if not row:
            return jsonify(error="Domain not found."), 404
        wordpress = bool(c.execute("SELECT 1 FROM app_installations WHERE domain=? AND app_type='wordpress'", (domain,)).fetchone())
        try:
            helper({"operation": "domain_config", "domain": domain, "owner": row["owner"], "webroot": row["webroot"], "ssl_mode": row["ssl_mode"], "suspended": False, "wordpress": wordpress})
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        c.execute("UPDATE domains SET suspended=0 WHERE domain=?", (domain,))
    audit("domain.unsuspend", domain)
    return jsonify(ok=True)


@app.post("/api/domains/<path:domain>/ssl")
@require_auth
@require_csrf
def set_domain_ssl(domain):
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode", "disabled")
    if mode not in SSL_MODES:
        return jsonify(error="Invalid SSL mode."), 400
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username", ""))
        if not row:
            return jsonify(error="Domain not found or access denied."), 404
        state = c.execute("SELECT suspended FROM domains WHERE domain=?", (domain,)).fetchone()
        wordpress = bool(c.execute("SELECT 1 FROM app_installations WHERE domain=? AND app_type='wordpress'", (domain,)).fetchone())
        try:
            helper({"operation": "domain_config", "domain": domain, "owner": row["owner"], "webroot": row["webroot"], "ssl_mode": mode, "suspended": bool(state["suspended"]), "wordpress": wordpress, "email": product_settings().get("support_email", "")})
        except RuntimeError as exc:
            audit("domain.ssl", domain, "failed")
            return jsonify(error=str(exc)), 400
        c.execute("UPDATE domains SET ssl_mode=? WHERE domain=?", (mode, domain))
    audit("domain.ssl", domain)
    return jsonify(ok=True, mode=mode)


@app.delete("/api/domains/<path:domain>")
@require_auth
@require_admin
@require_csrf
def delete_domain(domain):
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = c.execute(
            "SELECT d.owner,d.webroot,COALESCE(m.grommunio_managed,0) AS grommunio_managed "
            "FROM domains d LEFT JOIN mail_domains m ON m.domain=d.domain WHERE d.domain=?",
            (domain,),
        ).fetchone()
        if not row:
            return jsonify(error="Domain not found."), 404
        child_mail = c.execute("SELECT domain FROM mail_domains WHERE zone_domain=? AND domain<>zone_domain", (domain,)).fetchone()
        if child_mail:
            return jsonify(error=f"Delete the email subdomain {child_mail['domain']} from Email & Groupware first."), 409
        if c.execute("SELECT 1 FROM email_accounts WHERE domain=?", (domain,)).fetchone():
            return jsonify(error="Delete this website domain's mailboxes and forwarding addresses first."), 409
        app_row = c.execute("SELECT db_name,db_user FROM app_installations WHERE domain=?", (domain,)).fetchone()
        backup_files = [Path(item["filename"]) for item in c.execute("SELECT filename FROM backups WHERE domain=?", (domain,)).fetchall()]
        database_files = [Path(item["path"]) for item in c.execute("SELECT path FROM user_databases WHERE domain=?", (domain,)).fetchall()]
        grommunio_purged = False
        try:
            grommunio = helper({"operation":"grommunio_domain_users", "domain":domain})
            if grommunio.get("user_count", 0):
                return jsonify(error="This website's email domain still contains Grommunio users. Delete or move them first."), 409
            if row["grommunio_managed"]:
                helper({"operation": "grommunio_domain_delete", "domain": domain})
                grommunio_purged = True
            helper({"operation": "domain_delete", "domain": domain, "owner": row["owner"], "webroot": row["webroot"], "db_name": app_row["db_name"] if app_row else "", "db_user": app_row["db_user"] if app_row else ""})
        except RuntimeError as exc:
            if grommunio_purged:
                try: helper({"operation":"grommunio_domain_create", "domain":domain})
                except RuntimeError: pass
            return jsonify(error=str(exc)), 400
        c.execute("DELETE FROM backups WHERE domain=?", (domain,))
        c.execute("DELETE FROM user_databases WHERE domain=?", (domain,))
        c.execute("DELETE FROM domains WHERE domain=?", (domain,))
    for target in backup_files + database_files:
        try:
            if target.is_file(): target.unlink()
        except OSError:
            pass
    cloudflare = _auto_cloudflare_sync(domain, records=[], ensure_apex=False, prune=True, adopt_legacy=True)
    audit("domain.delete", domain)
    return jsonify(ok=True, cloudflare=cloudflare)


@app.get("/api/domains/<path:domain>/redirects")
@require_auth
def list_website_redirects(domain):
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username", ""))
        if not row: return jsonify(error="Website not found or access denied."), 404
        redirects = c.execute("SELECT id,domain,source_path,target_url,status_code,created_at FROM website_redirects WHERE domain=? ORDER BY source_path", (domain,)).fetchall()
    return jsonify(redirects=[dict(item) for item in redirects])


@app.post("/api/domains/<path:domain>/redirects")
@require_auth
@require_csrf
def create_website_redirect(domain):
    domain = domain.lower().strip().strip(".")
    payload = request.get_json(silent=True) or {}
    source = str(payload.get("source_path", "")).strip()
    target = str(payload.get("target_url", "")).strip()
    try: status_code = int(payload.get("status_code", 301))
    except (TypeError, ValueError): return jsonify(error="Choose a valid redirect type."), 400
    parsed = urlparse(target)
    if (not source.startswith("/") or len(source) > 1024 or any(ord(ch) < 32 or ch.isspace() or ch in '{};\"?#\\' for ch in source)
            or parsed.scheme not in {"http","https"} or not parsed.netloc or parsed.fragment or parsed.username or parsed.password or len(target) > 2048
            or any(ord(ch) < 32 or ch.isspace() or ch in '${};\"\\' for ch in target) or status_code not in {301,302,307,308}):
        return jsonify(error="Enter a safe source path and a complete HTTP or HTTPS destination."), 400
    try:
        with db() as c:
            row = _domain_context(c, domain, session.get("system_username", ""))
            if not row: return jsonify(error="Website not found or access denied."), 404
            cursor = c.execute("INSERT INTO website_redirects(domain,source_path,target_url,status_code,created_at,created_by) VALUES(?,?,?,?,?,?)", (domain,source,target,status_code,now(),session["username"]))
            _sync_website_rules(c, domain)
        audit("website.redirect.create", f"{domain}{source}")
        return jsonify(ok=True,id=cursor.lastrowid), 201
    except sqlite3.IntegrityError: return jsonify(error="A redirect already exists for that source path."), 409
    except RuntimeError as exc: return jsonify(error=str(exc)), 400


@app.delete("/api/domains/<path:domain>/redirects/<int:redirect_id>")
@require_auth
@require_csrf
def delete_website_redirect(domain, redirect_id):
    domain = domain.lower().strip().strip(".")
    try:
        with db() as c:
            row = _domain_context(c, domain, session.get("system_username", ""))
            if not row: return jsonify(error="Website not found or access denied."), 404
            cursor = c.execute("DELETE FROM website_redirects WHERE id=? AND domain=?", (redirect_id,domain))
            if not cursor.rowcount: return jsonify(error="Redirect not found."), 404
            _sync_website_rules(c, domain)
        audit("website.redirect.delete", f"{domain}:{redirect_id}")
        return jsonify(ok=True)
    except RuntimeError as exc: return jsonify(error=str(exc)), 400


@app.get("/api/apps")
@require_auth
def list_apps():
    owner = session.get("system_username", "")
    with db() as c:
        if session["role"] == "admin":
            rows = c.execute(
                "SELECT a.*,d.suspended FROM app_installations a JOIN domains d ON d.domain=a.domain ORDER BY a.domain"
            ).fetchall()
            domains = c.execute(
                "SELECT d.domain,d.owner FROM domains d LEFT JOIN app_installations a ON a.domain=d.domain "
                "WHERE a.id IS NULL AND d.suspended=0 ORDER BY d.domain"
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT a.*,d.suspended FROM app_installations a JOIN domains d ON d.domain=a.domain "
                "WHERE a.owner=? ORDER BY a.domain", (owner,),
            ).fetchall()
            domains = c.execute(
                "SELECT d.domain,d.owner FROM domains d LEFT JOIN app_installations a ON a.domain=d.domain "
                "WHERE d.owner=? AND a.id IS NULL AND d.suspended=0 ORDER BY d.domain", (owner,),
            ).fetchall()
    apps = [dict(row) for row in rows]
    for item in apps:
        metadata = APP_CATALOG.get(item.get("application_slug") or "wordpress", APP_CATALOG["wordpress"])
        item["catalog"] = metadata
    return jsonify(apps=apps, available_domains=[dict(row) for row in domains], catalog=list(APP_CATALOG.values()))


@app.post("/api/apps/wordpress")
@app.post("/api/apps/install/<slug>")
@require_auth
@require_csrf
def install_wordpress(slug="wordpress"):
    application = APP_CATALOG.get(str(slug).lower())
    if not application: return jsonify(error="Application is not available in this catalog."), 404
    if limited((session["username"], "wordpress-install"), 5, 3600):
        return jsonify(error="Application installation rate limit reached."), 429
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    with db() as c:
        context = _domain_context(c, domain, session.get("system_username", ""))
        if not context:
            return jsonify(error="Website not found or access denied."), 404
        if c.execute("SELECT 1 FROM app_installations WHERE domain=?", (domain,)).fetchone():
            return jsonify(error="An application is already installed on this website."), 409
        stamp = now()
        try:
            app_id = c.execute(
                "INSERT INTO app_installations(domain,owner,app_type,application_slug,version,admin_user,db_name,db_user,maintenance,status,installed_at,updated_at,installed_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (domain,context["owner"],"wordpress",application["slug"],"pending","pending","pending","pending",0,"installing",stamp,stamp,session["username"]),
            ).lastrowid
        except sqlite3.IntegrityError:
            return jsonify(error="An application installation is already in progress for this website."), 409
    request_data = {
        "operation": "wordpress_install" if application["engine"] == "wordpress" else "application_install", "domain": domain, "owner": context["owner"],
        "webroot": context["webroot"], "title": str(payload.get("title", "")).strip() or domain,
        "admin_user": str(payload.get("admin_user", "")).strip(),
        "admin_email": str(payload.get("admin_email", "")).strip(),
        "admin_password": str(payload.get("admin_password", "")), "application_slug":application["slug"],
    }
    try:
        result = helper(request_data)
        with db() as c:
            changed = c.execute(
                "UPDATE app_installations SET version=?,admin_user=?,db_name=?,db_user=?,status='active',updated_at=? WHERE id=? AND status='installing'",
                (result["version"],result["admin_user"],result["db_name"],result["db_user"],now(),app_id),
            )
            if changed.rowcount != 1: raise sqlite3.IntegrityError("Application reservation was lost.")
            c.execute("UPDATE domains SET ssl_mode=? WHERE domain=?", (result.get("ssl_mode", "self"), domain))
        audit("app.install", f"{application['slug']}:{domain}")
        return jsonify(ok=True, id=app_id, domain=domain, application=application, version=result["version"]), 201
    except (RuntimeError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        if isinstance(exc, (RuntimeError, subprocess.TimeoutExpired)):
            with db() as c: c.execute("DELETE FROM app_installations WHERE id=? AND status='installing'", (app_id,))
        audit("app.wordpress.install", domain, "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/apps/<int:app_id>/action")
@require_auth
@require_csrf
def manage_app(app_id):
    payload = request.get_json(silent=True) or {}
    action = str(payload.get("action", ""))
    if action not in {"update", "maintenance_on", "maintenance_off"}:
        return jsonify(error="Unsupported application action."), 400
    with db() as c:
        row = c.execute("SELECT * FROM app_installations WHERE id=?", (app_id,)).fetchone()
        if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")):
            return jsonify(error="Application not found or access denied."), 404
        if row["status"] != "active": return jsonify(error="This application installation is not ready for management."), 409
    try:
        slug = row["application_slug"] or "wordpress"
        operation = "wordpress_action" if APP_CATALOG.get(slug, {}).get("engine") == "wordpress" else "application_action"
        result = helper({"operation": operation, "application_slug":slug, "owner": row["owner"], "domain": row["domain"], "action": action})
        maintenance = 1 if action == "maintenance_on" else 0 if action == "maintenance_off" else row["maintenance"]
        with db() as c:
            c.execute("UPDATE app_installations SET version=?,maintenance=?,updated_at=? WHERE id=?", (result["version"], maintenance, now(), app_id))
        audit("app.wordpress." + action, row["domain"])
        return jsonify(ok=True, version=result["version"], maintenance=maintenance)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        audit("app.wordpress." + action, row["domain"], "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/apps/<int:app_id>/impersonate")
@require_auth
@require_csrf
def impersonate_wordpress(app_id):
    if limited((session["username"], "wordpress-impersonate"), 30, 3600):
        return jsonify(error="WordPress administrator access rate limit reached."), 429
    with db() as c:
        row = c.execute(
            "SELECT a.id,a.domain,a.owner,a.admin_user,a.status,d.suspended "
            "FROM app_installations a JOIN domains d ON d.domain=a.domain WHERE a.id=? AND a.application_slug IN ('wordpress','woocommerce','elementor','bbpress')",
            (app_id,),
        ).fetchone()
        if not row: return jsonify(error="WordPress installation not found."), 404
        if session["role"] != "admin" and row["owner"] != session.get("system_username"):
            return jsonify(error="WordPress installation not found or access denied."), 404
        if row["status"] != "active" or row["suspended"]: return jsonify(error="Only active WordPress sites can be opened."), 409
    try:
        helper({"operation":"wordpress_sso_install", "owner":row["owner"], "domain":row["domain"]})
    except RuntimeError as exc:
        audit("app.wordpress.impersonate.request", row["domain"], "failed")
        return jsonify(error=str(exc)), 400
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with db() as c:
        c.execute("DELETE FROM wordpress_impersonation_tokens WHERE expires_at < ? OR used_at IS NOT NULL", (int(time.time()),))
        c.execute(
            "INSERT INTO wordpress_impersonation_tokens(token_hash,app_id,domain,admin_user,admin_username,expires_at,created_at) VALUES(?,?,?,?,?,?,?)",
            (token_hash,row["id"],row["domain"],row["admin_user"],session["username"],int(time.time()) + 60,now()),
        )
    audit("app.wordpress.impersonate.request", row["domain"])
    return jsonify(ok=True, launch_url=f"/api/apps/impersonation/launch?token={raw_token}")


@app.get("/api/apps/impersonation/launch")
@require_auth
def launch_wordpress_impersonation():
    token = str(request.args.get("token", ""))
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row = c.execute("SELECT domain,admin_username,expires_at,used_at FROM wordpress_impersonation_tokens WHERE token_hash=?", (token_hash,)).fetchone()
    if not row or row["used_at"] or row["expires_at"] < int(time.time()) or row["admin_username"] != session["username"]:
        return Response("This WordPress handoff is invalid or expired.", status=410)
    return Response(f"<!doctype html><meta name=referrer content=no-referrer><meta name=viewport content='width=device-width'><title>Opening WordPress</title><body style='font:16px system-ui;display:grid;place-items:center;min-height:80vh'><form id=f method=post action='https://{html.escape(row['domain'], quote=True)}/?masspanel_impersonate=1'><input type=hidden name=token value='{html.escape(token, quote=True)}'><p>Opening WordPress securely…</p><noscript><button>Continue</button></noscript></form><script>document.getElementById('f').submit()</script></body>", content_type="text/html; charset=utf-8", headers={"Cache-Control":"no-store"})


@app.post("/api/apps/impersonation/exchange")
def exchange_wordpress_impersonation():
    if request.remote_addr not in {"127.0.0.1", "::1"} or request.host not in {"127.0.0.1:8100", "localhost:8100", "[::1]:8100"}: return jsonify(error="Local exchange only."), 403
    payload = request.get_json(silent=True) or {}
    token_hash = hashlib.sha256(str(payload.get("token", "")).encode()).hexdigest()
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    stamp = int(time.time())
    with db() as c:
        row = c.execute("SELECT domain,admin_user,admin_username,expires_at,used_at FROM wordpress_impersonation_tokens WHERE token_hash=?", (token_hash,)).fetchone()
        if not row or row["domain"] != domain or row["used_at"] or row["expires_at"] < stamp:
            return jsonify(error="Invalid or expired WordPress handoff."), 410
        changed = c.execute("UPDATE wordpress_impersonation_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL", (now(),token_hash)).rowcount
        if changed != 1: return jsonify(error="WordPress handoff was already used."), 410
    audit("app.wordpress.impersonate.open", domain, actor=row["admin_username"])
    return jsonify(username=row["admin_user"])


@app.get("/api/dns")
@require_auth
def list_dns():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    with db() as c:
        if session["role"] == "admin":
            if domain:
                records = c.execute(
                    "SELECT r.id,r.domain,r.mail_domain,r.type,r.name,r.value,r.ttl,r.created_at "
                    "FROM dns_records r WHERE r.domain=? ORDER BY r.name,r.type",
                    (domain,),
                ).fetchall()
            else:
                records = c.execute(
                    "SELECT r.id,r.domain,r.mail_domain,r.type,r.name,r.value,r.ttl,r.created_at "
                    "FROM dns_records r ORDER BY r.domain,r.name,r.type"
                ).fetchall()
        else:
            if domain:
                row = c.execute(
                    "SELECT 1 FROM domains WHERE domain=? AND owner=?",
                    (domain, session.get("system_username")),
                ).fetchone()
                if not row:
                    return jsonify(error="No access to that domain."), 403
                records = c.execute(
                    "SELECT r.id,r.domain,r.mail_domain,r.type,r.name,r.value,r.ttl,r.created_at "
                    "FROM dns_records r JOIN domains d ON d.domain=r.domain "
                    "WHERE d.owner=? AND r.domain=? ORDER BY r.name,r.type",
                    (session.get("system_username"), domain),
                ).fetchall()
            else:
                records = c.execute(
                    "SELECT r.id,r.domain,r.mail_domain,r.type,r.name,r.value,r.ttl,r.created_at "
                    "FROM dns_records r JOIN domains d ON d.domain=r.domain "
                    "WHERE d.owner=? ORDER BY r.domain,r.name,r.type",
                    (session.get("system_username"),),
                ).fetchall()
    return jsonify(records=[dict(r) for r in records])


@app.get("/api/dns/server")
@require_auth
def dns_server_status():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:
            route_probe.connect(("1.1.1.1", 53)); server_ip = route_probe.getsockname()[0]
    except (OSError, ValueError): server_ip = ""
    with db() as c: zones = c.execute("SELECT domain FROM domains ORDER BY domain").fetchall()
    active = subprocess.run(["/usr/bin/systemctl", "is-active", "bind9"], capture_output=True, text=True, timeout=3, check=False).stdout.strip() == "active"
    listening = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.5); probe.connect(("127.0.0.1", 53)); listening = True
    except OSError: pass
    primary_ns, secondary_ns = dns_service_nameservers()
    primary_ns_a = _public_dns("A", primary_ns) if primary_ns else []
    secondary_ns_a = _public_dns("A", secondary_ns) if secondary_ns else []
    return jsonify(engine="BIND 9", authoritative=True, recursion=False, active=active, listening=listening,
                   server_ip=server_ip, zone_count=len(zones), primary_ns=primary_ns, secondary_ns=secondary_ns,
                   primary_ready=bool(server_ip and server_ip in primary_ns_a),
                   secondary_ready=bool(server_ip and server_ip in secondary_ns_a),
                   zones=[{"domain":r["domain"],"primary_ns":primary_ns,"secondary_ns":secondary_ns} for r in zones])


@app.post("/api/dns")
@require_auth
@require_csrf
def create_dns():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    rtype = str(payload.get("type", "")).upper()
    name = str(payload.get("name", "")).lower().strip().strip(".")
    value = str(payload.get("value", "")).strip()

    try:
        ttl = payload.get("ttl", 3600)
        ttl = ttl if isinstance(ttl, int) else int(str(ttl))
    except ValueError:
        return jsonify(error="Invalid TTL value."), 400
    if ttl < 60 or ttl > 86400:
        return jsonify(error="TTL must be between 60 and 86400."), 400
    if not DOMAIN.fullmatch(domain) or rtype not in DNS_TYPES or (not DNS_RECORD_NAME.fullmatch(name) and name != "@"):
        return jsonify(error="Invalid DNS record details."), 400
    try:
        if not _validate_record_value(rtype, value):
            return jsonify(error="Invalid DNS record value."), 400
    except Exception:
        return jsonify(error="Invalid DNS record value."), 400

    try:
        with db() as c:
            if not _can_access_domain(c, domain, session.get("system_username")):
                return jsonify(error="No access to that domain."), 403
            if not c.execute("SELECT 1 FROM domains WHERE domain=?", (domain,)).fetchone():
                return jsonify(error="That domain does not exist."), 404
            cursor = c.execute(
                "INSERT INTO dns_records(domain,type,name,value,ttl,created_at,created_by) "
                "VALUES(?,?,?,?,?,?,?)",
                (domain, rtype, name, value, ttl, now(), session["username"]),
            )
            record_id = cursor.lastrowid
            _sync_dns(c, domain)
    except (RuntimeError, sqlite3.Error) as exc:
        audit("dns.create", domain, "failed")
        return jsonify(error=str(exc)), 400
    cloudflare = _auto_cloudflare_sync(domain)
    audit("dns.create", domain)
    return jsonify(ok=True, id=record_id, cloudflare=cloudflare), 201


@app.delete("/api/dns/<int:record_id>")
@require_auth
@require_csrf
def delete_dns(record_id):
    try:
        with db() as c:
            row = c.execute(
                "SELECT d.owner, r.domain FROM dns_records r JOIN domains d ON d.domain=r.domain WHERE r.id=?",
                (record_id,),
            ).fetchone()
            if not row:
                return jsonify(error="Record not found."), 404
            if session["role"] != "admin" and row["owner"] != session.get("system_username"):
                return jsonify(error="No access to this record."), 403
            c.execute("DELETE FROM dns_records WHERE id=?", (record_id,))
            _sync_dns(c, row["domain"])
    except (RuntimeError, sqlite3.Error) as exc:
        audit("dns.delete", str(record_id), "failed")
        return jsonify(error=str(exc)), 400
    cloudflare = _auto_cloudflare_sync(row["domain"])
    audit("dns.delete", row["domain"])
    return jsonify(ok=True, cloudflare=cloudflare)


@app.post("/api/dns/mail-plan")
@require_auth
@require_csrf
def generate_mail_dns():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    if not DOMAIN.fullmatch(domain):
        return jsonify(error="Enter a valid email domain or subdomain."), 400
    with db() as c:
        context = _mail_domain_context(c, domain, session.get("system_username"))
        if not context:
            return jsonify(error="No access to that domain."), 403
        zone_domain = context["zone_domain"]
    hostname = product_settings().get("mail_hostname", "")
    try: server_ip = socket.gethostbyname(hostname)
    except OSError: return jsonify(error="The configured mail hostname does not resolve."), 400
    try:
        plan = helper({"operation":"mail_dns_plan", "domain":domain, "mail_hostname":hostname, "server_ip":server_ip})
        with db() as c:
            for record in plan["records"]:
                zone_name = _mail_record_name(domain, zone_domain, record["name"])
                if domain == zone_domain:
                    c.execute("DELETE FROM dns_records WHERE domain=? AND type=? AND name=? AND (mail_domain=? OR mail_domain IS NULL)", (zone_domain, record["type"], zone_name, domain))
                else:
                    c.execute("DELETE FROM dns_records WHERE domain=? AND mail_domain=? AND type=? AND name=?", (zone_domain, domain, record["type"], zone_name))
                c.execute("INSERT INTO dns_records(domain,type,name,value,ttl,created_at,created_by,mail_domain) VALUES(?,?,?,?,?,?,?,?)",
                    (zone_domain, record["type"], zone_name, record["value"], record["ttl"], now(), session["username"], domain))
                record["zone_name"] = zone_name
            _sync_dns(c, zone_domain)
        plan["cloudflare"] = _auto_cloudflare_sync(zone_domain)
        audit("dns.mail.generate", domain)
        return jsonify(plan)
    except (RuntimeError, sqlite3.Error) as exc:
        audit("dns.mail.generate", domain, "failed")
        return jsonify(error=str(exc)), 400


@app.get("/api/integrations/cloudflare")
@require_auth
@require_admin
def cloudflare_status():
    try:
        result = helper({"operation":"cloudflare_status"})
        settings = product_settings()
        result.update({
            "auto_sync": True,
            "last_sync_at": settings.get("cloudflare_last_sync_at", ""),
            "last_sync_status": settings.get("cloudflare_last_sync_status", ""),
            "last_sync_domain": settings.get("cloudflare_last_sync_domain", ""),
            "last_sync_error": settings.get("cloudflare_last_sync_error", ""),
        })
        return jsonify(result)
    except RuntimeError as exc: return jsonify(error=str(exc)), 400


@app.post("/api/integrations/cloudflare")
@require_auth
@require_admin
@require_csrf
def cloudflare_connect():
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token", ""))
    account_id = str(payload.get("account_id", "")).lower().strip()
    label = str(payload.get("label", "")).strip()
    try:
        result = helper({"operation":"cloudflare_connect", "token":token, "account_id":account_id, "label":label})
        with db() as c:
            zones = [row["domain"] for row in c.execute("SELECT domain FROM domains ORDER BY domain").fetchall()]
        reconciled = [_auto_cloudflare_sync(zone) for zone in zones]
        settings = product_settings()
        service_hosts = {
            settings.get("mail_hostname", ""),
            urlparse(settings.get("public_url", "")).hostname if settings.get("public_url") else "",
        }
        for hostname in sorted(host for host in service_hosts if host and host not in zones):
            reconciled.append(_auto_cloudflare_service_hostname(hostname))
        result.update(auto_sync=True, reconciled=reconciled)
        audit("cloudflare.connect")
        return jsonify(result)
    except RuntimeError as exc:
        audit("cloudflare.connect", outcome="failed")
        return jsonify(error=str(exc)), 400


@app.delete("/api/integrations/cloudflare/<connection_id>")
@require_auth
@require_admin
@require_csrf
def cloudflare_disconnect(connection_id):
    if not re.fullmatch(r"[a-f0-9]{16}", connection_id): return jsonify(error="Invalid Cloudflare connection."), 400
    try:
        result = helper({"operation":"cloudflare_disconnect", "connection_id":connection_id})
        audit("cloudflare.disconnect", connection_id)
        return jsonify(result)
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/dns/cloudflare-sync")
@require_auth
@require_admin
@require_csrf
def sync_cloudflare_dns():
    domain = str((request.get_json(silent=True) or {}).get("domain", "")).lower().strip().strip(".")
    if not DOMAIN.fullmatch(domain):
        return jsonify(error="Enter a valid DNS domain or subdomain."), 400
    with db() as c:
        context = _mail_domain_context(c, domain, session.get("system_username"))
        if not context: return jsonify(error="Email domain not found."), 404
        zone_domain = context["zone_domain"]
    result = _auto_cloudflare_sync(zone_domain)
    if result.get("status") == "failed":
        audit("cloudflare.dns.sync", domain, "failed")
        return jsonify(error=result.get("error", "Cloudflare synchronization failed.")), 400
    if result.get("status") == "not_connected":
        return jsonify(error="Connect Cloudflare first."), 400
    try:
        audit("cloudflare.dns.sync", domain)
        return jsonify(result)
    except sqlite3.Error as exc:
        return jsonify(error=str(exc)), 400


@app.get("/api/files")
@require_auth
def list_files():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    path = str(request.args.get("path", "")).strip()
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username"))
        if not row:
            return jsonify(error="Domain not found or access denied."), 403
        root = Path(row["webroot"])
        try:
            base, target = _resolve_webroot_path(c, domain, path, session.get("system_username"))
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        target = Path(target)
        if not target.exists():
            return jsonify(error="Path not found."), 404
        if not target.is_dir():
            return jsonify(error="Path is not a directory."), 400
    return jsonify(
        domain=domain,
        path=path,
        root=str(root.resolve()),
        parent="" if str(target.resolve()) == str(root.resolve()) or target.relative_to(root).parent.as_posix() == "." else str(target.relative_to(root).parent.as_posix()),
        items=_list_directory_items(target),
    )


@app.get("/api/files/content")
@require_auth
def read_file():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    path = str(request.args.get("path", "")).strip()
    if not domain or not path:
        return jsonify(error="Domain and path are required."), 400
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username"))
        if not row:
            return jsonify(error="Domain not found or access denied."), 403
        try:
            _, target = _resolve_webroot_path(c, domain, path, session.get("system_username"))
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        target = Path(target)
        if not target.exists():
            return jsonify(error="File not found."), 404
        if target.is_dir():
            return jsonify(error="Path is not a file."), 400
    stat = os.stat(target)
    if stat.st_size > 262144:
        return jsonify(
            error="File is too large for inline view; download it instead.",
            size=stat.st_size,
        ), 413
    preview = _read_file_preview(target)
    if preview["is_binary"]:
        return jsonify(
            error="Binary file.",
            domain=domain,
            path=path,
            size=preview["size"],
            is_binary=True,
        ), 415
    return jsonify(
        domain=domain,
        path=path,
        encoding="utf-8",
        is_binary=False,
        content=preview["content"],
        size=preview["size"],
    )


@app.post("/api/files")
@require_auth
@require_csrf
def mutate_files():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    path = str(payload.get("path", "")).strip()
    action = str(payload.get("action", "")).strip()
    if action not in {"mkdir", "create_file", "write_file", "rename", "delete"}:
        return jsonify(error="Unsupported file action."), 400
    with db() as c:
        if not _domain_context(c, domain, session.get("system_username")):
            return jsonify(error="Domain not found or access denied."), 403
        try:
            root, target = _resolve_webroot_path(c, domain, path, session.get("system_username"), create_parent=True)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        if action == "mkdir":
            try:
                target.mkdir()
            except FileExistsError:
                return jsonify(error="Directory already exists."), 409
            audit("files.mkdir", f"{domain}:{path}")
            return jsonify(ok=True)
        if action in {"create_file", "write_file"}:
            content = payload.get("content", "")
            if not isinstance(content, str):
                return jsonify(error="File content must be text."), 400
            if action == "create_file" and target.exists():
                return jsonify(error="File already exists."), 409
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            except IsADirectoryError:
                return jsonify(error="Target is a directory."), 400
            audit("files.write", f"{domain}:{path}")
            return jsonify(ok=True)
        if action == "rename":
            new_name = str(payload.get("new_name", "")).strip()
            if not new_name or "/" in new_name or new_name in {".", ".."} or new_name == "":
                return jsonify(error="Invalid file name."), 400
            root_path = Path(root["webroot"]).resolve()
            if target.resolve() == root_path:
                return jsonify(error="Cannot rename domain root."), 400
            new_path = target.with_name(new_name)
            if new_path.exists():
                return jsonify(error="Destination already exists."), 409
            try:
                target.rename(new_path)
            except Exception as exc:
                return jsonify(error=str(exc)), 400
            audit("files.rename", f"{domain}:{path}")
            return jsonify(ok=True)
        if action == "delete":
            root_path = Path(root["webroot"]).resolve()
            if target.resolve() == root_path:
                return jsonify(error="Cannot delete domain root."), 400
            if not target.exists():
                return jsonify(error="Path not found."), 404
            if target.is_file() or target.is_symlink():
                target.unlink()
            else:
                import shutil
                shutil.rmtree(target)
            audit("files.delete", f"{domain}:{path}")
            return jsonify(ok=True)
    return jsonify(error="Unsupported action."), 400


@app.post("/api/files/upload")
@require_auth
@require_csrf
def upload_file():
    domain = str(request.form.get("domain", "")).lower().strip().strip(".")
    path = str(request.form.get("path", "")).strip()
    uploaded = request.files.get("file")
    if not domain or uploaded is None or not uploaded.filename:
        return jsonify(error="Domain and file are required."), 400
    filename = Path(uploaded.filename).name.strip()
    if (
        not filename
        or filename in {".", ".."}
        or "/" in uploaded.filename
        or "\\" in uploaded.filename
        or "\x00" in filename
    ):
        return jsonify(error="Invalid file name."), 400
    with db() as c:
        if not _domain_context(c, domain, session.get("system_username")):
            return jsonify(error="Domain not found or access denied."), 403
        try:
            _, directory = _resolve_webroot_path(c, domain, path, session.get("system_username"))
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        directory = Path(directory)
        if not directory.exists() or not directory.is_dir():
            return jsonify(error="Upload path is not a directory."), 400
        target = directory / filename
        if target.exists():
            return jsonify(error="A file with that name already exists."), 409
        try:
            uploaded.save(target)
        except OSError as exc:
            return jsonify(error=str(exc)), 400
    audit("files.upload", f"{domain}:{path}/{filename}".replace("//", "/"))
    return jsonify(ok=True, name=filename, size=target.stat().st_size), 201


@app.get("/api/files/download")
@require_auth
def download_file():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    path = str(request.args.get("path", "")).strip()
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username"))
        if not row:
            return jsonify(error="Domain not found or access denied."), 403
        try:
            _, target = _resolve_webroot_path(c, domain, path, session.get("system_username"), create_parent=True)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
        if not target.exists():
            return jsonify(error="File not found."), 404
        if target.is_dir():
            return jsonify(error="Cannot download a directory."), 400
    return send_file(target, as_attachment=True, download_name=target.name)


@app.get("/api/databases")
@require_auth
def list_databases():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    with db() as c:
        if session["role"] == "admin":
            if domain:
                rows = c.execute(
                    "SELECT id,owner,domain,name,path,created_at,created_by FROM user_databases WHERE domain=? ORDER BY name",
                    (domain,),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id,owner,domain,name,path,created_at,created_by FROM user_databases ORDER BY domain,name"
                ).fetchall()
        else:
            if domain:
                if not c.execute("SELECT 1 FROM domains WHERE domain=? AND owner=?", (domain, session.get("system_username"))).fetchone():
                    return jsonify(error="No access to that domain."), 403
                rows = c.execute(
                    "SELECT id,owner,domain,name,path,created_at,created_by FROM user_databases "
                    "WHERE owner=? AND domain=? ORDER BY name",
                    (session.get("system_username"), domain),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id,owner,domain,name,path,created_at,created_by FROM user_databases "
                    "WHERE owner=? ORDER BY domain,name",
                    (session.get("system_username"),),
                ).fetchall()
        if session["role"] == "admin":
            app_rows = c.execute("SELECT id,owner,domain,db_name,db_user,application_slug,installed_at,installed_by,status FROM app_installations WHERE db_name<>'' AND db_name<>'pending' AND (?='' OR domain=?) ORDER BY domain,db_name", (domain,domain)).fetchall()
        else:
            app_rows = c.execute("SELECT id,owner,domain,db_name,db_user,application_slug,installed_at,installed_by,status FROM app_installations WHERE owner=? AND db_name<>'' AND db_name<>'pending' AND (?='' OR domain=?) ORDER BY domain,db_name", (session.get("system_username"),domain,domain)).fetchall()
    databases = [{**dict(r), "engine":"sqlite", "managed_application":False} for r in rows]
    databases.extend({"id":f"app-{r['id']}","owner":r["owner"],"domain":r["domain"],"name":r["db_name"],"database_user":r["db_user"],"engine":"mariadb","managed_application":True,"application_slug":r["application_slug"],"status":r["status"],"created_at":r["installed_at"],"created_by":r["installed_by"]} for r in app_rows)
    return jsonify(databases=databases)


@app.post("/api/databases")
@require_auth
@require_csrf
def create_database():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    name = str(payload.get("name", "")).strip().lower()
    if not DB_NAME.fullmatch(name):
        return jsonify(error="Invalid database name."), 400

    with db() as c:
        row = _domain_context(c, domain, session.get("system_username"))
        if not row:
            return jsonify(error="Domain not found or access denied."), 403
        if c.execute(
            "SELECT 1 FROM user_databases WHERE owner=? AND domain=? AND name=?",
            (row["owner"], domain, name),
        ).fetchone():
            return jsonify(error="That database name already exists for this domain."), 409
        package_limit = _package_limit(c, row["owner"], "database_limit")
        current_total = c.execute("SELECT (SELECT COUNT(*) FROM user_databases WHERE owner=?)+(SELECT COUNT(*) FROM app_installations WHERE owner=? AND db_name<>'' AND db_name<>'pending') AS total", (row["owner"],row["owner"])).fetchone()["total"]
        if package_limit is not None and current_total >= package_limit:
            return jsonify(error="This hosting package has reached its database limit."), 409
        root = Path(row["webroot"]).resolve().parent.parent
        target = _database_path(root, domain, name)
        if target.exists():
            return jsonify(error="That database already exists."), 409
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            with sqlite3.connect(target) as sqlite_db:
                sqlite_db.execute("PRAGMA user_version = 1")
        except Exception as exc:
            return jsonify(error=str(exc)), 400
        cursor = c.execute(
            "INSERT INTO user_databases(owner,domain,name,path,created_by,created_at) VALUES(?,?,?,?,?,?)",
            (row["owner"], domain, name, str(target), session["username"], now()),
        )
        db_id = cursor.lastrowid
    os.chmod(target, 0o640)
    audit("database.create", name)
    return jsonify(ok=True, id=db_id), 201


@app.delete("/api/databases/<int:database_id>")
@require_auth
@require_csrf
def delete_database(database_id):
    with db() as c:
        row = c.execute("SELECT id,owner,domain,name,path FROM user_databases WHERE id=?", (database_id,)).fetchone()
        if not row:
            return jsonify(error="Database not found."), 404
        if session["role"] != "admin" and row["owner"] != session.get("system_username"):
            return jsonify(error="No access to this database."), 403
        c.execute("DELETE FROM user_databases WHERE id=?", (database_id,))
    path = Path(row["path"])
    if path.exists():
        try:
            path.unlink()
        except IsADirectoryError:
            import shutil
            shutil.rmtree(path)
    audit("database.delete", row["name"] if "name" in row.keys() else row["domain"])
    return jsonify(ok=True)


@app.post("/api/databases/<int:database_id>/query")
@require_auth
@require_csrf
def query_database(database_id):
    payload = request.get_json(silent=True) or {}
    sql = str(payload.get("sql", "")).strip()
    if not sql:
        return jsonify(error="Missing SQL statement."), 400
    if not sql.lower().startswith("select"):
        return jsonify(error="Only SELECT queries are allowed for safety."), 400
    with db() as c:
        rec = c.execute(
            "SELECT owner, path, name FROM user_databases WHERE id=?",
            (database_id,),
        ).fetchone()
        if not rec:
            return jsonify(error="Database not found."), 404
        if session["role"] != "admin" and rec["owner"] != session.get("system_username"):
            return jsonify(error="No access to this database."), 403
        db_path = Path(rec["path"])
        if not db_path.exists():
            return jsonify(error="Database file missing."), 404
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql).fetchall()
    except Exception as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(database=rec["name"], rows=[dict(r) for r in rows])


def _managed_database(database_ref):
    match = re.fullmatch(r"app-(\d+)", str(database_ref))
    if not match: return None
    with db() as c:
        row = c.execute("SELECT id,owner,domain,db_name,application_slug,status FROM app_installations WHERE id=? AND db_name<>'' AND db_name<>'pending'", (int(match.group(1)),)).fetchone()
    if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")): return None
    return row


@app.get("/api/databases/<database_ref>/browse")
@require_auth
def browse_managed_database(database_ref):
    row = _managed_database(database_ref)
    if not row: return jsonify(error="Database not found or access denied."), 404
    try: result = helper({"operation":"database_browse", "database":row["db_name"], "table":str(request.args.get("table", "")).strip()})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    return jsonify(**result)


@app.patch("/api/databases/<database_ref>/rows")
@require_auth
@require_csrf
def update_managed_database_row(database_ref):
    row = _managed_database(database_ref)
    if not row: return jsonify(error="Database not found or access denied."), 404
    payload = request.get_json(silent=True) or {}
    try: result = helper({"operation":"database_update_row", "database":row["db_name"], "table":payload.get("table"), "key":payload.get("key"), "changes":payload.get("changes")})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("database.row.update", f"{row['domain']}:{row['db_name']}:{payload.get('table','')}")
    return jsonify(**result)


@app.get("/api/tool-auth/files")
@require_auth
def authorize_file_tool():
    is_admin = session.get("role") == "admin" and not session.get("_impersonating_as")
    username = "masspanel-admin" if is_admin else str(session.get("system_username") or session.get("username") or "")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{2,31}", username): return "", 403
    response = make_response("", 204)
    response.headers["X-MassPanel-User"] = username
    response.headers["X-MassPanel-Role"] = "admin" if is_admin else "client"
    return response


@app.get("/api/files/quota")
@require_auth
def file_storage_quota():
    domain = str(request.args.get("domain", "")).lower().strip()
    with db() as c:
        row = c.execute(
            "SELECT d.owner,COALESCE(p.disk_mb,a.disk_limit_mb) AS disk_mb FROM domains d JOIN accounts a ON a.system_username=d.owner "
            "LEFT JOIN hosting_packages p ON p.id=a.package_id WHERE d.domain=?",
            (domain,),
        ).fetchone()
    if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")):
        return jsonify(error="Website not found or access denied."), 404
    try: usage = helper({"operation":"hosting_storage_usage", "username":row["owner"]})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    limit_bytes = int(row["disk_mb"] or 0) * 1024 * 1024
    return jsonify(owner=row["owner"], used_bytes=usage["used_bytes"], limit_bytes=limit_bytes,
                   disk_mb=int(row["disk_mb"] or 0), percent=round((usage["used_bytes"] / limit_bytes) * 100, 1) if limit_bytes else None)


@app.get("/api/file-tool/open")
@require_auth
def open_file_tool():
    is_admin = session.get("role") == "admin" and not session.get("_impersonating_as")
    is_reseller = session.get("role") == "reseller" and not session.get("_impersonating_as")
    if is_admin or is_reseller:
        with db() as c:
            if is_admin:
                rows = c.execute("SELECT domain,owner,webroot FROM domains ORDER BY domain").fetchall()
            else:
                rows = c.execute("SELECT domain,owner,webroot FROM domains WHERE created_by=? ORDER BY domain", (session["username"],)).fetchall()
        workspace_user = "masspanel-admin" if is_admin else str(session.get("system_username") or session["username"])
        try: helper({"operation":"filebrowser_workspace_sync", "workspace_user":workspace_user, "domains":[dict(row) for row in rows]})
        except RuntimeError as exc: return jsonify(error=str(exc)), 400
        audit("filebrowser.workspace", f"{workspace_user}:{len(rows)}")
    return redirect("/file-tool/", code=302)


@app.get("/api/tool-auth/database")
@require_auth
def authorize_database_tool():
    database_ref = str(request.args.get("database_ref", "") or session.get("database_tool_ref", ""))
    row = _managed_database(database_ref)
    if not row: return "", 403
    try: access = helper({"operation":"database_tool_access", "database":row["db_name"]})
    except RuntimeError as exc:
        app.logger.warning("Database tool authorization failed for %s: %s", row["db_name"], exc)
        return "", 403
    response = make_response("", 204)
    response.headers["X-MassPanel-Db-Server"] = access["server"]
    response.headers["X-MassPanel-Db-Name"] = access["database"]
    response.headers["X-MassPanel-Db-User"] = access["username"]
    response.headers["X-MassPanel-Db-Password"] = access["password"]
    return response


@app.get("/api/database-tool/open/<database_ref>")
@require_auth
def open_database_tool(database_ref):
    row = _managed_database(database_ref)
    if not row:
        return jsonify(error="MariaDB database not found or access denied."), 404
    session["database_tool_ref"] = database_ref
    audit("database.tool.open", f"{row['domain']}:{row['db_name']}")
    return redirect("/database-tool/", code=302)


def _rspamd_export_authorized():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        return False
    try:
        expected = RSPAMD_EXPORT_SECRET.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    supplied = request.authorization.password if request.authorization else ""
    return bool(expected and hmac.compare_digest(supplied or "", expected))


def _recipient_list(value):
    if isinstance(value, list): raw = value
    else: raw = re.split(r"[,;\s]+", str(value or ""))
    found = []
    for item in raw:
        address = str(item).strip().lower().strip("<>")
        if _valid_email_address(address) and address not in found: found.append(address)
    return found[:100]


def _metadata_scalar(value):
    if isinstance(value, list): value = value[0] if value else ""
    return str(value or "")


def _mail_security_upsert(metadata, raw_message=b""):
    recipients = _recipient_list(metadata.get("rcpt") or metadata.get("recipients"))
    message_id = str(metadata.get("message_id") or metadata.get("message-id") or "").strip().strip("<>")[:512]
    queue_id = str(metadata.get("qid") or metadata.get("queue_id") or "")[:128]
    digest = hashlib.sha256(raw_message).hexdigest() if raw_message else ""
    message_key = queue_id or message_id or digest or secrets.token_hex(16)
    sender = _metadata_scalar(metadata.get("from") or metadata.get("header_from"))[:512]
    subject = _metadata_scalar(metadata.get("header_subject") or metadata.get("subject"))[:998]
    action = _metadata_scalar(metadata.get("action") or "no action").lower()[:64]
    source_ip = _metadata_scalar(metadata.get("ip"))[:64]
    try: score = float(metadata.get("score") or 0)
    except (TypeError, ValueError): score = 0.0
    symbols = metadata.get("symbols") or []
    if isinstance(symbols, dict): symbols = [{"name": key, **(value if isinstance(value, dict) else {})} for key, value in symbols.items()]
    direction = "outgoing" if _metadata_scalar(metadata.get("user")).strip() else "incoming"
    event_id = secrets.token_urlsafe(18)
    quarantine_path = ""
    status = "tracked"
    if raw_message:
        parsed = BytesParser(policy=policy.default).parsebytes(raw_message, headersonly=True)
        subject = subject or str(parsed.get("Subject", ""))[:998]
        sender = sender or str(parsed.get("From", ""))[:512]
        recipients = recipients or _recipient_list([parsed.get("To", ""), parsed.get("Cc", "")])
        QUARANTINE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        quarantine_path = str(QUARANTINE_DIR / f"{event_id}.eml")
        Path(quarantine_path).write_bytes(raw_message)
        os.chmod(quarantine_path, 0o600)
        status = "quarantined"
    with db() as c:
        existing = c.execute("SELECT id,quarantine_path,status FROM mail_security_events WHERE message_key=?", (message_key,)).fetchone()
        if existing:
            event_id = existing["id"]
            if raw_message:
                final_path = str(QUARANTINE_DIR / f"{event_id}.eml")
                if quarantine_path != final_path:
                    os.replace(quarantine_path, final_path)
                quarantine_path = final_path
            else:
                quarantine_path = existing["quarantine_path"]
                status = existing["status"]
            c.execute("UPDATE mail_security_events SET queue_id=?,sender=?,recipients_json=?,subject=?,source_ip=?,score=?,action=?,symbols_json=?,direction=?,size_bytes=?,quarantine_path=?,status=? WHERE id=?", (queue_id,sender,json.dumps(recipients),subject,source_ip,score,action,json.dumps(symbols)[:65535],direction,len(raw_message),quarantine_path,status,event_id))
        else:
            c.execute("INSERT INTO mail_security_events(id,message_key,queue_id,sender,recipients_json,subject,source_ip,score,action,symbols_json,direction,size_bytes,quarantine_path,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (event_id,message_key,queue_id,sender,json.dumps(recipients),subject,source_ip,score,action,json.dumps(symbols)[:65535],direction,len(raw_message),quarantine_path,status,now()))
    return event_id


@app.post("/api/mail-security/ingest/event")
def ingest_mail_security_event():
    if not _rspamd_export_authorized(): return jsonify(error="Not authorized."), 403
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        try: payload = json.loads(request.get_data(cache=False))
        except (TypeError, ValueError, json.JSONDecodeError): payload = None
    if not isinstance(payload, dict): return jsonify(error="Invalid event."), 400
    return jsonify(ok=True, id=_mail_security_upsert(payload)), 201


@app.post("/api/mail-security/ingest/quarantine")
def ingest_mail_quarantine():
    if not _rspamd_export_authorized(): return jsonify(error="Not authorized."), 403
    raw = request.get_data(cache=False)
    if not raw or len(raw) > 64 * 1024 * 1024: return jsonify(error="Invalid message."), 400
    prefix = "X-Rspamd-"
    metadata = {key[len(prefix):].lower().replace("-", "_"): value for key, value in request.headers.items() if key.lower().startswith(prefix.lower())}
    return jsonify(ok=True, id=_mail_security_upsert(metadata, raw)), 201


def _mail_security_visible(event):
    if session.get("role") == "admin": return True
    recipients = json.loads(event["recipients_json"] or "[]")
    domains = {address.rpartition("@")[2] for address in recipients if "@" in address}
    if not domains: return False
    with db() as c:
        owned = {row["domain"] for row in c.execute("SELECT domain FROM mail_domains WHERE owner=?", (session.get("system_username"),)).fetchall()}
    return bool(domains & owned)


def _serialize_mail_event(row):
    data = dict(row)
    data["recipients"] = json.loads(data.pop("recipients_json") or "[]")
    data["symbols"] = json.loads(data.pop("symbols_json") or "[]")
    data["quarantined"] = bool(data.pop("quarantine_path", "")) and data["status"] == "quarantined"
    return data


@app.get("/api/mail-security/events")
@require_auth
def list_mail_security_events():
    status = str(request.args.get("status", "all")).lower()
    search = str(request.args.get("search", "")).strip().lower()[:200]
    with db() as c:
        rows = c.execute("SELECT * FROM mail_security_events ORDER BY created_at DESC LIMIT 1000").fetchall()
    visible = [row for row in rows if _mail_security_visible(row)]
    if status != "all": visible = [row for row in visible if row["status"] == status or row["action"] == status]
    if search:
        visible = [row for row in visible if search in (row["sender"] + " " + row["subject"] + " " + row["recipients_json"] + " " + row["queue_id"]).lower()]
    events = [_serialize_mail_event(row) for row in visible[:250]]
    stats = {"total":len(visible),"quarantined":sum(row["status"] == "quarantined" for row in visible),"released":sum(row["status"] == "released" for row in visible),"rejected":sum(row["action"] == "reject" for row in visible)}
    return jsonify(events=events, stats=stats, scope="all tenants" if session["role"] == "admin" else "your domains")


@app.post("/api/mail-security/events/<event_id>/release")
@require_auth
@require_csrf
def release_mail_security_event(event_id):
    with db() as c: row = c.execute("SELECT * FROM mail_security_events WHERE id=?", (event_id,)).fetchone()
    if not row: return jsonify(error="Quarantined message not found."), 404
    if not _mail_security_visible(row): return jsonify(error="No access to this message."), 403
    if row["status"] != "quarantined" or not row["quarantine_path"]: return jsonify(error="This message is no longer quarantined."), 409
    recipients = json.loads(row["recipients_json"] or "[]")
    with db() as c:
        claimed = c.execute("UPDATE mail_security_events SET status='released',released_at=?,released_by=? WHERE id=? AND status='quarantined'", (now(),session["username"],event_id)).rowcount
    if claimed != 1: return jsonify(error="This message was already handled."), 409
    try: helper({"operation":"mail_quarantine_release", "path":row["quarantine_path"], "recipients":recipients})
    except RuntimeError as exc:
        with db() as c: c.execute("UPDATE mail_security_events SET status='quarantined',released_at=NULL,released_by=NULL WHERE id=? AND status='released'", (event_id,))
        return jsonify(error=str(exc)), 400
    audit("mail.quarantine.release", event_id)
    return jsonify(ok=True)


@app.delete("/api/mail-security/events/<event_id>")
@require_auth
@require_csrf
def delete_mail_security_event(event_id):
    with db() as c: row = c.execute("SELECT * FROM mail_security_events WHERE id=?", (event_id,)).fetchone()
    if not row: return jsonify(error="Message not found."), 404
    if not _mail_security_visible(row): return jsonify(error="No access to this message."), 403
    path = row["quarantine_path"]
    if path:
        try:
            candidate = Path(path).resolve(); root = QUARANTINE_DIR.resolve()
            if candidate.parent == root: candidate.unlink(missing_ok=True)
        except OSError: pass
    with db() as c: c.execute("UPDATE mail_security_events SET status='deleted',quarantine_path='' WHERE id=?", (event_id,))
    audit("mail.quarantine.delete", event_id)
    return jsonify(ok=True)


@app.get("/api/emails")
@require_auth
def list_emails():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    with db() as c:
        if session["role"] == "admin":
            if domain:
                emails = c.execute(
                    "SELECT id,full_email,COALESCE(mail_domain,domain) AS domain,localpart,destination,forward_copy,quota_mb,status,allow_smtp,allow_imap,allow_web,allow_dav,allow_eas,created_at "
                    "FROM email_accounts WHERE COALESCE(mail_domain,domain)=? ORDER BY localpart",
                    (domain,),
                ).fetchall()
            else:
                emails = c.execute(
                    "SELECT id,full_email,COALESCE(mail_domain,domain) AS domain,localpart,destination,forward_copy,quota_mb,status,allow_smtp,allow_imap,allow_web,allow_dav,allow_eas,created_at "
                    "FROM email_accounts ORDER BY domain,localpart"
                ).fetchall()
        else:
            if domain:
                if not c.execute("SELECT 1 FROM mail_domains WHERE domain=? AND owner=?", (domain, session.get("system_username"))).fetchone():
                    return jsonify(error="No access to that domain."), 403
                emails = c.execute(
                    "SELECT e.id,e.full_email,COALESCE(e.mail_domain,e.domain) AS domain,e.localpart,e.destination,e.forward_copy,e.quota_mb,e.status,e.allow_smtp,e.allow_imap,e.allow_web,e.allow_dav,e.allow_eas,e.created_at "
                    "FROM email_accounts e JOIN domains d ON d.domain=e.domain "
                    "WHERE d.owner=? AND COALESCE(e.mail_domain,e.domain)=? ORDER BY e.localpart",
                    (session.get("system_username"), domain),
                ).fetchall()
            else:
                emails = c.execute(
                    "SELECT e.id,e.full_email,COALESCE(e.mail_domain,e.domain) AS domain,e.localpart,e.destination,e.forward_copy,e.quota_mb,e.status,e.allow_smtp,e.allow_imap,e.allow_web,e.allow_dav,e.allow_eas,e.created_at "
                    "FROM email_accounts e JOIN domains d ON d.domain=e.domain "
                    "WHERE d.owner=? ORDER BY e.domain,e.localpart",
                    (session.get("system_username"),),
                ).fetchall()
    hidden = set(OWNER_SERVICE_LOCALPARTS)
    visible = [dict(e) for e in emails if e["localpart"] not in hidden and e["full_email"] != product_settings().get("system_mailbox", "")]
    return jsonify(emails=visible)


@app.get("/api/mail/status")
@require_auth
def mail_status():
    hostname = product_settings().get("mail_hostname", "")
    ports = {}
    for name, port in (("smtp", 25), ("submission", 587), ("imap", 143), ("imaps", 993)):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                ports[name] = True
        except OSError:
            ports[name] = False
    return jsonify(
        platform="Grommunio Mail",
        hostname=hostname,
        ports=ports,
        ready=bool(hostname and all(ports.values())),
        webmail_url=f"https://{hostname}/" if hostname else "",
    )


OWNER_SERVICE_LOCALPARTS = ("postmaster", "abuse", "webmaster", "root")


def _provision_owner_service_aliases(domain, zone_domain, destination, actor):
    for localpart in OWNER_SERVICE_LOCALPARTS:
        address = f"{localpart}@{domain}"
        with db() as c:
            existing = c.execute("SELECT id,destination FROM email_accounts WHERE full_email=?", (address,)).fetchone()
        if existing and not existing["destination"]:
            continue
        helper({"operation":"grommunio_email_create", "full_email":address, "destination":destination, "password":""})
        with db() as c:
            if existing:
                c.execute("UPDATE email_accounts SET destination=?,status='active' WHERE id=?", (destination,existing["id"]))
            else:
                c.execute(
                    "INSERT INTO email_accounts(full_email,domain,mail_domain,localpart,destination,quota_mb,status,created_at,created_by,password_hash) VALUES(?,?,?,?,?,0,'active',?,?,NULL)",
                    (address,zone_domain,domain,localpart,destination,now(),actor),
                )


def _refresh_owner_service_routes(system_mailbox, actor):
    created_or_updated, conflicts = [], []
    with db() as c: domains = c.execute("SELECT domain,zone_domain FROM mail_domains ORDER BY domain").fetchall()
    for mail_domain in domains:
        with db() as c:
            customer = c.execute(
                "SELECT full_email FROM email_accounts WHERE mail_domain=? AND destination IS NULL "
                "AND localpart NOT IN ('postmaster','abuse','webmaster','root') AND full_email<>? "
                "ORDER BY CASE WHEN localpart IN ('admin','info') THEN 0 ELSE 1 END,id LIMIT 1",
                (mail_domain["domain"],system_mailbox),
            ).fetchone()
        if not customer:
            conflicts.append(f"{mail_domain['domain']}: no customer mailbox")
            continue
        destination = f"{customer['full_email']},{system_mailbox}"
        _provision_owner_service_aliases(mail_domain["domain"], mail_domain["zone_domain"], destination, actor)
        created_or_updated.append(mail_domain["domain"])
    return {"domains":created_or_updated,"conflicts":conflicts}


@app.get("/api/mail/owner-addresses")
@require_auth
@require_admin
def owner_service_addresses():
    settings = product_settings()
    destination = settings.get("owner_mailbox", "")
    with db() as c:
        rows = c.execute(
            "SELECT full_email,COALESCE(mail_domain,domain) AS domain,localpart,destination,status "
            "FROM email_accounts WHERE localpart IN ('postmaster','abuse','webmaster','root') ORDER BY domain,localpart"
        ).fetchall()
        domains = c.execute("SELECT domain FROM mail_domains ORDER BY domain").fetchall()
    return jsonify(destination=destination, system_mailbox_configured=bool(settings.get("system_mailbox")), localparts=list(OWNER_SERVICE_LOCALPARTS), domains=[r["domain"] for r in domains], addresses=[dict(r) for r in rows])


@app.post("/api/mail/system/impersonate")
@require_auth
@require_admin
@require_csrf
def open_system_mailbox():
    mailbox = product_settings().get("system_mailbox", "")
    if not _valid_email_address(mailbox): return jsonify(error="The panel system mailbox is not configured."), 409
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    with db() as c:
        c.execute("DELETE FROM mail_impersonation_tokens WHERE expires_at < ? OR used_at IS NOT NULL", (int(time.time()),))
        c.execute("INSERT INTO mail_impersonation_tokens(token_hash,mailbox,admin_username,expires_at,created_at) VALUES(?,?,?,?,?)", (token_hash,mailbox,session["username"],int(time.time()) + 60,now()))
    audit("mail.system.open", "system-mailbox")
    return jsonify(ok=True,launch_url=f"/api/mail/impersonation/launch?token={raw_token}")


@app.put("/api/mail/owner-addresses")
@require_auth
@require_admin
@require_csrf
def update_owner_service_addresses():
    system_mailbox = product_settings().get("system_mailbox", "")
    if not _valid_email_address(system_mailbox):
        return jsonify(error="The panel system mailbox is not configured."), 409
    created, updated, conflicts = [], [], []
    try:
        with db() as c:
            domains = c.execute("SELECT domain,zone_domain FROM mail_domains ORDER BY domain").fetchall()
            for mail_domain in domains:
                customer = c.execute(
                    "SELECT full_email FROM email_accounts WHERE mail_domain=? AND destination IS NULL "
                    "AND localpart NOT IN ('postmaster','abuse','webmaster','root') AND full_email<>? "
                    "ORDER BY CASE WHEN localpart IN ('admin','info') THEN 0 ELSE 1 END,id LIMIT 1",
                    (mail_domain["domain"],system_mailbox),
                ).fetchone()
                if not customer:
                    conflicts.append(f"{mail_domain['domain']}: no customer mailbox")
                    continue
                destination = f"{customer['full_email']},{system_mailbox}"
                for localpart in OWNER_SERVICE_LOCALPARTS:
                    address = f"{localpart}@{mail_domain['domain']}"
                    existing = c.execute("SELECT id,destination FROM email_accounts WHERE full_email=?", (address,)).fetchone()
                    if existing and not existing["destination"]:
                        conflicts.append(address)
                        continue
                    helper({"operation":"grommunio_email_create", "full_email":address, "destination":destination, "password":""})
                    if existing:
                        c.execute("UPDATE email_accounts SET destination=?,status='active' WHERE id=?", (destination,existing["id"]))
                        updated.append(address)
                    else:
                        c.execute(
                            "INSERT INTO email_accounts(full_email,domain,mail_domain,localpart,destination,quota_mb,status,created_at,created_by,password_hash) VALUES(?,?,?,?,?,0,'active',?,?,NULL)",
                            (address,mail_domain["zone_domain"],mail_domain["domain"],localpart,destination,now(),session["username"]),
                        )
                        created.append(address)
    except (RuntimeError, sqlite3.Error) as exc:
        audit("mail.owner-addresses", "system-mailbox", "failed")
        return jsonify(error=str(exc)), 400
    audit("mail.owner-addresses", "system-mailbox")
    return jsonify(ok=True,created=created,updated=updated,conflicts=conflicts)


@app.post("/api/emails/<int:email_id>/impersonate")
@require_auth
@require_admin
@require_csrf
def impersonate_mailbox(email_id):
    if limited((session["username"], "mail-impersonate"), 30, 3600):
        return jsonify(error="Mailbox administrator access rate limit reached."), 429
    with db() as c:
        row = c.execute("SELECT full_email,destination,status FROM email_accounts WHERE id=?", (email_id,)).fetchone()
        if not row: return jsonify(error="Mailbox not found."), 404
        if row["destination"]: return jsonify(error="Forwarding addresses do not have a Grommunio mailbox."), 409
        if row["status"] != "active": return jsonify(error="Only active mailboxes can be opened."), 409
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        c.execute("DELETE FROM mail_impersonation_tokens WHERE expires_at < ? OR used_at IS NOT NULL", (int(time.time()),))
        c.execute("INSERT INTO mail_impersonation_tokens(token_hash,mailbox,admin_username,expires_at,created_at) VALUES(?,?,?,?,?)", (token_hash,row["full_email"],session["username"],int(time.time()) + 60,now()))
    audit("mail.impersonate.request", row["full_email"])
    return jsonify(ok=True, launch_url=f"/api/mail/impersonation/launch?token={raw_token}")


@app.get("/api/mail/impersonation/launch")
@require_auth
@require_admin
def launch_mail_impersonation():
    token = str(request.args.get("token", ""))
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as c: row = c.execute("SELECT mailbox,admin_username,expires_at,used_at FROM mail_impersonation_tokens WHERE token_hash=?", (token_hash,)).fetchone()
    if not row or row["used_at"] or row["expires_at"] < int(time.time()) or row["admin_username"] != session["username"]: return Response("This mailbox handoff is invalid or expired.", status=410)
    hostname = product_settings().get("mail_hostname", "")
    if not hostname: return Response("The mail hostname is not configured.", status=409)
    return Response(f"<!doctype html><meta name=referrer content=no-referrer><meta name=viewport content='width=device-width'><title>Opening mailbox</title><body style='font:16px system-ui;display:grid;place-items:center;min-height:80vh'><form id=f method=post action='https://{html.escape(hostname, quote=True)}/web/masspanel-sso.php'><input type=hidden name=token value='{html.escape(token, quote=True)}'><p>Opening {html.escape(row['mailbox'])} securely…</p><noscript><button>Continue</button></noscript></form><script>document.getElementById('f').submit()</script></body>", content_type="text/html; charset=utf-8", headers={"Cache-Control":"no-store"})


@app.post("/api/mail/impersonation/exchange")
def exchange_mail_impersonation():
    if request.remote_addr not in {"127.0.0.1", "::1"} or request.host not in {"127.0.0.1:8100", "localhost:8100", "[::1]:8100"}: return jsonify(error="Local exchange only."), 403
    token = str((request.get_json(silent=True) or {}).get("token", ""))
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as c:
        row = c.execute("SELECT mailbox,admin_username,expires_at,used_at FROM mail_impersonation_tokens WHERE token_hash=?", (token_hash,)).fetchone()
        if not row or row["used_at"] or row["expires_at"] < int(time.time()): return jsonify(error="Invalid or expired mailbox handoff."), 410
        changed = c.execute("UPDATE mail_impersonation_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL", (now(),token_hash)).rowcount
        if changed != 1: return jsonify(error="Mailbox handoff was already used."), 410
    settings = product_settings()
    operation = "grommunio_system_mailbox_credentials" if row["mailbox"] == settings.get("system_mailbox", "") else "grommunio_impersonation_credentials"
    try: credentials = helper({"operation":operation, "full_email":row["mailbox"]})
    except RuntimeError as exc:
        audit("mail.impersonate.exchange", row["mailbox"], "failed", actor=row["admin_username"])
        return jsonify(error=str(exc)), 400
    audit("mail.impersonate.open", row["mailbox"], actor=row["admin_username"])
    return jsonify(username=credentials["username"], password=credentials["password"], mailbox=credentials["mailbox"])


@app.post("/api/emails")
@require_auth
@require_csrf
def create_email():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    localpart = str(payload.get("localpart", "")).lower().strip()
    destination = (payload.get("destination") or "").strip().lower() or None
    password = str(payload.get("password", ""))
    try:
        quota = payload.get("quota_mb", 0)
        quota = quota if isinstance(quota, int) else int(str(quota))
    except ValueError:
        return jsonify(error="Invalid mailbox quota."), 400

    if not DOMAIN.fullmatch(domain) or not EMAIL_LOCALPART.fullmatch(localpart):
        return jsonify(error="Invalid email address details."), 400
    if quota < 0 or quota > 1048576:
        return jsonify(error="Invalid mailbox quota."), 400
    if destination and not _valid_email_address(destination):
        return jsonify(error="Invalid destination address."), 400
    if not destination and (len(password) < 12 or len(password) > 256 or password != payload.get("confirm_password")):
        return jsonify(error="Mailbox passwords must match and contain 12-256 characters."), 400

    password_hash = None if destination else "{GROMMUNIO}"

    try:
        with db() as c:
            context = _mail_domain_context(c, domain, session.get("system_username"))
            if not context:
                return jsonify(error="No access to that domain."), 403
            zone_domain = context["zone_domain"]
            package_limit = _package_limit(c, context["owner"], "mailbox_limit")
            current_total = c.execute(
                "SELECT COUNT(*) AS total FROM email_accounts e JOIN mail_domains m ON m.domain=e.mail_domain WHERE m.owner=?",
                (context["owner"],),
            ).fetchone()["total"]
            if package_limit is not None and current_total >= package_limit:
                return jsonify(error="This hosting package has reached its mailbox limit."), 409
            full_email = f"{localpart}@{domain}"
            try:
                cursor = c.execute(
                    "INSERT INTO email_accounts(full_email,domain,mail_domain,localpart,destination,quota_mb,created_at,created_by,password_hash) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (full_email, zone_domain, domain, localpart, destination, quota, now(), session["username"], password_hash),
                )
            except sqlite3.IntegrityError:
                return jsonify(error="That email account already exists."), 409
            rowid = cursor.lastrowid
            helper({"operation": "grommunio_email_create", "full_email": full_email, "destination": destination, "password": password})
    except (RuntimeError, sqlite3.Error) as exc:
        audit("email.create", f"{localpart}@{domain}", "failed")
        return jsonify(error=str(exc)), 400
    audit("email.create", full_email)
    if not destination and localpart not in OWNER_SERVICE_LOCALPARTS:
        archive = product_settings().get("system_mailbox", "")
        if _valid_email_address(archive) and full_email != archive:
            try: _provision_owner_service_aliases(domain, zone_domain, f"{full_email},{archive}", session["username"])
            except (RuntimeError, sqlite3.Error) as exc: app.logger.warning("Owner service routing could not be updated for %s: %s", domain, exc)
    return jsonify(ok=True, id=rowid), 201


@app.put("/api/emails/<int:email_id>")
@require_auth
@require_csrf
def update_email(email_id):
    payload = request.get_json(silent=True) or {}
    try:
        quota = int(payload.get("quota_mb", 0))
    except (TypeError, ValueError):
        return jsonify(error="Invalid mailbox quota."), 400
    if quota < 0 or quota > 1048576:
        return jsonify(error="Invalid mailbox quota."), 400
    password = str(payload.get("password", ""))
    if password and (len(password) < 12 or len(password) > 256 or password != payload.get("confirm_password")):
        return jsonify(error="New mailbox passwords must match and contain 12-256 characters."), 400
    try:
        with db() as c:
            row = c.execute("SELECT e.*,d.owner FROM email_accounts e JOIN domains d ON d.domain=e.domain WHERE e.id=?", (email_id,)).fetchone()
            if not row:
                return jsonify(error="Email account not found."), 404
            if session["role"] != "admin" and row["owner"] != session.get("system_username"):
                return jsonify(error="No access to this account."), 403
            forwarding_only = bool(row["destination"])
            destination = str(payload.get("destination", "")).lower().strip()
            forward_copy = str(payload.get("forward_copy", "")).lower().strip()
            selected = destination if forwarding_only else forward_copy
            destinations = [item.strip() for item in selected.split(",") if item.strip()]
            if len(destinations) > 4 or len(set(destinations)) != len(destinations) or any(not _valid_email_address(item) for item in destinations):
                return jsonify(error="Enter up to four valid, unique forwarding addresses."), 400
            if forwarding_only and not destinations:
                return jsonify(error="A forwarding-only address must have a destination."), 400
            flags = {name: bool(payload.get(name, True)) for name in ("allow_smtp", "allow_imap", "allow_web", "allow_dav", "allow_eas")}
            helper({"operation":"grommunio_email_update", "full_email":row["full_email"], "forwarding_only":forwarding_only,
                    "destination":",".join(destinations), "password":password, **flags})
            if forwarding_only:
                c.execute("UPDATE email_accounts SET destination=?,quota_mb=? WHERE id=?", (",".join(destinations), quota, email_id))
            else:
                c.execute("UPDATE email_accounts SET forward_copy=?,quota_mb=?,allow_smtp=?,allow_imap=?,allow_web=?,allow_dav=?,allow_eas=? WHERE id=?",
                          (",".join(destinations), quota, *(1 if flags[name] else 0 for name in ("allow_smtp","allow_imap","allow_web","allow_dav","allow_eas")), email_id))
    except (RuntimeError, sqlite3.Error) as exc:
        audit("email.update", str(email_id), "failed")
        return jsonify(error=str(exc)), 400
    audit("email.update", row["full_email"])
    return jsonify(ok=True)


@app.delete("/api/emails/<int:email_id>")
@require_auth
@require_csrf
def delete_email(email_id):
    try:
        with db() as c:
            row = c.execute(
                "SELECT d.owner,e.full_email,e.domain FROM email_accounts e JOIN domains d ON d.domain=e.domain WHERE e.id=?",
                (email_id,),
            ).fetchone()
            if not row:
                return jsonify(error="Email account not found."), 404
            if session["role"] != "admin" and row["owner"] != session.get("system_username"):
                return jsonify(error="No access to this account."), 403
            helper({"operation": "grommunio_email_delete", "full_email": row["full_email"]})
            c.execute("DELETE FROM email_accounts WHERE id=?", (email_id,))
    except (RuntimeError, sqlite3.Error) as exc:
        audit("email.delete", str(email_id), "failed")
        return jsonify(error=str(exc)), 400
    audit("email.delete", row["full_email"])
    return jsonify(ok=True)


@app.get("/api/packages")
@require_auth
def list_hosting_packages():
    with db() as c:
        packages = [dict(row) for row in c.execute("SELECT * FROM hosting_packages ORDER BY name").fetchall()]
        for package in packages:
            package["features"] = {key: True for key in FEATURE_CATALOG}
            for feature in c.execute("SELECT feature_key,enabled FROM package_features WHERE package_id=?", (package["id"],)):
                if feature["feature_key"] in package["features"]: package["features"][feature["feature_key"]] = bool(feature["enabled"])
        assigned = None
        if session["role"] != "admin":
            assigned = c.execute(
                "SELECT p.* FROM accounts a LEFT JOIN hosting_packages p ON p.id=a.package_id WHERE a.username=?",
                (session["username"],),
            ).fetchone()
    return jsonify(packages=packages if session["role"] == "admin" else [], assigned=dict(assigned) if assigned and assigned["id"] else None, catalog=FEATURE_CATALOG, effective=_session_features())


@app.post("/api/packages")
@require_auth
@require_admin
@require_csrf
def create_hosting_package():
    payload = request.get_json(silent=True) or {}
    supplied = payload.get("features", {})
    if not isinstance(supplied, dict) or any(key not in FEATURE_CATALOG or not isinstance(value, bool) for key,value in supplied.items()): return jsonify(error="Provide valid feature switches."), 400
    name = str(payload.get("name", "")).strip()
    if not name or len(name) > 64: return jsonify(error="Enter a package name of no more than 64 characters."), 400
    fields = {"domain_limit":(0,1000,10),"disk_mb":(128,10485760,10240),"bandwidth_mb":(0,104857600,102400),"database_limit":(0,1000,10),"mailbox_limit":(0,10000,25),"cron_limit":(0,1000,10),"backup_limit":(0,1000,5)}
    values = {}
    try:
        for key,(minimum,maximum,default) in fields.items():
            values[key] = int(payload.get(key,default))
            if not minimum <= values[key] <= maximum: raise ValueError(key)
    except (TypeError, ValueError): return jsonify(error="One or more package limits are invalid."), 400
    try:
        with db() as c:
            cursor = c.execute("INSERT INTO hosting_packages(name,domain_limit,disk_mb,bandwidth_mb,database_limit,mailbox_limit,cron_limit,backup_limit,allow_php,allow_ssh,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (name,values["domain_limit"],values["disk_mb"],values["bandwidth_mb"],values["database_limit"],values["mailbox_limit"],values["cron_limit"],values["backup_limit"],int(bool(payload.get("allow_php",True))),int(bool(payload.get("allow_ssh",False))),now(),now()))
            for key in FEATURE_CATALOG:
                c.execute("INSERT INTO package_features(package_id,feature_key,enabled) VALUES(?,?,?)", (cursor.lastrowid,key,int(bool(supplied.get(key, True)))))
        audit("package.create", name)
        return jsonify(ok=True,id=cursor.lastrowid), 201
    except sqlite3.IntegrityError: return jsonify(error="A package with that name already exists."), 409


@app.delete("/api/packages/<int:package_id>")
@require_auth
@require_admin
@require_csrf
def delete_hosting_package(package_id):
    with db() as c:
        if c.execute("SELECT 1 FROM accounts WHERE package_id=?",(package_id,)).fetchone(): return jsonify(error="Reassign accounts before deleting this package."), 409
        cursor = c.execute("DELETE FROM hosting_packages WHERE id=?",(package_id,))
    if not cursor.rowcount: return jsonify(error="Package not found."), 404
    audit("package.delete", str(package_id)); return jsonify(ok=True)


@app.put("/api/packages/<int:package_id>/features")
@require_auth
@require_admin
@require_csrf
def update_package_features(package_id):
    features = (request.get_json(silent=True) or {}).get("features")
    if not isinstance(features, dict) or any(key not in FEATURE_CATALOG or not isinstance(value, bool) for key,value in features.items()): return jsonify(error="Provide valid feature switches."), 400
    with db() as c:
        if not c.execute("SELECT 1 FROM hosting_packages WHERE id=?", (package_id,)).fetchone(): return jsonify(error="Package not found."), 404
        for key,value in features.items(): c.execute("INSERT INTO package_features(package_id,feature_key,enabled) VALUES(?,?,?) ON CONFLICT(package_id,feature_key) DO UPDATE SET enabled=excluded.enabled", (package_id,key,int(value)))
    audit("package.features", str(package_id)); return jsonify(ok=True)


@app.put("/api/users/<username>/features")
@require_auth
@require_admin
@require_csrf
def update_account_features(username):
    overrides = (request.get_json(silent=True) or {}).get("overrides")
    if not isinstance(overrides, dict) or any(key not in FEATURE_CATALOG or not (value is None or isinstance(value,bool)) for key,value in overrides.items()): return jsonify(error="Provide valid account feature overrides."), 400
    with db() as c:
        if not c.execute("SELECT 1 FROM accounts WHERE username=? AND role='client'", (username,)).fetchone(): return jsonify(error="Client account not found."), 404
        for key,value in overrides.items():
            if value is None: c.execute("DELETE FROM account_feature_overrides WHERE username=? AND feature_key=?", (username,key))
            else: c.execute("INSERT INTO account_feature_overrides(username,feature_key,enabled) VALUES(?,?,?) ON CONFLICT(username,feature_key) DO UPDATE SET enabled=excluded.enabled", (username,key,int(value)))
        effective = _effective_features(c, username)
    audit("user.features", username); return jsonify(ok=True,effective=effective)


@app.put("/api/users/<username>/package")
@require_auth
@require_admin
@require_csrf
def assign_hosting_package(username):
    payload = request.get_json(silent=True) or {}
    if payload.get("package_id") is None:
        with db() as c:
            cursor = c.execute("UPDATE accounts SET package_id=NULL WHERE username=? AND role='client'", (username,))
        if not cursor.rowcount: return jsonify(error="Client account not found."), 404
        audit("user.package", f"{username}:custom"); return jsonify(ok=True)
    try: package_id = int(payload.get("package_id"))
    except (TypeError,ValueError): return jsonify(error="Choose a hosting package."), 400
    with db() as c:
        package = c.execute("SELECT * FROM hosting_packages WHERE id=?",(package_id,)).fetchone()
        account = c.execute("SELECT system_username FROM accounts WHERE username=? AND role='client'",(username,)).fetchone()
        if not package: return jsonify(error="Package not found."), 404
        if not account: return jsonify(error="Client account not found."), 404
        current_domains = c.execute("SELECT COUNT(*) total FROM domains WHERE owner=?",(account["system_username"],)).fetchone()["total"]
        if current_domains > package["domain_limit"]: return jsonify(error="This account already exceeds the package domain limit."), 409
        c.execute("UPDATE accounts SET package_id=?,domain_limit=?,allow_domain_creation=? WHERE username=?",(package_id,package["domain_limit"],int(package["domain_limit"]>0),username))
    audit("user.package", f"{username}:{package_id}"); return jsonify(ok=True)


STORE_TEMPLATE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ store.store_name }}</title><style>
:root{color-scheme:dark;--ink:#eef4ff;--muted:#9fb0c9;--line:#263653;--blue:#4294ff;--panel:#111b2e}*{box-sizing:border-box}body{margin:0;background:#07101f;color:var(--ink);font:16px/1.55 system-ui,-apple-system,sans-serif}a{color:inherit}.wrap{width:min(1120px,92vw);margin:auto}header{display:flex;justify-content:space-between;align-items:center;padding:28px 0}.brand{font-weight:800;font-size:20px}.pill{border:1px solid var(--line);border-radius:99px;padding:8px 14px;color:var(--muted)}.hero{padding:80px 0 55px;max-width:780px}.eyebrow{color:#77b3ff;text-transform:uppercase;letter-spacing:.14em;font-size:12px;font-weight:800}.hero h1{font-size:clamp(42px,7vw,76px);line-height:1.03;margin:14px 0 20px}.hero p{font-size:20px;color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px;padding-bottom:80px}.card{position:relative;background:linear-gradient(150deg,#14213a,#0d1729);border:1px solid var(--line);border-radius:22px;padding:28px}.card.featured{border-color:#4294ff;box-shadow:0 18px 70px #1d69cf2b}.tag{position:absolute;right:18px;top:18px;background:#173d71;color:#a9d0ff;border-radius:99px;padding:5px 10px;font-size:12px}.price{font-size:38px;font-weight:800;margin:20px 0}.price small{font-size:14px;color:var(--muted);font-weight:500}.desc{color:var(--muted);min-height:50px}.limits{list-style:none;padding:0;margin:22px 0;color:#ccd8eb}.limits li{border-top:1px solid var(--line);padding:9px 0}.buy{display:block;width:100%;border:0;border-radius:11px;background:var(--blue);color:white;padding:13px;font-weight:800;cursor:pointer}.order{display:none;margin-top:18px}.order:target{display:block}.order input,.order select,.order textarea{width:100%;margin:5px 0 10px;padding:11px;background:#081223;color:white;border:1px solid var(--line);border-radius:8px}.order textarea{min-height:80px}.hp{position:absolute;left:-10000px}footer{border-top:1px solid var(--line);padding:28px 0;color:var(--muted)}{{ custom_css|safe }}</style></head><body><div class="wrap"><header><div class="brand">{{ store.store_name }}</div><a class="pill" href="mailto:{{ store.contact_email }}">Contact sales</a></header><section class="hero"><div class="eyebrow">Simple hosting. Clear pricing.</div><h1>Hosting that grows with your ideas.</h1><p>Choose a plan and send an order request. We will contact you to finish setup—no surprise checkout or automatic charge.</p></section><main class="grid">{% for product in packages %}<article class="card{% if product.featured %} featured{% endif %}">{% if product.featured %}<span class="tag">Popular</span>{% endif %}<h2>{{ product.display_name }}</h2><p class="desc">{{ product.description }}</p><div class="price">{{ store.currency }} {{ product.monthly_price }} <small>/ month</small></div><ul class="limits"><li>{{ product.domain_limit }} domains</li><li>{{ product.disk_mb }} MB storage</li><li>{{ product.mailbox_limit }} mailboxes</li><li>{{ product.database_limit }} databases</li></ul><a class="buy" href="#order-{{ product.id }}">Request this plan</a><form class="order" id="order-{{ product.id }}" action="/order" method="post"><input type="hidden" name="product_id" value="{{ product.id }}"><input class="hp" name="website" tabindex="-1" autocomplete="off"><input name="name" placeholder="Your name" required maxlength="120"><input type="email" name="email" placeholder="Email address" required maxlength="254"><input name="company" placeholder="Company (optional)" maxlength="120"><input name="domain" placeholder="Domain you want to use" maxlength="253"><select name="billing_cycle"><option value="monthly">Monthly — {{ store.currency }} {{ product.monthly_price }}</option>{% if product.yearly_price_cents %}<option value="yearly">Yearly — {{ store.currency }} {{ product.yearly_price }}</option>{% endif %}</select><textarea name="notes" placeholder="Anything we should know?" maxlength="1000"></textarea><button class="buy">Send order request</button></form></article>{% else %}<p>No packages are available yet.</p>{% endfor %}</main><footer>© {{ year }} {{ store.store_name }} · Orders are reviewed manually.</footer></div></body></html>"""

STORE_TEMPLATE_V2 = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>{{ store.store_name }}</title><style>
:root{--navy:#071d3a;--blue:#0878f9;--muted:#66758a;--line:#dce4ee;--soft:#f6f8fb;--green:#138a52}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:#fff;color:var(--navy);font:15px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}a{color:inherit;text-decoration:none}.container{width:min(1180px,calc(100% - 40px));margin:auto}.site-header{height:72px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{font-size:19px;font-weight:850;letter-spacing:-.025em}.site-header nav{display:flex;align-items:center;gap:28px;color:#526176;font-size:13px}.site-header .contact{border:1px solid #b9c7d7;border-radius:7px;padding:9px 14px;color:var(--navy);font-weight:750}.hero{padding:88px 0 62px;max-width:820px}.hero h1{font-size:clamp(43px,6.4vw,74px);line-height:1.01;letter-spacing:-.055em;margin:0 0 22px;max-width:790px}.hero p{font-size:19px;color:var(--muted);max-width:630px;margin:0}.plans-head{display:flex;align-items:end;justify-content:space-between;gap:24px;margin:0 0 22px}.plans-head h2{font-size:28px;letter-spacing:-.035em;margin:0}.plans-head p{margin:5px 0 0;color:var(--muted)}.billing{display:flex;align-items:center;border:1px solid var(--line);border-radius:7px;padding:3px;font-size:12px}.billing span{padding:6px 10px}.billing .active{background:#e9f3ff;color:var(--blue);border-radius:5px;font-weight:800}.plan-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;align-items:stretch;padding-bottom:45px}.plan{position:relative;border:1px solid var(--line);border-radius:10px;padding:26px;display:flex;flex-direction:column;min-height:455px;background:#fff}.plan.featured{border:2px solid var(--blue);padding:25px}.popular{position:absolute;left:-2px;right:-2px;top:-31px;height:30px;border-radius:9px 9px 0 0;background:var(--blue);color:#fff;display:grid;place-items:center;font-size:11px;font-weight:800}.plan h3{font-size:18px;margin:0}.description{color:var(--muted);font-size:13px;min-height:48px;margin:8px 0 18px}.price{font-size:35px;font-weight:850;letter-spacing:-.04em}.price small{font-size:12px;font-weight:550;color:var(--muted);letter-spacing:0}.yearly{font-size:11px;color:var(--muted);min-height:20px}.request{display:block;text-align:center;border:1px solid #b8c5d5;border-radius:7px;padding:10px;margin:20px 0;font-weight:800;font-size:12px}.featured .request{background:var(--blue);border-color:var(--blue);color:#fff}.features{list-style:none;padding:0;margin:0}.features li{padding:8px 0;border-top:1px solid #edf1f5;font-size:12px}.features li:before{content:"✓";color:var(--green);font-weight:900;margin-right:9px}.trust{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;padding:25px 0 70px;border-top:1px solid var(--line)}.trust b,.trust span{display:block}.trust b{font-size:12px}.trust span{font-size:10px;color:var(--muted);margin-top:3px}.empty{grid-column:1/-1;padding:70px 20px;text-align:center;border:1px dashed #c8d3df;border-radius:9px;color:var(--muted)}.footer{border-top:1px solid var(--line);padding:30px 0;display:flex;justify-content:space-between;color:var(--muted);font-size:11px}.drawer{position:fixed;inset:0;z-index:10;visibility:hidden;opacity:0;background:#071d3a35;transition:.18s}.drawer:target{visibility:visible;opacity:1}.drawer-panel{position:absolute;right:0;top:0;bottom:0;width:min(440px,100%);background:#fff;padding:28px;overflow:auto;transform:translateX(100%);transition:.22s ease}.drawer:target .drawer-panel{transform:translateX(0)}.drawer-head{display:flex;justify-content:space-between;align-items:start;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:20px}.drawer-head h2{margin:0;font-size:21px}.close{font-size:25px;line-height:1;color:#526176}.order-plan{background:var(--soft);border-radius:7px;padding:13px;margin-bottom:18px}.order-plan b,.order-plan span{display:block}.order-plan span{color:var(--muted);font-size:12px;margin-top:3px}.drawer label{display:grid;gap:6px;font-size:11px;font-weight:750;margin-bottom:13px}.drawer input,.drawer select,.drawer textarea{width:100%;border:1px solid #cbd6e2;border-radius:6px;padding:11px;font:inherit;color:var(--navy)}.drawer textarea{min-height:90px;resize:vertical}.submit{width:100%;border:0;border-radius:7px;background:var(--blue);color:#fff;padding:13px;font-weight:850;cursor:pointer}.hp{position:absolute;left:-10000px}{{ custom_css|safe }}
@media(max-width:850px){.site-header nav a:not(.contact){display:none}.hero{padding:65px 0 48px}.plans-head{align-items:start}.plan-grid{grid-template-columns:1fr}.plan{min-height:0}.plan.featured{margin-top:30px}.trust{grid-template-columns:1fr 1fr}.footer{gap:15px;flex-wrap:wrap}}@media(max-width:480px){.container{width:min(100% - 24px,1180px)}.hero h1{font-size:43px}.plans-head{display:grid}.trust{grid-template-columns:1fr}.drawer-panel{padding:20px}}
</style></head><body><div class="container"><header class="site-header"><a class="brand" href="/">{{ store.store_name }}</a><nav><a href="#plans">Plans</a><a href="mailto:{{ store.contact_email }}">Support</a><a class="contact" href="mailto:{{ store.contact_email }}">Contact sales</a></nav></header><section class="hero"><h1>Hosting built for real work</h1><p>Fast, secure hosting with straightforward plans and real support. Choose what fits today and upgrade when you need more.</p></section><section id="plans"><div class="plans-head"><div><h2>Choose a plan</h2><p>Clear limits. Manual review. No surprise automatic charges.</p></div><div class="billing"><span class="active">Monthly</span><span>Yearly available</span></div></div><main class="plan-grid">{% for product in packages %}<article class="plan{% if product.featured %} featured{% endif %}">{% if product.featured %}<div class="popular">Most popular</div>{% endif %}<h3>{{ product.display_name }}</h3><p class="description">{{ product.description }}</p><div class="price">{{ store.currency }} {{ product.monthly_price }} <small>/mo</small></div><div class="yearly">{% if product.yearly_price_cents %}{{ store.currency }} {{ product.yearly_price }} billed yearly{% else %}Monthly billing{% endif %}</div><a class="request" href="#order-{{ product.id }}">Request plan</a><ul class="features"><li>{{ product.domain_limit }} hosted domains</li><li>{{ product.disk_mb }} MB storage</li><li>{{ product.bandwidth_mb }} MB bandwidth</li><li>{{ product.mailbox_limit }} mailboxes</li><li>{{ product.database_limit }} databases</li>{% if product.allow_php %}<li>PHP applications</li>{% endif %}</ul></article>{% else %}<div class="empty"><b>Plans are being prepared.</b><br>Please contact sales for current hosting options.</div>{% endfor %}</main></section><section class="trust"><div><b>Secure by default</b><span>TLS certificates and isolated accounts</span></div><div><b>Grommunio mail</b><span>Email, calendars and contacts</span></div><div><b>WordPress ready</b><span>Managed installation tools</span></div><div><b>Real support</b><span>Orders reviewed by a person</span></div></section><footer class="footer"><b>{{ store.store_name }}</b><span>© {{ year }} · Orders are reviewed manually.</span><a href="mailto:{{ store.contact_email }}">{{ store.contact_email }}</a></footer></div>{% for product in packages %}<section class="drawer" id="order-{{ product.id }}"><form class="drawer-panel" action="/order" method="post"><div class="drawer-head"><div><h2>Request plan</h2><span>We will contact you to finish setup.</span></div><a class="close" href="#plans" aria-label="Close">×</a></div><div class="order-plan"><b>{{ product.display_name }}</b><span>{{ store.currency }} {{ product.monthly_price }}/month</span></div><input type="hidden" name="product_id" value="{{ product.id }}"><input class="hp" name="website" tabindex="-1" autocomplete="off"><label>Your name<input name="name" required maxlength="120" autocomplete="name"></label><label>Email address<input type="email" name="email" required maxlength="254" autocomplete="email"></label><label>Company<input name="company" maxlength="120" autocomplete="organization"></label><label>Domain you want to use<input name="domain" maxlength="253" placeholder="example.com"></label><label>Billing cycle<select name="billing_cycle"><option value="monthly">Monthly — {{ store.currency }} {{ product.monthly_price }}</option>{% if product.yearly_price_cents %}<option value="yearly">Yearly — {{ store.currency }} {{ product.yearly_price }}</option>{% endif %}</select></label><label>Anything we should know?<textarea name="notes" maxlength="1000"></textarea></label><button class="submit">Send order request</button></form></section>{% endfor %}</body></html>"""


def _store_payload(c):
    settings = dict(c.execute("SELECT * FROM store_settings WHERE id=1").fetchone())
    products = [dict(r) for r in c.execute("SELECT sp.*,p.name AS package_source_name,p.domain_limit,p.disk_mb,p.bandwidth_mb,p.database_limit,p.mailbox_limit,p.cron_limit,p.backup_limit,p.allow_php,p.allow_ssh FROM store_products sp JOIN hosting_packages p ON p.id=sp.package_id ORDER BY sp.sort_order,sp.id")]
    for item in products:
        item["monthly_price"] = f'{item["monthly_price_cents"] / 100:.2f}'
        item["yearly_price"] = f'{item["yearly_price_cents"] / 100:.2f}'
    return settings, products


def _store_public_data(settings, products):
    return {
        "store": {
            "name": settings["store_name"],
            "hostname": settings["hostname"],
            "currency": settings["currency"],
            "contact_email": settings["contact_email"],
        },
        "packages": products,
        "order_url": "/order",
        "data_url": "/data.json",
        "year": datetime.now().year,
    }


def _render_store(settings, products):
    source = settings["custom_template"] if settings["template_mode"] == "custom" and settings["custom_template"].strip() else STORE_TEMPLATE_V2
    environment = SandboxedEnvironment(loader=BaseLoader(), autoescape=select_autoescape(default_for_string=True, default=True), undefined=StrictUndefined)
    storefront = _store_public_data(settings, products)
    rendered = environment.from_string(source).render(store=settings, packages=products, storefront=storefront, custom_css="", custom_js="", year=storefront["year"])
    custom_css = str(settings.get("custom_css", ""))
    if custom_css:
        style = "<style id=masspanel-custom-css>" + custom_css.replace("</style", "<\\/style") + "</style>"
        rendered = re.sub(r"</head\s*>", style + "</head>", rendered, count=1, flags=re.I) if re.search(r"</head\s*>", rendered, re.I) else style + rendered
    data_json = json.dumps(storefront, ensure_ascii=False, separators=(",", ":")).replace("<", "\\u003c")
    custom_js = str(settings.get("custom_js", "")).replace("</script", "<\\/script")
    scripts = "<script>window.MassPanelStore=" + data_json + ";</script>"
    if custom_js: scripts += "<script id=masspanel-custom-js>" + custom_js + "</script>"
    return re.sub(r"</body\s*>", scripts + "</body>", rendered, count=1, flags=re.I) if re.search(r"</body\s*>", rendered, re.I) else rendered + scripts


@app.get("/api/store")
@require_auth
@require_admin
def store_admin():
    with db() as c:
        settings, products = _store_payload(c)
        packages = [dict(r) for r in c.execute("SELECT * FROM hosting_packages ORDER BY name")]
        orders = [dict(r) for r in c.execute("SELECT * FROM store_orders ORDER BY id DESC LIMIT 250")]
    return jsonify(settings=settings, products=products, packages=packages, orders=orders)


@app.get("/api/store/preview")
@require_auth
@require_admin
def store_preview():
    """Render the customer storefront for an administrator without publishing it."""
    with db() as c:
        settings, products = _store_payload(c)
    try:
        return Response(_render_store(settings, [product for product in products if product["enabled"]]), content_type="text/html; charset=utf-8")
    except TemplateError:
        return Response("The store template could not be rendered.", status=500)


@app.put("/api/store/settings")
@require_auth
@require_admin
@require_csrf
def save_store_settings():
    payload = request.get_json(silent=True) or {}
    hostname = str(payload.get("hostname", "")).lower().strip().rstrip(".")
    enabled = int(bool(payload.get("enabled")))
    mode = str(payload.get("template_mode", "default"))
    email = str(payload.get("contact_email", "")).strip()
    currency = str(payload.get("currency", "USD")).upper().strip()
    if enabled and not DOMAIN.fullmatch(hostname): return jsonify(error="Enter a valid store domain or subdomain before enabling the store."), 400
    if mode not in {"default", "custom"}: return jsonify(error="Invalid template mode."), 400
    if not re.fullmatch(r"[A-Z]{3}", currency): return jsonify(error="Use a three-letter currency code such as USD."), 400
    if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): return jsonify(error="Enter a valid contact email."), 400
    settings = {"store_name":str(payload.get("store_name","Hosting Store")).strip()[:80] or "Hosting Store", "hostname":hostname, "enabled":enabled, "currency":currency, "contact_email":email[:254], "template_mode":mode, "custom_template":str(payload.get("custom_template", ""))[:200000], "custom_css":str(payload.get("custom_css", ""))[:100000], "custom_js":str(payload.get("custom_js", ""))[:100000]}
    try:
        preview = {**settings, "id":1, "updated_at":now()}
        _render_store(preview, [])
        helper({"operation":"storefront_config", "hostname":hostname, "enabled":bool(enabled)})
        with db() as c:
            c.execute("UPDATE store_settings SET enabled=?,hostname=?,store_name=?,currency=?,contact_email=?,template_mode=?,custom_template=?,custom_css=?,custom_js=?,updated_at=? WHERE id=1", (enabled,hostname,settings["store_name"],currency,email,mode,settings["custom_template"],settings["custom_css"],settings["custom_js"],now()))
    except (RuntimeError, TemplateError) as exc: return jsonify(error=f"Store settings were not saved: {exc}"), 400
    audit("store.settings", hostname or "disabled")
    return jsonify(ok=True, url=("https://" if enabled else "http://") + hostname if hostname else "")


@app.put("/api/store/products/<int:package_id>")
@require_auth
@require_admin
@require_csrf
def save_store_product(package_id):
    payload = request.get_json(silent=True) or {}
    try:
        monthly = round(float(payload.get("monthly_price", 0)) * 100); yearly = round(float(payload.get("yearly_price", 0)) * 100)
        order = int(payload.get("sort_order", 0))
        if monthly < 0 or yearly < 0 or monthly > 100000000 or yearly > 100000000: raise ValueError()
    except (TypeError, ValueError): return jsonify(error="Enter valid non-negative prices."), 400
    with db() as c:
        package = c.execute("SELECT name FROM hosting_packages WHERE id=?", (package_id,)).fetchone()
        if not package: return jsonify(error="Hosting package not found."), 404
        name = str(payload.get("display_name", package["name"])).strip()[:80] or package["name"]
        c.execute("INSERT INTO store_products(package_id,display_name,description,monthly_price_cents,yearly_price_cents,enabled,featured,sort_order) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(package_id) DO UPDATE SET display_name=excluded.display_name,description=excluded.description,monthly_price_cents=excluded.monthly_price_cents,yearly_price_cents=excluded.yearly_price_cents,enabled=excluded.enabled,featured=excluded.featured,sort_order=excluded.sort_order", (package_id,name,str(payload.get("description", ""))[:1000],monthly,yearly,int(bool(payload.get("enabled",True))),int(bool(payload.get("featured"))),order))
    audit("store.product", str(package_id)); return jsonify(ok=True)


@app.put("/api/store/orders/<int:order_id>")
@require_auth
@require_admin
@require_csrf
def update_store_order(order_id):
    status = str((request.get_json(silent=True) or {}).get("status", ""))
    if status not in {"pending","contacted","approved","rejected","completed"}: return jsonify(error="Invalid order status."), 400
    with db() as c: cursor = c.execute("UPDATE store_orders SET status=?,updated_at=? WHERE id=?", (status,now(),order_id))
    if not cursor.rowcount: return jsonify(error="Order not found."), 404
    audit("store.order", f"{order_id}:{status}"); return jsonify(ok=True)


@app.post("/api/store/certificate")
@require_auth
@require_admin
@require_csrf
def store_certificate():
    with db() as c: settings = c.execute("SELECT hostname,enabled,contact_email FROM store_settings WHERE id=1").fetchone()
    if not settings or not settings["enabled"]: return jsonify(error="Enable the storefront first."), 409
    try: result = helper({"operation":"storefront_certificate", "hostname":settings["hostname"], "email":settings["contact_email"], "force":bool((request.get_json(silent=True) or {}).get("force"))})
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("store.certificate", settings["hostname"]); return jsonify(result)


@app.get("/store/")
def public_store():
    with db() as c: settings, products = _store_payload(c)
    host = request.host.split(":",1)[0].lower()
    if not settings["enabled"] or host != settings["hostname"]: return Response("Store not found", status=404)
    try: return Response(_render_store(settings, [p for p in products if p["enabled"]]), content_type="text/html; charset=utf-8")
    except TemplateError: return Response("The store template could not be rendered.", status=500)


@app.get("/store/data.json")
def public_store_data():
    with db() as c: settings, products = _store_payload(c)
    host = request.host.split(":",1)[0].lower()
    if not settings["enabled"] or host != settings["hostname"]: return jsonify(error="Store not found"), 404
    return jsonify(_store_public_data(settings, [p for p in products if p["enabled"]]))


@app.post("/store/order")
def public_store_order():
    host = request.host.split(":",1)[0].lower()
    if limited(("store-order", request.remote_addr), 6, 3600): return Response("Too many requests. Please try later.", status=429)
    if request.form.get("website"): return Response("Thanks", status=202)
    with db() as c:
        settings = c.execute("SELECT * FROM store_settings WHERE id=1").fetchone()
        if not settings or not settings["enabled"] or host != settings["hostname"]: return Response("Store not found", status=404)
        try: product_id = int(request.form.get("product_id", ""))
        except ValueError: return Response("Invalid package", status=400)
        product = c.execute("SELECT sp.id,sp.display_name FROM store_products sp WHERE sp.id=? AND sp.enabled=1", (product_id,)).fetchone()
        name = request.form.get("name", "").strip()[:120]; email = request.form.get("email", "").strip()[:254]
        cycle = request.form.get("billing_cycle", "monthly")
        if not product or not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or cycle not in {"monthly","yearly"}: return Response("Check the order details and try again.", status=400)
        number = "MP-" + datetime.now().strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper()
        c.execute("INSERT INTO store_orders(order_number,product_id,package_name,customer_name,customer_email,company,phone,requested_domain,billing_cycle,notes,status,created_at,updated_at,remote_addr) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (number,product_id,product["display_name"],name,email,request.form.get("company","").strip()[:120],request.form.get("phone","").strip()[:60],request.form.get("domain","").lower().strip()[:253],cycle,request.form.get("notes","").strip()[:1000],"pending",now(),now(),request.remote_addr))
    audit("store.order.create", number, actor="storefront")
    return Response(f"<!doctype html><meta name=viewport content='width=device-width'><title>Order received</title><body style='font:16px system-ui;max-width:620px;margin:12vh auto;padding:30px'><h1>Order request received</h1><p>Thank you, {html.escape(name)}. Your reference is <b>{number}</b>. We will contact you at {html.escape(email)}.</p><a href='/'>Return to store</a></body>", content_type="text/html; charset=utf-8", status=201)


@app.get("/api/tools/overview")
@require_auth
def hosting_tools_overview():
    username = session.get("system_username")
    with db() as c:
        query = "SELECT domain,owner,php_enabled,php_memory_limit,php_upload_limit,php_execution_time FROM domains"
        if session["role"] == "admin":
            domains = c.execute(query + " ORDER BY domain").fetchall()
            task_count = c.execute("SELECT COUNT(*) AS total FROM scheduled_tasks").fetchone()["total"]
        else:
            domains = c.execute(query + " WHERE owner=? ORDER BY domain", (username,)).fetchall()
            task_count = c.execute("SELECT COUNT(*) AS total FROM scheduled_tasks WHERE owner=?", (username,)).fetchone()["total"]
    services = []
    for name in ["nginx", "mariadb", "gromox-imap", "postfix@-", "rspamd", "masspanel"]:
        state = subprocess.run(["/usr/bin/systemctl", "is-active", name], capture_output=True, text=True, timeout=3, check=False).stdout.strip() or "unknown"
        services.append({"name": name, "state": state})
    disk = psutil.disk_usage("/")
    return jsonify(domains=[dict(row) for row in domains], task_count=task_count, services=services, resources={
        "cpu_percent": psutil.cpu_percent(interval=0.1), "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": disk.percent, "disk_free": disk.free,
    })


@app.get("/api/tools/services")
@require_auth
@require_admin
def managed_services():
    try:
        return jsonify(**helper({"operation":"service_list"}))
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 400


@app.post("/api/tools/services/<path:service>/<action>")
@require_auth
@require_admin
@require_csrf
def manage_service(service, action):
    if action not in {"start", "stop", "restart"}:
        return jsonify(error="Unsupported service action."), 400
    try:
        result = helper({"operation":"service_action", "service":service, "action":action})
        audit(f"service.{action}", service)
        return jsonify(**result)
    except RuntimeError as exc:
        audit(f"service.{action}", service, "failed")
        return jsonify(error=str(exc)), 400


def _backup_schedule_cron(row):
    minute, hour = int(row["minute"]), int(row["hour"])
    if row["frequency"] == "daily":
        return f"{minute} {hour} * * *"
    if row["frequency"] == "weekly":
        return f"{minute} {hour} * * {int(row['weekday'])}"
    return f"{minute} {hour} {int(row['monthday'])} * *"


def _backup_secret_box():
    key = base64.urlsafe_b64encode(hashlib.sha256(app.secret_key.encode("utf-8")).digest())
    return Fernet(key)


def _encrypt_backup_destination(config):
    if not config:
        return ""
    return _backup_secret_box().encrypt(json.dumps(config).encode("utf-8")).decode("ascii")


def _decrypt_backup_destination(value):
    if not value:
        return {}
    try:
        return json.loads(_backup_secret_box().decrypt(value.encode("ascii")).decode("utf-8"))
    except (InvalidToken, ValueError, json.JSONDecodeError):
        raise RuntimeError("The backup destination credentials cannot be decrypted.")


def _public_backup_schedule(row):
    item = dict(row)
    item.pop("destination_config", None)
    item["destination_configured"] = item.get("destination_type", "local") == "local" or bool(row["destination_config"])
    return item


def _validate_backup_destination(payload):
    kind = str(payload.get("destination_type", "local")).lower().strip()
    if kind not in {"local", "ftp", "sftp", "google_drive"}:
        raise ValueError("Choose local storage, FTP, SFTP or Google Drive.")
    remote_path = str(payload.get("remote_path", "MassPanel")).strip().strip("/") or "MassPanel"
    if ".." in remote_path.split("/") or len(remote_path) > 240:
        raise ValueError("Choose a valid remote backup folder.")
    if kind == "local":
        return kind, {}, remote_path
    config = payload.get("destination_config") or {}
    if not isinstance(config, dict):
        raise ValueError("Backup destination settings are invalid.")
    if kind in {"ftp", "sftp"}:
        required = ("host", "username", "password")
        if any(not str(config.get(field, "")).strip() for field in required):
            raise ValueError(f"{kind.upper()} host, username and password are required.")
        port = int(config.get("port") or (21 if kind == "ftp" else 22))
        if not 1 <= port <= 65535:
            raise ValueError("The remote port is invalid.")
        config = {"host":str(config["host"]).strip(), "port":port, "username":str(config["username"]).strip(), "password":str(config["password"])}
    else:
        token = config.get("token")
        if isinstance(token, str):
            try: token = json.loads(token)
            except json.JSONDecodeError as exc: raise ValueError("Paste a valid Google Drive OAuth token JSON object.") from exc
        if not isinstance(token, dict) or not token.get("access_token"):
            raise ValueError("A Google Drive OAuth token is required.")
        config = {"token":token, "client_id":str(config.get("client_id", "")).strip(), "client_secret":str(config.get("client_secret", "")).strip()}
    return kind, config, remote_path


def _sync_backup_schedules(c):
    rows = c.execute("SELECT id,frequency,hour,minute,weekday,monthday FROM backup_schedules WHERE enabled=1 ORDER BY id").fetchall()
    return helper({"operation":"backup_schedule_sync", "schedules":[{"id":row["id"], "cron":_backup_schedule_cron(row)} for row in rows]})


@app.get("/api/backup-schedules")
@require_auth
def list_backup_schedules():
    with db() as c:
        if session["role"] == "admin":
            rows = c.execute("SELECT * FROM backup_schedules ORDER BY domain,created_at").fetchall()
        else:
            rows = c.execute("SELECT * FROM backup_schedules WHERE owner=? ORDER BY domain,created_at", (session.get("system_username"),)).fetchall()
    return jsonify(schedules=[_public_backup_schedule(row) for row in rows])


@app.post("/api/backup-schedules")
@require_auth
@require_csrf
def create_backup_schedule():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    frequency = str(payload.get("frequency", "daily")).lower().strip()
    try:
        hour = int(payload.get("hour", 2)); minute = int(payload.get("minute", 0))
        weekday = int(payload.get("weekday", 0)); monthday = int(payload.get("monthday", 1)); retention = int(payload.get("retention", 3))
        destination_type, destination_config, remote_path = _validate_backup_destination(payload)
    except (TypeError, ValueError) as exc:
        return jsonify(error=str(exc) or "Backup schedule values are invalid."), 400
    if frequency not in {"daily", "weekly", "monthly"} or not 0 <= hour <= 23 or not 0 <= minute <= 59 or not 0 <= weekday <= 6 or not 1 <= monthday <= 28 or not 1 <= retention <= 30:
        return jsonify(error="Choose a valid daily, weekly or monthly backup schedule."), 400
    with db() as c:
        context = _domain_context(c, domain, session.get("system_username"))
        if not context:
            return jsonify(error="Domain not found or access denied."), 403
        if c.execute("SELECT 1 FROM backup_schedules WHERE domain=?", (domain,)).fetchone():
            return jsonify(error="This website already has a backup schedule."), 409
        package_limit = _package_limit(c, context["owner"], "backup_limit")
        if package_limit is not None and retention > package_limit:
            return jsonify(error=f"This package can keep at most {package_limit} backups."), 409
        schedule_id = secrets.token_hex(8)
        try:
            c.execute("INSERT INTO backup_schedules(id,owner,domain,frequency,hour,minute,weekday,monthday,retention,destination_type,destination_config,remote_path,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)",
                      (schedule_id,context["owner"],domain,frequency,hour,minute,weekday,monthday,retention,destination_type,_encrypt_backup_destination(destination_config),remote_path,now(),now()))
            _sync_backup_schedules(c)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
    audit("backup.schedule.create", domain)
    return jsonify(ok=True,id=schedule_id), 201


@app.post("/api/backup-schedules/<schedule_id>/toggle")
@require_auth
@require_csrf
def toggle_backup_schedule(schedule_id):
    with db() as c:
        row = c.execute("SELECT * FROM backup_schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")):
            return jsonify(error="Backup schedule not found."), 404
        enabled = 0 if row["enabled"] else 1
        try:
            c.execute("UPDATE backup_schedules SET enabled=?,updated_at=? WHERE id=?", (enabled,now(),schedule_id))
            _sync_backup_schedules(c)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
    audit("backup.schedule.toggle", row["domain"])
    return jsonify(ok=True,enabled=bool(enabled))


@app.post("/api/backup-schedules/<schedule_id>/run")
@require_auth
@require_csrf
def run_backup_schedule_now(schedule_id):
    with db() as c:
        row = c.execute("SELECT * FROM backup_schedules WHERE id=?", (schedule_id,)).fetchone()
    if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")):
        return jsonify(error="Backup schedule not found."), 404
    try:
        result = run_backup_schedule(schedule_id, allow_disabled=True)
        audit("backup.schedule.run", row["domain"])
        return jsonify(ok=True, **result)
    except RuntimeError as exc:
        audit("backup.schedule.run", row["domain"], "failed")
        return jsonify(error=str(exc)), 400


@app.delete("/api/backup-schedules/<schedule_id>")
@require_auth
@require_csrf
def delete_backup_schedule(schedule_id):
    with db() as c:
        row = c.execute("SELECT * FROM backup_schedules WHERE id=?", (schedule_id,)).fetchone()
        if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")):
            return jsonify(error="Backup schedule not found."), 404
        try:
            c.execute("DELETE FROM backup_schedules WHERE id=?", (schedule_id,))
            _sync_backup_schedules(c)
        except RuntimeError as exc:
            return jsonify(error=str(exc)), 400
    audit("backup.schedule.delete", row["domain"])
    return jsonify(ok=True)


@app.get("/api/cron")
@require_auth
def list_scheduled_tasks():
    with db() as c:
        rows = c.execute("SELECT * FROM scheduled_tasks ORDER BY owner,name,id").fetchall() if session["role"] == "admin" else c.execute(
            "SELECT * FROM scheduled_tasks WHERE owner=? ORDER BY name,id", (session.get("system_username"),)
        ).fetchall()
    return jsonify(tasks=[dict(row) for row in rows])


@app.post("/api/cron")
@require_auth
@require_csrf
def create_scheduled_task():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".") or None
    name = str(payload.get("name", "")).strip()
    if not name or len(name) > 80: return jsonify(error="Enter a task name of no more than 80 characters."), 400
    try:
        schedule = _validate_schedule(payload.get("schedule"))
        command = _validate_task_command(payload.get("command"))
    except RuntimeError as exc: return jsonify(error=str(exc)), 400
    with db() as c:
        if domain:
            context = _domain_context(c, domain, session.get("system_username"))
            if not context: return jsonify(error="Domain not found or access denied."), 403
            owner = context["owner"]
        elif session["role"] == "admin":
            owner = str(payload.get("owner", "")).strip()
            if not c.execute("SELECT 1 FROM accounts WHERE system_username=?", (owner,)).fetchone():
                return jsonify(error="Choose a valid hosting account."), 400
        else: owner = session.get("system_username")
        package = c.execute("SELECT p.cron_limit FROM accounts a JOIN hosting_packages p ON p.id=a.package_id WHERE a.system_username=?", (owner,)).fetchone()
        current_tasks = c.execute("SELECT COUNT(*) AS total FROM scheduled_tasks WHERE owner=?", (owner,)).fetchone()["total"]
        if package and current_tasks >= package["cron_limit"]:
            return jsonify(error="This hosting package has reached its scheduled-task limit."), 409
        task_id = secrets.token_hex(8)
        try:
            c.execute("INSERT INTO scheduled_tasks(id,owner,domain,name,schedule,command,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,1,?,?)",
                      (task_id, owner, domain, name, schedule, command, now(), now()))
            _sync_owner_tasks(c, owner)
        except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("cron.create", f"{owner}:{name}")
    return jsonify(ok=True, id=task_id), 201


@app.post("/api/cron/<task_id>/toggle")
@require_auth
@require_csrf
def toggle_scheduled_task(task_id):
    with db() as c:
        row = c.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
        if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")): return jsonify(error="Scheduled task not found."), 404
        enabled = 0 if row["enabled"] else 1
        try:
            c.execute("UPDATE scheduled_tasks SET enabled=?,updated_at=? WHERE id=?", (enabled, now(), task_id))
            _sync_owner_tasks(c, row["owner"])
        except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("cron.toggle", task_id)
    return jsonify(ok=True, enabled=bool(enabled))


@app.post("/api/cron/<task_id>/run")
@require_auth
@require_csrf
def run_scheduled_task(task_id):
    with db() as c: row = c.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
    if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")): return jsonify(error="Scheduled task not found."), 404
    try:
        result = helper({"operation":"cron_run", "owner":row["owner"], "command":row["command"]})
        audit("cron.run", task_id)
        return jsonify(ok=True, output=result.get("output", ""))
    except RuntimeError as exc:
        audit("cron.run", task_id, "failed")
        return jsonify(error=str(exc)), 400


@app.delete("/api/cron/<task_id>")
@require_auth
@require_csrf
def delete_scheduled_task(task_id):
    with db() as c:
        row = c.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
        if not row or (session["role"] != "admin" and row["owner"] != session.get("system_username")): return jsonify(error="Scheduled task not found."), 404
        try:
            c.execute("DELETE FROM scheduled_tasks WHERE id=?", (task_id,))
            _sync_owner_tasks(c, row["owner"])
        except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("cron.delete", task_id)
    return jsonify(ok=True)


@app.put("/api/tools/php/<path:domain>")
@require_auth
@require_csrf
def update_domain_php(domain):
    payload = request.get_json(silent=True) or {}; domain = domain.lower().strip().strip("."); enabled = bool(payload.get("enabled"))
    try: memory, upload, execution = int(payload.get("memory_limit",256)), int(payload.get("upload_limit",64)), int(payload.get("execution_time",120))
    except (TypeError, ValueError): return jsonify(error="PHP limits must be numbers."), 400
    if not 32 <= memory <= 2048 or not 2 <= upload <= 2048 or not 10 <= execution <= 3600: return jsonify(error="PHP limits are outside the supported range."), 400
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username"))
        if not row: return jsonify(error="Domain not found or access denied."), 403
        package = c.execute("SELECT p.allow_php FROM accounts a JOIN hosting_packages p ON p.id=a.package_id WHERE a.system_username=?", (row["owner"],)).fetchone()
        if enabled and package and not package["allow_php"]: return jsonify(error="PHP is disabled by this hosting package."), 403
        try:
            helper({"operation":"php_config", "domain":domain, "owner":row["owner"], "webroot":row["webroot"], "ssl_mode":row["ssl_mode"],
                    "suspended":bool(row["suspended"]), "enabled":enabled, "memory_limit":memory, "upload_limit":upload, "execution_time":execution})
            c.execute("UPDATE domains SET php_enabled=?,php_memory_limit=?,php_upload_limit=?,php_execution_time=? WHERE domain=?",
                      (int(enabled),memory,upload,execution,domain))
        except RuntimeError as exc: return jsonify(error=str(exc)), 400
    audit("php.configure", domain)
    return jsonify(ok=True, domain=domain, php_enabled=enabled, php_memory_limit=memory, php_upload_limit=upload, php_execution_time=execution)


@app.get("/api/tools/logs/<path:domain>")
@require_auth
def website_logs(domain):
    domain = domain.lower().strip().strip(".")
    try: lines = min(500, max(20, int(request.args.get("lines",100))))
    except ValueError: lines = 100
    with db() as c: row = _domain_context(c, domain, session.get("system_username"))
    if not row: return jsonify(error="Domain not found or access denied."), 403
    try: return jsonify(**helper({"operation":"website_logs", "domain":domain, "owner":row["owner"], "webroot":row["webroot"], "lines":lines}))
    except RuntimeError as exc: return jsonify(error=str(exc)), 400


@app.get("/api/backups")
@require_auth
def list_backups():
    domain = str(request.args.get("domain", "")).lower().strip().strip(".")
    with db() as c:
        if session["role"] == "admin":
            if domain:
                rows = c.execute(
                    "SELECT id,domain,filename,size_bytes,created_by,created_at FROM backups WHERE domain=? ORDER BY id DESC",
                    (domain,),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT id,domain,filename,size_bytes,created_by,created_at FROM backups ORDER BY id DESC"
                ).fetchall()
        else:
            rows = c.execute(
                "SELECT b.id,b.domain,b.filename,b.size_bytes,b.created_by,b.created_at "
                "FROM backups b JOIN domains d ON d.domain=b.domain "
                "WHERE d.owner=? ORDER BY b.id DESC",
                (session.get("system_username"),),
            ).fetchall()
    return jsonify(backups=[dict(r) for r in rows])


def _validate_domain_for_backup(c, domain, username):
    row = c.execute("SELECT webroot,owner FROM domains WHERE domain=?", (domain,)).fetchone()
    if not row:
        return None
    if session["role"] != "admin" and row["owner"] != username:
        return None
    return row


def _create_backup_archive(domain, webroot, actor, schedule_id=None):
    if not webroot or not Path(webroot).exists():
        raise RuntimeError("Domain path not found.")
    filename = f"{domain.replace('.', '_')}-{int(time.time())}-{secrets.token_hex(4)}.tar.gz"
    backup_file = BACKUP_DIR / filename
    try:
        with tarfile.open(backup_file, "w:gz") as archive:
            archive.add(webroot, arcname=".", recursive=True)
    except Exception as exc:
        backup_file.unlink(missing_ok=True)
        raise RuntimeError(f"Backup failed: {exc}") from exc
    size = backup_file.stat().st_size
    with db() as c:
        cursor = c.execute(
            "INSERT INTO backups(domain,filename,size_bytes,created_by,created_at,schedule_id) VALUES(?,?,?,?,?,?)",
            (domain,str(backup_file),size,actor,now(),schedule_id),
        )
    return {"id":cursor.lastrowid,"size":size,"filename":str(backup_file)}


def _rclone_backup(row, local_filename):
    kind = row["destination_type"] or "local"
    if kind == "local":
        return
    if not shutil.which("rclone"):
        raise RuntimeError("Remote backup support is unavailable because rclone is not installed.")
    settings = _decrypt_backup_destination(row["destination_config"])
    parser = configparser.RawConfigParser()
    section = "masspanel_backup"
    if kind in {"ftp", "sftp"}:
        obscured = subprocess.run(["rclone", "obscure", settings["password"]], capture_output=True, text=True, timeout=15)
        if obscured.returncode:
            raise RuntimeError("Could not protect the remote backup password.")
        parser[section] = {"type":kind, "host":settings["host"], "port":str(settings["port"]), "user":settings["username"], "pass":obscured.stdout.strip()}
    else:
        parser[section] = {"type":"drive", "scope":"drive.file", "token":json.dumps(settings["token"], separators=(",", ":"))}
        if settings.get("client_id"): parser[section]["client_id"] = settings["client_id"]
        if settings.get("client_secret"): parser[section]["client_secret"] = settings["client_secret"]
    remote_dir = f"{section}:{row['remote_path'].strip('/')}/{row['domain']}"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        parser.write(handle)
        config_path = handle.name
    try:
        os.chmod(config_path, 0o600)
        command = ["rclone", "copyto", local_filename, f"{remote_dir}/{Path(local_filename).name}", "--config", config_path, "--retries", "3"]
        upload = subprocess.run(command, capture_output=True, text=True, timeout=3600)
        if upload.returncode:
            raise RuntimeError(f"Remote upload failed: {(upload.stderr or upload.stdout).strip()[:300]}")
        listing = subprocess.run(["rclone", "lsf", remote_dir, "--files-only", "--config", config_path], capture_output=True, text=True, timeout=120)
        if listing.returncode == 0:
            prefix = row["domain"].replace(".", "_") + "-"
            names = sorted((name.strip() for name in listing.stdout.splitlines() if name.strip().startswith(prefix) and name.strip().endswith(".tar.gz")), reverse=True)
            for name in names[int(row["retention"]):]:
                subprocess.run(["rclone", "deletefile", f"{remote_dir}/{name}", "--config", config_path], capture_output=True, timeout=120)
    finally:
        Path(config_path).unlink(missing_ok=True)


def run_backup_schedule(schedule_id, allow_disabled=False):
    with db() as c:
        row = c.execute("SELECT s.*,d.webroot FROM backup_schedules s JOIN domains d ON d.domain=s.domain WHERE s.id=?", (schedule_id,)).fetchone()
    if not row or (not row["enabled"] and not allow_disabled):
        raise RuntimeError("Backup schedule is unavailable or paused.")
    try:
        result = _create_backup_archive(row["domain"],row["webroot"],"scheduled-backup",schedule_id)
        _rclone_backup(row, result["filename"])
        expired = []
        with db() as c:
            old = c.execute("SELECT id,filename FROM backups WHERE schedule_id=? ORDER BY id DESC LIMIT -1 OFFSET ?", (schedule_id,row["retention"])).fetchall()
            expired = [dict(item) for item in old]
            for item in old:
                c.execute("DELETE FROM backups WHERE id=?", (item["id"],))
            c.execute("UPDATE backup_schedules SET last_run_at=?,last_status='success',last_error='',updated_at=? WHERE id=?", (now(),now(),schedule_id))
        for item in expired:
            Path(item["filename"]).unlink(missing_ok=True)
        return {"backup_id":result["id"],"size":result["size"],"removed":len(expired)}
    except RuntimeError as exc:
        with db() as c:
            c.execute("UPDATE backup_schedules SET last_run_at=?,last_status='failed',last_error=?,updated_at=? WHERE id=?", (now(),str(exc)[:500],now(),schedule_id))
        raise


@app.post("/api/backups")
@require_auth
@require_csrf
def create_backup():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    with db() as c:
        row = _validate_domain_for_backup(c, domain, session.get("system_username"))
        if not row:
            return jsonify(error="No access to that domain."), 403
        package_limit = _package_limit(c, row["owner"], "backup_limit")
        current_total = c.execute(
            "SELECT COUNT(*) AS total FROM backups b JOIN domains d ON d.domain=b.domain WHERE d.owner=?",
            (row["owner"],),
        ).fetchone()["total"]
        if package_limit is not None and current_total >= package_limit:
            return jsonify(error="This hosting package has reached its backup limit."), 409
        webroot = row["webroot"]

    try:
        result = _create_backup_archive(domain,webroot,session["username"])
    except RuntimeError as exc:
        return jsonify(error=str(exc)), 500

    audit("backup.create", domain)
    return jsonify(ok=True, id=result["id"], size=result["size"])


@app.get("/api/backups/<int:backup_id>/download")
@require_auth
def download_backup(backup_id):
    with db() as c:
        row = c.execute(
            "SELECT b.id,b.domain,b.filename,d.owner "
            "FROM backups b JOIN domains d ON d.domain=b.domain "
            "WHERE b.id=?",
            (backup_id,),
        ).fetchone()
        if not row:
            return jsonify(error="Backup not found."), 404
        if session["role"] != "admin" and row["owner"] != session.get("system_username"):
            return jsonify(error="No access to this backup."), 403
    filepath = Path(row["filename"])
    if not filepath.exists():
        return jsonify(error="Backup file missing."), 404
    return send_file(
        filepath,
        as_attachment=True,
        download_name=filepath.name,
        mimetype="application/gzip",
    )


@app.post("/api/backups/<int:backup_id>/restore")
@require_auth
@require_admin
@require_csrf
def restore_backup(backup_id):
    with db() as c:
        row = c.execute(
            "SELECT b.domain,b.filename,d.owner FROM backups b JOIN domains d ON d.domain=b.domain WHERE b.id=?",
            (backup_id,),
        ).fetchone()
        if not row:
            return jsonify(error="Backup not found."), 404
        owner = row["owner"]
        if session["role"] != "admin" and owner != session.get("system_username"):
            return jsonify(error="No access to this backup."), 403
        webroot = c.execute("SELECT webroot FROM domains WHERE domain=?", (row["domain"],)).fetchone()["webroot"]
    backup_path = Path(row["filename"])
    if not backup_path.exists():
        return jsonify(error="Backup file missing."), 404
    try:
        with tarfile.open(backup_path, "r:gz") as archive:
            archive.extractall(path=webroot, filter="data")
    except Exception as exc:
        return jsonify(error=f"Restore failed: {exc}"), 500
    audit("backup.restore", row["domain"])
    return jsonify(ok=True)


@app.delete("/api/backups/<int:backup_id>")
@require_auth
@require_csrf
def delete_backup(backup_id):
    with db() as c:
        row = c.execute(
            "SELECT b.filename,d.owner,b.domain FROM backups b JOIN domains d ON d.domain=b.domain WHERE b.id=?",
            (backup_id,),
        ).fetchone()
        if not row:
            return jsonify(error="Backup not found."), 404
        if session["role"] != "admin" and row["owner"] != session.get("system_username"):
            return jsonify(error="No access to this backup."), 403
        c.execute("DELETE FROM backups WHERE id=?", (backup_id,))
    filepath = Path(row["filename"])
    if filepath.exists():
        filepath.unlink()
    audit("backup.delete", row["domain"])
    return jsonify(ok=True)


@app.get("/api/ssl")
@require_auth
def list_ssl():
    with db() as c:
        if session["role"] == "admin":
            rows = c.execute("SELECT domain,ssl_mode FROM domains ORDER BY domain").fetchall()
        else:
            rows = c.execute(
                "SELECT domain,ssl_mode FROM domains WHERE owner=? ORDER BY domain",
                (session.get("system_username"),),
            ).fetchall()
    status = service_domain_status()
    services = []
    if status["panel_hostname"]:
        services.append({"kind":"panel", "domain":status["panel_hostname"], "label":"Panel domain", "tls_ready":status["checks"]["panel_tls"]})
    if status["mail_hostname"]:
        services.append({"kind":"mail", "domain":status["mail_hostname"], "label":"Mail server", "tls_ready":status["checks"]["mail_tls"]})
    return jsonify(items=[dict(r) for r in rows], services=services)


@app.post("/api/ssl/service/mail/regenerate")
@require_auth
@require_admin
@require_csrf
def regenerate_mail_service_ssl():
    status = service_domain_status()
    if not status["mail_hostname"]: return jsonify(error="Configure the mail hostname in Settings first."), 409
    if not status["checks"]["mail_a"]: return jsonify(error=f"Public DNS for {status['mail_hostname']} must point to {status['server_ip']} first."), 409
    try:
        result = helper({"operation":"mail_certificate", "hostname":status["mail_hostname"],
                         "email":product_settings().get("support_email", ""), "force":True})
        audit("service.ssl.regenerate", status["mail_hostname"])
        return jsonify(result)
    except RuntimeError as exc:
        audit("service.ssl.regenerate", status["mail_hostname"], "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/ssl/service/panel/regenerate")
@require_auth
@require_admin
@require_csrf
def regenerate_panel_service_ssl():
    status = service_domain_status()
    if not status["panel_hostname"]: return jsonify(error="Configure the panel / UI URL in Settings first."), 409
    if not status["checks"]["panel_a"]: return jsonify(error=f"Public DNS for {status['panel_hostname']} must point to {status['server_ip']} first."), 409
    try:
        result = helper({"operation":"panel_certificate", "hostname":status["panel_hostname"],
                         "email":product_settings().get("support_email", ""), "force":True})
        audit("service.ssl.regenerate", status["panel_hostname"])
        return jsonify(result)
    except RuntimeError as exc:
        audit("service.ssl.regenerate", status["panel_hostname"], "failed")
        return jsonify(error=str(exc)), 400


@app.post("/api/ssl/<path:domain>/regenerate")
@require_auth
@require_csrf
def regenerate_ssl(domain):
    domain = domain.lower().strip().strip(".")
    with db() as c:
        row = _domain_context(c, domain, session.get("system_username", ""))
        if not row:
            return jsonify(error="Domain not found or access denied."), 404
        state = c.execute("SELECT ssl_mode,suspended FROM domains WHERE domain=?", (domain,)).fetchone()
        if state["ssl_mode"] != "letsencrypt":
            return jsonify(error="Select and save Let's Encrypt before regenerating this certificate."), 409
        if state["suspended"]:
            return jsonify(error="Unsuspend the website before regenerating its certificate."), 409
    try:
        result = helper({"operation":"domain_certificate_regenerate", "domain":domain, "owner":row["owner"],
            "webroot":row["webroot"], "email":product_settings().get("support_email", "")})
        audit("domain.ssl.regenerate", domain)
        return jsonify(result)
    except RuntimeError as exc:
        audit("domain.ssl.regenerate", domain, "failed")
        return jsonify(error=str(exc)), 400


def _can_access_ticket(c, ticket):
    if session["role"] == "admin" or ticket["requester"] == session["username"]: return True
    if not ticket["domain"]: return False
    if session["role"] == "reseller":
        return bool(c.execute("SELECT 1 FROM domains WHERE domain=? AND created_by=?", (ticket["domain"],session["username"])).fetchone())
    return bool(c.execute("SELECT 1 FROM domains WHERE domain=? AND owner=?", (ticket["domain"],session.get("system_username"))).fetchone())


@app.get("/api/tickets")
@require_auth
def list_tickets():
    with db() as c:
        if session["role"] == "admin":
            rows = c.execute(
                "SELECT id,domain,requester,subject,body,priority,status,target_role,created_at,updated_at "
                "FROM support_tickets ORDER BY id DESC"
            ).fetchall()
            domains = c.execute("SELECT domain,owner,created_by FROM domains ORDER BY domain").fetchall()
            customers = c.execute("SELECT username,system_username,active FROM accounts WHERE role='client' ORDER BY username").fetchall()
        elif session["role"] == "reseller":
            rows = c.execute(
                "SELECT id,domain,requester,subject,body,priority,status,target_role,created_at,updated_at FROM support_tickets "
                "WHERE requester=? OR domain IN (SELECT domain FROM domains WHERE created_by=?) ORDER BY id DESC",
                (session["username"], session["username"]),
            ).fetchall()
            domains = c.execute("SELECT domain,owner,created_by FROM domains WHERE created_by=? ORDER BY domain", (session["username"],)).fetchall()
            customers = c.execute(
                "SELECT DISTINCT a.username,a.system_username,a.active FROM accounts a JOIN domains d ON d.owner=a.system_username "
                "WHERE d.created_by=? ORDER BY a.username", (session["username"],)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT id,domain,requester,subject,body,priority,status,target_role,created_at,updated_at "
                "FROM support_tickets "
                "WHERE requester=? OR domain IN (SELECT domain FROM domains WHERE owner=?) "
                "ORDER BY id DESC",
                (session["username"], session.get("system_username")),
            ).fetchall()
            domains = c.execute("SELECT domain,owner,created_by FROM domains WHERE owner=? ORDER BY domain", (session.get("system_username"),)).fetchall()
            customers = []
    tickets = [dict(r) for r in rows]
    counts = {"all":len(tickets),"open":0,"in_progress":0,"closed":0,"urgent":0}
    for ticket in tickets:
        counts[ticket["status"]] = counts.get(ticket["status"], 0) + 1
        if ticket["priority"] == "urgent" and ticket["status"] != "closed": counts["urgent"] += 1
    return jsonify(tickets=tickets, domains=[dict(r) for r in domains], customers=[dict(r) for r in customers], overview=counts,
                   can_contact_owner=session["role"] == "reseller", scope=session["role"])


@app.get("/api/tickets/<int:ticket_id>")
@require_auth
def get_ticket(ticket_id):
    with db() as c:
        ticket = c.execute(
            "SELECT id,domain,requester,subject,body,priority,status,created_at,updated_at "
            "FROM support_tickets WHERE id=?",
            (ticket_id,),
        ).fetchone()
        if not ticket:
            return jsonify(error="Ticket not found."), 404
        if not _can_access_ticket(c, ticket): return jsonify(error="No access to this ticket."), 403
        replies = c.execute(
            "SELECT id,author,message,created_at FROM ticket_replies WHERE ticket_id=? ORDER BY id",
            (ticket_id,),
        ).fetchall()
    return jsonify(ticket=dict(ticket), replies=[dict(r) for r in replies])


@app.post("/api/tickets")
@require_auth
@require_csrf
def create_ticket():
    payload = request.get_json(silent=True) or {}
    subject = str(payload.get("subject", "")).strip()
    body = str(payload.get("body", "")).strip()
    domain = str(payload.get("domain", "")).lower().strip().strip(".")
    priority = str(payload.get("priority", "normal"))
    contact_owner = bool(payload.get("contact_owner"))

    if not subject or not body:
        return jsonify(error="Subject and message are required."), 400
    if priority not in TICKET_PRIORITIES:
        return jsonify(error="Invalid ticket priority."), 400

    with db() as c:
        if contact_owner and session["role"] != "reseller":
            return jsonify(error="Only reseller accounts can use owner escalation."), 403
        if domain:
            allowed = _can_access_domain(c, domain, session.get("system_username"))
            if session["role"] == "reseller":
                allowed = bool(c.execute("SELECT 1 FROM domains WHERE domain=? AND created_by=?", (domain,session["username"])).fetchone())
            if session["role"] != "admin" and not allowed:
                return jsonify(error="No access to this domain."), 403
        created = now()
        cursor = c.execute(
            "INSERT INTO support_tickets(domain,requester,subject,body,priority,status,target_role,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (domain or None, session["username"], subject, body, priority, "open", "owner" if contact_owner else "provider", created, created),
        )
        ticket_id = cursor.lastrowid
    audit("ticket.create", str(ticket_id))
    return jsonify(ok=True, id=ticket_id), 201


@app.post("/api/tickets/<int:ticket_id>/status")
@require_auth
@require_csrf
def update_ticket_status(ticket_id):
    payload = request.get_json(silent=True) or {}
    status = payload.get("status", "")
    if status not in TICKET_STATUS:
        return jsonify(error="Invalid ticket status."), 400
    with db() as c:
        ticket = c.execute("SELECT requester,domain,status FROM support_tickets WHERE id=?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify(error="Ticket not found."), 404
        if not _can_access_ticket(c, ticket): return jsonify(error="No access to this ticket."), 403
        c.execute(
            "UPDATE support_tickets SET status=?,updated_at=? WHERE id=?",
            (status, now(), ticket_id),
        )
    audit("ticket.status", str(ticket_id))
    return jsonify(ok=True)


@app.post("/api/tickets/<int:ticket_id>/reply")
@require_auth
@require_csrf
def reply_ticket(ticket_id):
    payload = request.get_json(silent=True) or {}
    message = str(payload.get("message", "")).strip()
    if not message:
        return jsonify(error="Message cannot be empty."), 400
    with db() as c:
        ticket = c.execute("SELECT requester,domain FROM support_tickets WHERE id=?", (ticket_id,)).fetchone()
        if not ticket:
            return jsonify(error="Ticket not found."), 404
        if not _can_access_ticket(c, ticket): return jsonify(error="No access to this ticket."), 403
        c.execute(
            "INSERT INTO ticket_replies(ticket_id,author,message,created_at) VALUES(?,?,?,?)",
            (ticket_id, session["username"], message, now()),
        )
        c.execute("UPDATE support_tickets SET updated_at=? WHERE id=?", (now(), ticket_id))
    audit("ticket.reply", str(ticket_id))
    return jsonify(ok=True)


@app.delete("/api/tickets/<int:ticket_id>")
@require_auth
@require_csrf
def delete_ticket(ticket_id):
    with db() as c:
        ticket = c.execute(
            "SELECT requester,domain FROM support_tickets WHERE id=?",
            (ticket_id,),
        ).fetchone()
        if not ticket:
            return jsonify(error="Ticket not found."), 404
        if not _can_access_ticket(c, ticket): return jsonify(error="No access to this ticket."), 403
        c.execute("DELETE FROM ticket_replies WHERE ticket_id=?", (ticket_id,))
        c.execute("DELETE FROM support_tickets WHERE id=?", (ticket_id,))
    audit("ticket.delete", str(ticket_id))
    return jsonify(ok=True)


@app.get("/api/audit")
@require_auth
@require_admin
def get_audit():
    with db() as c:
        rows = c.execute(
            "SELECT id,created_at,action,target,outcome FROM audit ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return jsonify(items=[dict(r) for r in rows])


def cli():
    init_db()
    if len(os.sys.argv) == 3 and os.sys.argv[1] == "init-admin":
        password = os.environ.get("MASSPANEL_INITIAL_PASSWORD")
        if not password or len(password) < 16:
            raise SystemExit("MASSPANEL_INITIAL_PASSWORD must be at least 16 characters.")
        with db() as c:
            c.execute(
                "INSERT OR REPLACE INTO accounts(username,password_hash,role,system_username,created_at) "
                "VALUES(?,?,'admin',NULL,?)",
                (os.sys.argv[2], ph.hash(password), now()),
            )
        print("Administrator initialized.")


init_db()
if __name__ == "__main__":
    cli()
