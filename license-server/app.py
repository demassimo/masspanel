import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from flask import Flask, Response, jsonify, redirect, render_template_string, request, url_for


STATE_DIR = Path(os.environ.get("MASSPANEL_LICENSE_STATE", "/var/lib/masspanel-license"))
DB_PATH = STATE_DIR / "licenses.db"
PRIVATE_KEY_PATH = STATE_DIR / "signing-key.pem"
PUBLIC_KEY_PATH = STATE_DIR / "signing-public.pem"
ADMIN_USERNAME = os.environ.get("MASSPANEL_LICENSE_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("MASSPANEL_LICENSE_ADMIN_PASSWORD", "")
GRACE_DAYS = int(os.environ.get("MASSPANEL_LICENSE_GRACE_DAYS", "14"))

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=32 * 1024, JSON_SORT_KEYS=True)


def utcnow():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def b64url(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_state():
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    if not PRIVATE_KEY_PATH.exists():
        private_key = Ed25519PrivateKey.generate()
        PRIVATE_KEY_PATH.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        PUBLIC_KEY_PATH.write_bytes(private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        os.chmod(PRIVATE_KEY_PATH, 0o600)
        os.chmod(PUBLIC_KEY_PATH, 0o644)
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS licenses(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          key_hash TEXT NOT NULL UNIQUE,
          key_hint TEXT NOT NULL,
          customer_name TEXT NOT NULL,
          customer_email TEXT NOT NULL,
          plan TEXT NOT NULL CHECK(plan IN ('unlimited')),
          status TEXT NOT NULL CHECK(status IN ('active','revoked')) DEFAULT 'active',
          expires_at TEXT NOT NULL,
          max_installations INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activations(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          license_id INTEGER NOT NULL,
          installation_id TEXT NOT NULL,
          instance_url TEXT NOT NULL DEFAULT '',
          secret_hash TEXT NOT NULL,
          created_at TEXT NOT NULL,
          last_seen_at TEXT NOT NULL,
          UNIQUE(license_id, installation_id),
          FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_activations_installation ON activations(installation_id);
        """)


def private_key():
    return serialization.load_pem_private_key(PRIVATE_KEY_PATH.read_bytes(), password=None)


def sign_entitlement(license_row, installation_id):
    expiry = parse_iso(license_row["expires_at"])
    payload = {
        "v": 1,
        "issuer": "MassPanel Licensing",
        "plan": license_row["plan"],
        "domain_limit": None,
        "installation_id": installation_id,
        "license_id": license_row["id"],
        "issued_at": iso(utcnow()),
        "subscription_expires_at": iso(expiry),
        "grace_until": iso(expiry + timedelta(days=GRACE_DAYS)),
    }
    encoded = b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = b64url(private_key().sign(encoded.encode("ascii")))
    return f"{encoded}.{signature}", payload


def key_hash(value):
    return hashlib.sha256(value.strip().encode()).hexdigest()


def activation_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def require_admin(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        auth = request.authorization
        valid = bool(
            ADMIN_PASSWORD and auth
            and hmac.compare_digest(auth.username or "", ADMIN_USERNAME)
            and hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)
        )
        if not valid:
            return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="MassPanel Licensing"'})
        return fn(*args, **kwargs)
    return wrapped


def admin_csrf():
    return hashlib.sha256(("masspanel-admin-form\0" + ADMIN_PASSWORD).encode()).hexdigest()


def require_admin_form(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not hmac.compare_digest(request.form.get("csrf", ""), admin_csrf()):
            return Response("Invalid form token", 403)
        return fn(*args, **kwargs)
    return wrapped


def json_payload():
    return request.get_json(silent=True) or {}


@app.get("/health")
def health():
    try:
        with db() as c:
            c.execute("SELECT 1").fetchone()
        return jsonify(ok=True, service="masspanel-licensing")
    except sqlite3.Error:
        return jsonify(ok=False), 503


@app.get("/v1/public-key")
def public_key():
    return Response(PUBLIC_KEY_PATH.read_text(), mimetype="text/plain")


@app.post("/v1/activate")
def activate():
    payload = json_payload()
    license_key = str(payload.get("license_key", "")).strip()
    installation_id = str(payload.get("installation_id", "")).strip()
    instance_url = str(payload.get("instance_url", "")).strip()[:300]
    if not license_key or len(installation_id) < 16 or len(installation_id) > 100:
        return jsonify(error="A valid licence key and installation ID are required."), 400
    with db() as c:
        row = c.execute("SELECT * FROM licenses WHERE key_hash=?", (key_hash(license_key),)).fetchone()
        if not row or row["status"] != "active":
            return jsonify(error="Licence key is invalid or revoked."), 403
        if parse_iso(row["expires_at"]) < utcnow():
            return jsonify(error="The subscription has expired."), 403
        activation = c.execute(
            "SELECT * FROM activations WHERE license_id=? AND installation_id=?",
            (row["id"], installation_id),
        ).fetchone()
        if not activation:
            count = c.execute("SELECT COUNT(*) FROM activations WHERE license_id=?", (row["id"],)).fetchone()[0]
            if count >= row["max_installations"]:
                return jsonify(error="This licence is already active on another server."), 409
            activation_secret = secrets.token_urlsafe(32)
            cursor = c.execute(
                "INSERT INTO activations(license_id,installation_id,instance_url,secret_hash,created_at,last_seen_at) VALUES(?,?,?,?,?,?)",
                (row["id"], installation_id, instance_url, activation_hash(activation_secret), iso(utcnow()), iso(utcnow())),
            )
            activation_id = cursor.lastrowid
        else:
            activation_secret = secrets.token_urlsafe(32)
            activation_id = activation["id"]
            c.execute(
                "UPDATE activations SET instance_url=?,secret_hash=?,last_seen_at=? WHERE id=?",
                (instance_url, activation_hash(activation_secret), iso(utcnow()), activation_id),
            )
        token, entitlement = sign_entitlement(row, installation_id)
    return jsonify(ok=True, activation_id=activation_id, activation_secret=activation_secret,
                   entitlement_token=token, entitlement=entitlement)


@app.post("/v1/refresh")
def refresh():
    payload = json_payload()
    try:
        activation_id = int(payload.get("activation_id"))
    except (TypeError, ValueError):
        return jsonify(error="Invalid activation."), 400
    secret = str(payload.get("activation_secret", ""))
    installation_id = str(payload.get("installation_id", ""))
    with db() as c:
        row = c.execute(
            "SELECT a.*,l.* FROM activations a JOIN licenses l ON l.id=a.license_id WHERE a.id=?",
            (activation_id,),
        ).fetchone()
        if not row or not hmac.compare_digest(row["secret_hash"], activation_hash(secret)):
            return jsonify(error="Invalid activation."), 403
        if row["installation_id"] != installation_id or row["status"] != "active":
            return jsonify(error="The activation is revoked or belongs to another server."), 403
        if parse_iso(row["expires_at"]) < utcnow():
            return jsonify(error="The subscription has expired."), 403
        c.execute("UPDATE activations SET last_seen_at=? WHERE id=?", (iso(utcnow()), activation_id))
        token, entitlement = sign_entitlement(row, installation_id)
    return jsonify(ok=True, entitlement_token=token, entitlement=entitlement)


PAGE = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width'>
<title>MassPanel Licensing</title><style>
body{font:15px system-ui;background:#0b1220;color:#e7edf7;margin:0}.wrap{max-width:1050px;margin:auto;padding:32px}
h1{margin:0 0 6px}.muted{color:#9aabc3}.card{background:#131e31;border:1px solid #263651;border-radius:14px;padding:20px;margin:20px 0}
form{display:grid;grid-template-columns:1fr 1fr 120px 120px auto;gap:10px}input,button{padding:10px;border-radius:8px;border:1px solid #344762;background:#0e1728;color:white}
button{background:#2878ff;border:0;font-weight:700;cursor:pointer}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px;border-bottom:1px solid #263651}
.key{padding:14px;background:#0a1424;border-radius:8px;word-break:break-all;color:#8ee6b2}.danger{background:#b63d4a}.active{color:#62d891}.revoked{color:#ff8590}
@media(max-width:800px){form{grid-template-columns:1fr}.wrap{padding:16px}.table{overflow:auto}}
</style></head><body><div class=wrap><h1>MassPanel Licensing</h1><div class=muted>Community: 20 domains · Unlimited: $5/month per server</div>
{% if created_key %}<div class=card><b>New licence key — copy it now</b><div class=key>{{ created_key }}</div></div>{% endif %}
<div class=card><h2>Create unlimited licence</h2><form method=post action=/admin/licenses>
<input type=hidden name=csrf value='{{ csrf }}'><input name=customer_name placeholder='Customer name' required><input name=customer_email type=email placeholder='Email' required>
<input name=days type=number min=1 max=3660 value=30 required><input name=max_installations type=number min=1 max=100 value=1 required><button>Create</button></form></div>
<div class='card table'><table><thead><tr><th>ID</th><th>Customer</th><th>Key</th><th>Expires</th><th>Installs</th><th>Status</th><th></th></tr></thead><tbody>
{% for item in licenses %}<tr><td>{{ item.id }}</td><td>{{ item.customer_name }}<br><span class=muted>{{ item.customer_email }}</span></td><td>{{ item.key_hint }}</td><td>{{ item.expires_at }}</td><td>{{ item.activation_count }}/{{ item.max_installations }}</td><td class={{ item.status }}>{{ item.status }}</td><td>
<form method=post action='/admin/licenses/{{ item.id }}/extend' style='display:flex'><input type=hidden name=csrf value='{{ csrf }}'><input name=days type=number min=1 max=3660 value=30 style='width:65px'><button>Extend</button></form>
{% if item.activation_count %}<form method=post action='/admin/licenses/{{ item.id }}/release' style='display:block'><input type=hidden name=csrf value='{{ csrf }}'><button>Release install</button></form>{% endif %}
{% if item.status=='active' %}<form method=post action='/admin/licenses/{{ item.id }}/revoke' style='display:block'><input type=hidden name=csrf value='{{ csrf }}'><button class=danger>Revoke</button></form>{% endif %}</td></tr>{% endfor %}
</tbody></table></div></div></body></html>"""


@app.get("/")
@require_admin
def admin_home():
    with db() as c:
        rows = c.execute(
            "SELECT l.*,COUNT(a.id) activation_count FROM licenses l LEFT JOIN activations a ON a.license_id=l.id GROUP BY l.id ORDER BY l.id DESC"
        ).fetchall()
    return render_template_string(PAGE, licenses=rows, created_key="", csrf=admin_csrf())


@app.post("/admin/licenses")
@require_admin
@require_admin_form
def create_license():
    name = request.form.get("customer_name", "").strip()[:120]
    email = request.form.get("customer_email", "").strip().lower()[:200]
    try:
        days = min(max(int(request.form.get("days", "30")), 1), 3660)
        max_installations = min(max(int(request.form.get("max_installations", "1")), 1), 100)
    except ValueError:
        return jsonify(error="Invalid duration or installation count."), 400
    if not name or "@" not in email:
        return jsonify(error="Customer name and email are required."), 400
    raw_key = "MPU-" + secrets.token_urlsafe(30)
    created = utcnow()
    with db() as c:
        c.execute(
            "INSERT INTO licenses(key_hash,key_hint,customer_name,customer_email,plan,status,expires_at,max_installations,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (key_hash(raw_key), raw_key[:9] + "..." + raw_key[-5:], name, email, "unlimited", "active",
             iso(created + timedelta(days=days)), max_installations, iso(created), iso(created)),
        )
    with db() as c:
        rows = c.execute(
            "SELECT l.*,COUNT(a.id) activation_count FROM licenses l LEFT JOIN activations a ON a.license_id=l.id GROUP BY l.id ORDER BY l.id DESC"
        ).fetchall()
    response = app.make_response(render_template_string(PAGE, licenses=rows, created_key=raw_key, csrf=admin_csrf()))
    response.headers["X-MassPanel-License-Key"] = raw_key
    return response


@app.post("/admin/licenses/<int:license_id>/revoke")
@require_admin
@require_admin_form
def revoke_license(license_id):
    with db() as c:
        c.execute("UPDATE licenses SET status='revoked',updated_at=? WHERE id=?", (iso(utcnow()), license_id))
    return redirect(url_for("admin_home"))


@app.post("/admin/licenses/<int:license_id>/extend")
@require_admin
@require_admin_form
def extend_license(license_id):
    try: days = min(max(int(request.form.get("days", "30")), 1), 3660)
    except ValueError: return Response("Invalid duration", 400)
    with db() as c:
        row = c.execute("SELECT expires_at FROM licenses WHERE id=?", (license_id,)).fetchone()
        if not row: return Response("Licence not found", 404)
        baseline = max(parse_iso(row["expires_at"]), utcnow())
        c.execute("UPDATE licenses SET expires_at=?,status='active',updated_at=? WHERE id=?",
                  (iso(baseline + timedelta(days=days)), iso(utcnow()), license_id))
    return redirect(url_for("admin_home"))


@app.post("/admin/licenses/<int:license_id>/release")
@require_admin
@require_admin_form
def release_license(license_id):
    with db() as c:
        c.execute("DELETE FROM activations WHERE license_id=?", (license_id,))
    return redirect(url_for("admin_home"))


if __name__ == "__main__":
    init_state()
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        print(PUBLIC_KEY_PATH)
    else:
        app.run(host="127.0.0.1", port=8080)
else:
    init_state()
