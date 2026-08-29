#!/usr/bin/env python3
import datetime as dt
import hashlib
import grp
import ipaddress
import json
import os
import pwd
import re
import secrets
import smtplib
import spwd
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

USERNAME = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SHELLS = {"/bin/bash", "/bin/sh", "/usr/sbin/nologin"}
PROTECTED = {"root", "massimo", "masspanel"}
MAX_HELPER_INPUT = 4 * 1024 * 1024
CLOUDFLARE_CONNECTIONS = Path("/etc/masspanel/cloudflare-connections.json")
CLOUDFLARE_LEGACY_TOKEN = Path("/etc/masspanel/cloudflare-token")
GROMMUNIO_SSO_CREDENTIALS = Path("/etc/masspanel/grommunio-impersonation.json")
SYSTEM_MAILBOX_CREDENTIALS = Path("/etc/masspanel/system-mailbox.json")
MANAGED_SERVICES = {
    "nginx": ("Web server", True),
    "masspanel": ("MassPanel API", True),
    "php8.3-fpm": ("PHP application runtime", False),
    "mariadb": ("MariaDB database", False),
    "bind9": ("Authoritative DNS", False),
    "postfix": ("SMTP transport", False),
    "rspamd": ("Spam filtering", False),
    "gromox-http": ("Grommunio web and EWS", False),
    "gromox-imap": ("IMAP mailbox access", False),
    "gromox-pop3": ("POP3 mailbox access", False),
    "gromox-delivery": ("Mail delivery", False),
    "gromox-delivery-queue": ("Mail delivery queue", False),
    "gromox-zcore": ("Gromox store service", False),
    "gromox-midb": ("Gromox mailbox database", False),
    "gromox-event": ("Gromox events", False),
    "gromox-timer": ("Gromox timers", False),
    "redis-server@grommunio": ("Grommunio cache", False),
    "fail2ban": ("Brute-force protection", False),
    "cron": ("Scheduled jobs", False),
    "masspanel-system-mail-sorter.timer": ("System mailbox sorting", False),
    "masspanel-updater.timer": ("Update checks", False),
}


def valid_email_address(value):
    localpart, separator, domain = str(value).lower().rpartition("@")
    return bool(separator and re.fullmatch(r"[a-z0-9._%+-]{1,64}", localpart) and DOMAIN.fullmatch(domain))


def sql_hex(value):
    """Return a MariaDB hex literal without placing user text in SQL syntax."""
    return "X'" + str(value).encode("utf-8").hex() + "'"


def _mariadb_xml(sql, database=""):
    command = ["/usr/bin/mariadb", "--xml", "--default-character-set=utf8mb4"]
    if database: command.append(database)
    result = run(command, sql + "\n", timeout=30)
    try: root = ET.fromstring(result.stdout)
    except ET.ParseError: fail("MariaDB returned an unreadable response.")
    rows = []
    for row in root.findall(".//row"):
        item = {}
        for field in row.findall("field"):
            name = field.attrib.get("name", "")
            nil = any(key.endswith("}nil") and value == "true" for key, value in field.attrib.items())
            value = None if nil else (field.text or "")
            if isinstance(value, str) and len(value) > 4000: value = value[:4000] + "…"
            item[name] = value
        rows.append(item)
    return rows


def _database_identifier(value, label="database"):
    value = str(value or "")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", value): fail(f"Invalid {label} name.")
    return value


def database_browse(payload):
    database = _database_identifier(payload.get("database"))
    tables = [next(iter(row.values())) for row in _mariadb_xml(f"SHOW TABLES FROM `{database}`") if row]
    table = str(payload.get("table") or "")
    if not table: return {"database":database, "tables":tables, "table":"", "columns":[], "primary_key":[], "rows":[]}
    table = _database_identifier(table, "table")
    if table not in tables: fail("Database table not found.")
    columns = _mariadb_xml(f"SHOW FULL COLUMNS FROM `{table}`", database)
    keys = _mariadb_xml(f"SHOW KEYS FROM `{table}` WHERE Key_name='PRIMARY'", database)
    primary = [row.get("Column_name", "") for row in sorted(keys, key=lambda row:int(row.get("Seq_in_index") or 0)) if row.get("Column_name")]
    rows = _mariadb_xml(f"SELECT * FROM `{table}` LIMIT 50", database)
    return {"database":database, "tables":tables, "table":table, "columns":columns, "primary_key":primary, "rows":rows, "limit":50}


def database_update_row(payload):
    database = _database_identifier(payload.get("database")); table = _database_identifier(payload.get("table"), "table")
    changes = payload.get("changes"); key = payload.get("key")
    if not isinstance(changes, dict) or not changes or len(changes) > 32: fail("Choose at least one field to update.")
    if not isinstance(key, dict) or not key: fail("This table needs a primary key before rows can be edited safely.")
    metadata = database_browse({"database":database, "table":table})
    allowed = {str(column.get("Field")) for column in metadata["columns"]}; primary = set(metadata["primary_key"])
    if not set(changes).issubset(allowed) or set(key) != primary: fail("Invalid database column selection.")
    assignments = [f"`{column}`=" + ("NULL" if value is None else sql_hex(value)) for column, value in changes.items()]
    filters = [f"`{column}`=" + ("NULL" if value is None else sql_hex(value)) for column, value in key.items()]
    run(["/usr/bin/mariadb", database], f"UPDATE `{table}` SET {', '.join(assignments)} WHERE {' AND '.join(filters)} LIMIT 1;\n", timeout=30)
    return {"database":database, "table":table, "updated":True}


def database_tool_access(payload):
    database = _database_identifier(payload.get("database"))
    store = Path("/etc/masspanel/database-tool-users.json")
    try: credentials = json.loads(store.read_text(encoding="utf-8")) if store.exists() else {}
    except (OSError, json.JSONDecodeError): credentials = {}
    record = credentials.get(database) if isinstance(credentials.get(database), dict) else {}
    username = "mpn_" + hashlib.sha256(database.encode()).hexdigest()[:12]
    password = str(record.get("password") or secrets.token_urlsafe(32))
    password_sql = "'" + password.replace("\\", "\\\\").replace("'", "''") + "'"
    sql = f"CREATE USER IF NOT EXISTS `{username}`@`localhost` IDENTIFIED BY {password_sql};ALTER USER `{username}`@`localhost` IDENTIFIED BY {password_sql};GRANT ALL PRIVILEGES ON `{database}`.* TO `{username}`@`localhost`;FLUSH PRIVILEGES;"
    run(["/usr/bin/mariadb"], sql, timeout=30)
    credentials[database] = {"username":username,"password":password}
    store.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    atomic_write_text(store, json.dumps(credentials, indent=2) + "\n", 0o600)
    return {"database":database,"username":username,"password":password,"server":"localhost"}


def hosting_storage_usage(payload):
    username = validate_username(payload.get("username"))
    account = pwd.getpwnam(username)
    home = Path(account.pw_dir).resolve()
    expected = Path("/home") / username
    if home != expected or not home.is_dir(): fail("Hosting home directory is unavailable.")
    completed = run(["/usr/bin/du", "-sb", "--", str(home)], timeout=60)
    try: used_bytes = int(completed.stdout.split()[0])
    except (IndexError, ValueError): fail("Could not calculate hosting storage usage.")
    return {"username":username,"used_bytes":used_bytes}


def filebrowser_workspace_sync(payload):
    workspace_user = validate_username(payload.get("workspace_user"))
    entries = payload.get("domains")
    if not isinstance(entries, list) or len(entries) > 10000: fail("Invalid website workspace.")
    workspace = Path("/home") / workspace_user / "websites"
    workspace.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    workspace.mkdir(mode=0o755, exist_ok=True)
    host_mount = ["/usr/bin/nsenter", "--mount=/proc/1/ns/mnt", "--"]
    wanted = {}
    for entry in entries:
        if not isinstance(entry, dict): fail("Invalid website workspace entry.")
        domain = str(entry.get("domain", "")).lower().strip()
        owner = validate_username(entry.get("owner"))
        if not DOMAIN.fullmatch(domain): fail("Invalid website domain.")
        _, target = domain_paths(domain, owner, entry.get("webroot"))
        wanted[domain] = target
    for item in workspace.iterdir():
        if item.name in wanted: continue
        if subprocess.run(host_mount + ["/usr/bin/mountpoint", "-q", str(item)], check=False).returncode == 0:
            run(host_mount + ["/usr/bin/umount", str(item)])
        if item.is_symlink(): item.unlink()
        elif item.is_dir(): item.rmdir()
    for domain, target in wanted.items():
        link = workspace / domain
        if link.is_symlink(): link.unlink()
        link.mkdir(mode=0o755, exist_ok=True)
        mounted = subprocess.run(host_mount + ["/usr/bin/mountpoint", "-q", str(link)], check=False).returncode == 0
        if mounted: continue
        run(host_mount + ["/usr/bin/mount", "--bind", str(target), str(link)])
    return {"workspace":str(workspace),"websites":len(wanted)}


def grommunio_query_rows(raw, object_key):
    """Normalize grommunio-admin JSON output across object and array formats."""
    try:
        payload = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        fail("Could not read the Grommunio directory.")
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows = []
        for key, value in payload.items():
            row = dict(value) if isinstance(value, dict) else {}
            row.setdefault(object_key, key)
            rows.append(row)
        return rows
    fail("Could not read the Grommunio directory.")

def fail(message, code=1):
    print(json.dumps({"ok": False, "error": message}))
    raise SystemExit(code)


def read_helper_payload(stream):
    raw = stream.read(MAX_HELPER_INPUT + 1)
    if len(raw) > MAX_HELPER_INPUT: fail("Request is too large.")
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("Invalid request.")

def validate_username(value):
    if not isinstance(value, str) or not USERNAME.fullmatch(value):
        fail("Username must start with a letter and use 3-32 lowercase letters, numbers, _ or -.")
    return value

def run(command, stdin=None, timeout=20):
    try:
        return subprocess.run(command, input=stdin, text=True, check=True, capture_output=True, timeout=timeout)
    except subprocess.CalledProcessError as exc:
        fail((exc.stderr or exc.stdout or "Account operation failed.").strip()[:240])
    except subprocess.TimeoutExpired:
        fail("Account operation timed out.")
    except (FileNotFoundError, PermissionError):
        fail("A required server utility is unavailable.")


def atomic_write_text(path, content, mode=0o644):
    staged = path.with_name(path.name + ".new")
    staged.write_text(content, encoding="utf-8")
    staged.chmod(mode)
    staged.replace(path)


def atomic_write_bytes(path, content, mode=0o644):
    staged = path.with_name(path.name + ".new")
    staged.write_bytes(content)
    staged.chmod(mode)
    staged.replace(path)


def snapshot_path(path):
    if path.is_symlink():
        return ("symlink", os.readlink(path))
    if path.is_file():
        return ("file", path.read_bytes(), path.stat().st_mode & 0o777)
    return ("missing",)


def restore_path(path, snapshot):
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    if snapshot[0] == "symlink":
        os.symlink(snapshot[1], path)
    elif snapshot[0] == "file":
        staged = path.with_name(path.name + ".restore")
        staged.write_bytes(snapshot[1])
        staged.chmod(snapshot[2])
        staged.replace(path)


def domain_paths(domain, owner, webroot, require_exists=True):
    owner = validate_username(owner)
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    try: account = pwd.getpwnam(owner)
    except KeyError: fail("Website owner does not exist.")
    home = Path(account.pw_dir).resolve(strict=True)
    expected_lexical = Path(account.pw_dir) / "domains" / domain / "public_html"
    supplied_lexical = Path(os.path.abspath(str(webroot)))
    if supplied_lexical != Path(os.path.abspath(str(expected_lexical))): fail("Invalid website root.")
    current = Path(account.pw_dir)
    for component in ("domains", domain, "public_html"):
        current = current / component
        if current.is_symlink(): fail("Website paths cannot contain symbolic links.")
    root = supplied_lexical.resolve(strict=require_exists)
    if root != expected_lexical.resolve(strict=require_exists) or home not in root.parents or (require_exists and not root.is_dir()): fail("Invalid website root.")
    if require_exists and root.stat().st_uid != account.pw_uid: fail("Website root ownership is invalid.")
    return account, root


def grant_panel_access(account, webroot):
    domains_root = Path(account.pw_dir) / "domains"
    run(["/usr/bin/setfacl", "-R", "-m", f"u:masspanel:rwx,u:{account.pw_name}:rwx,m:rwx", str(domains_root)])
    run(["/usr/bin/find", str(domains_root), "-type", "d", "-exec", "/usr/bin/setfacl", "-d", "-m", f"u:masspanel:rwx,u:{account.pw_name}:rwx,m:rwx", "{}", "+"])


def write_domain_config(domain, webroot, ssl_mode="disabled", suspended=False, php_socket=None):
    if ssl_mode not in {"disabled", "self", "letsencrypt"}: fail("Unsupported SSL mode.")
    if ssl_mode == "letsencrypt":
        cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        key = f"/etc/letsencrypt/live/{domain}/privkey.pem"
    else:
        cert = "/etc/masspanel/tls/masspanel.crt"
        key = "/etc/masspanel/tls/masspanel.key"
    log_directives = f" access_log /var/log/nginx/masspanel-domain-{domain}.access.log;\n error_log /var/log/nginx/masspanel-domain-{domain}.error.log warn;\n"
    rules_dir = Path("/etc/nginx/masspanel-domain-rules")
    rules_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    rules_file = rules_dir / (domain + ".conf")
    if not rules_file.exists(): atomic_write_text(rules_file, "# Managed by MassPanel\n", 0o644)
    rules_include = f" include {rules_file};\n"
    if suspended:
        # Keep the error document below an nginx-readable parent.  /var/lib/masspanel
        # is intentionally private, which made nginx return its own 403 page.
        suspended_page = Path("/var/www/html/.masspanel-suspended.html")
        atomic_write_text(suspended_page, '''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hosting account suspended</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#f4f7fb;color:#10233f;font:16px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}.notice{width:min(620px,100%);padding:42px;border:1px solid #d7e0eb;border-radius:14px;background:#fff;box-shadow:0 20px 55px #0b234015}.mark{width:52px;height:52px;display:grid;place-items:center;border-radius:50%;background:#fff3da;color:#a96b00;font-size:27px;font-weight:800}h1{margin:22px 0 10px;font-size:30px;letter-spacing:-.03em}p{margin:0;color:#637187}.ref{margin-top:25px;padding-top:18px;border-top:1px solid #e3e8ef;font-size:13px;color:#8792a2}</style></head><body><main class="notice"><div class="mark">!</div><h1>This hosting account is suspended</h1><p>The website is temporarily unavailable. Please contact your hosting provider if you are the account owner.</p><div class="ref">Service unavailable · HTTP 503</div></main></body></html>''', 0o644)
        suspended_location = f''' error_page 503 /__masspanel_suspended.html;
 location = /__masspanel_suspended.html {{ internal; alias {suspended_page}; }}
 location ^~ /.well-known/acme-challenge/ {{ root {webroot}; try_files $uri =404; }}
 location / {{ return 503; }}
'''
        content = f'''server {{ listen 80; listen [::]:80; server_name {domain} www.{domain};{log_directives}{suspended_location} }}\n'''
        if ssl_mode != "disabled":
            content += f'''server {{ listen 443 ssl http2; listen [::]:443 ssl http2; server_name {domain} www.{domain}; ssl_certificate {cert}; ssl_certificate_key {key};{log_directives}{suspended_location} }}\n'''
    else:
        index = "index.php index.html" if php_socket else "index.html"
        fallback = "/index.php?$args" if php_socket else "=404"
        if ssl_mode == "disabled":
            content = f'''server {{
 listen 80; listen [::]:80; server_name {domain} www.{domain};
 {log_directives}
 root {webroot}; index {index};
 {rules_include}
 location ^~ /.well-known/acme-challenge/ {{ try_files $uri =404; }}
 location / {{ try_files $uri $uri/ {fallback}; }}
'''
            if php_socket:
                content += f''' location ~ \\.php$ {{ include snippets/fastcgi-php.conf; fastcgi_pass unix:{php_socket}; }}\n location ~ /\\. {{ deny all; }}\n'''
            content += "}\n"
        else:
            content = f'''server {{
 listen 80; listen [::]:80; server_name {domain} www.{domain};
 {rules_include} location ^~ /.well-known/acme-challenge/ {{ root {webroot}; }}
 location / {{ return 301 https://$host$request_uri; }}
}}
server {{
 listen 443 ssl http2; listen [::]:443 ssl http2; server_name {domain} www.{domain};
 {log_directives}
 ssl_certificate {cert}; ssl_certificate_key {key};
 root {webroot}; index {index};
 {rules_include}
 location / {{ try_files $uri $uri/ {fallback}; }}
'''
            if php_socket:
                content += f''' location ~ \\.php$ {{ include snippets/fastcgi-php.conf; fastcgi_pass unix:{php_socket}; }}\n location ~ /\\. {{ deny all; }}\n'''
            content += "}\n"
    config = Path("/etc/nginx/sites-available") / ("masspanel-domain-" + domain + ".conf")
    enabled = Path("/etc/nginx/sites-enabled") / config.name
    previous = config.read_text(encoding="utf-8") if config.exists() else None
    try:
        config.write_text(content, encoding="utf-8"); config.chmod(0o644)
        if not enabled.exists(): enabled.symlink_to(config)
        run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"]); time.sleep(0.5)
    except BaseException:
        if previous is None:
            enabled.unlink(missing_ok=True); config.unlink(missing_ok=True)
        else:
            config.write_text(previous, encoding="utf-8")
        raise
    return config


def website_rules_sync(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    domain_paths(domain, payload.get("owner"), payload.get("webroot"))
    redirects = payload.get("redirects", [])
    if not isinstance(redirects, list) or len(redirects) > 200: fail("Invalid website redirect set.")
    lines = ["# Managed by MassPanel"]
    for item in redirects:
        if not isinstance(item, dict): fail("Invalid website redirect.")
        source = str(item.get("source_path", ""))
        target = str(item.get("target_url", ""))
        try: code = int(item.get("status_code", 301))
        except (TypeError, ValueError): fail("Invalid redirect status.")
        parsed = urllib.parse.urlsplit(target)
        if (not source.startswith("/") or len(source) > 1024 or any(ord(ch) < 32 or ch.isspace() or ch in '{};"?#\\' for ch in source)
                or parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.fragment or parsed.username or parsed.password or len(target) > 2048
                or any(ord(ch) < 32 or ch.isspace() or ch in '${};"\\' for ch in target) or code not in {301,302,307,308}):
            fail("Invalid website redirect.")
        lines.append(f"location = {source} {{ return {code} {target}; }}")
    settings = payload.get("settings", {})
    if not isinstance(settings, dict): fail("Invalid website protection settings.")
    error_404 = str(settings.get("error_404_path", "")).strip()
    if error_404:
        if not error_404.startswith("/") or len(error_404) > 255 or any(ord(ch) < 32 or ch.isspace() or ch in '{};\"?#\\' for ch in error_404): fail("Invalid custom error page path.")
        lines.append(f"error_page 404 {error_404};")
    if bool(settings.get("hotlink_enabled")):
        extensions = [item.strip().lower() for item in str(settings.get("hotlink_extensions", "")).split(",") if item.strip()]
        referrers = [item.strip().lower().rstrip(".") for item in str(settings.get("allowed_referrers", "")).split(",") if item.strip()]
        if not extensions or len(extensions) > 30 or any(not re.fullmatch(r"[a-z0-9]{1,10}", item) for item in extensions): fail("Invalid hotlink extension list.")
        if len(referrers) > 30 or any(not DOMAIN.fullmatch(item) for item in referrers): fail("Invalid allowed referrer list.")
        extension_pattern = "|".join(re.escape(item) for item in extensions)
        allowed = " ".join(referrers)
        lines.append(f"location ~* \\.({extension_pattern})$ {{ valid_referers none blocked server_names {allowed}; if ($invalid_referer) {{ return 403; }} try_files $uri =404; }}")
    rules_dir = Path("/etc/nginx/masspanel-domain-rules")
    rules_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    rules_file = rules_dir / (domain + ".conf")
    previous = rules_file.read_text(encoding="utf-8") if rules_file.exists() else None
    try:
        atomic_write_text(rules_file, "\n".join(lines) + "\n", 0o644)
        config = Path("/etc/nginx/sites-available") / ("masspanel-domain-" + domain + ".conf")
        if config.exists() and str(rules_file) not in config.read_text(encoding="utf-8"):
            fail("Regenerate this website configuration before adding redirects.")
        run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"]); time.sleep(0.6)
    except BaseException:
        if previous is None: rules_file.unlink(missing_ok=True)
        else: atomic_write_text(rules_file, previous, 0o644)
        raise
    return {"domain":domain, "redirect_count":len(redirects)}


def cron_sync(payload):
    owner = validate_username(payload.get("owner"))
    try: account = pwd.getpwnam(owner)
    except KeyError: fail("Hosting account does not exist.")
    tasks = payload.get("tasks", [])
    if not isinstance(tasks, list) or len(tasks) > 100: fail("Invalid scheduled task set.")
    lines = ["SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    log_dir = Path(account.pw_dir) / "logs"
    log_dir.mkdir(mode=0o750, exist_ok=True)
    os.chown(log_dir, account.pw_uid, account.pw_gid)
    cron_log = log_dir / "cron.log"
    if not cron_log.exists():
        cron_log.touch(mode=0o640)
        os.chown(cron_log, account.pw_uid, account.pw_gid)
    for task in tasks:
        if not isinstance(task, dict): fail("Invalid scheduled task.")
        task_id = str(task.get("id", ""))
        if not re.fullmatch(r"[a-f0-9]{16}", task_id): fail("Invalid scheduled task identifier.")
        name = str(task.get("name", "")).strip()
        schedule = str(task.get("schedule", "")).strip()
        command = str(task.get("command", "")).strip()
        fields = schedule.split()
        if len(fields) != 5 or any(not re.fullmatch(r"[0-9*/?,\-]+", field) for field in fields): fail("Invalid cron schedule.")
        if not command or len(command) > 1000 or any(ch in command for ch in "\r\n\x00"): fail("Invalid cron command.")
        safe_name = re.sub(r"[^A-Za-z0-9 ._\-]", "", name)[:80]
        lines.append(f"# MassPanel {task_id} {safe_name}" + ("" if task.get("enabled") else " (disabled)"))
        if task.get("enabled"):
            escaped_command = command.replace("%", r"\%")
            lines.append(f"{schedule} {owner} ( {escaped_command} ) >> {cron_log} 2>&1")
    path = Path("/etc/cron.d") / ("masspanel-" + owner)
    if tasks:
        atomic_write_text(path, "\n".join(lines) + "\n", 0o600)
    else:
        path.unlink(missing_ok=True)
    return {"owner": owner, "task_count": len(tasks), "path": str(path)}


def backup_schedule_sync(payload):
    schedules = payload.get("schedules", [])
    if not isinstance(schedules, list) or len(schedules) > 1000:
        fail("Invalid backup schedule set.")
    lines = ["SHELL=/bin/bash", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    for item in schedules:
        schedule_id = str(item.get("id", ""))
        cron = str(item.get("cron", "")).strip()
        if not re.fullmatch(r"[a-f0-9]{16}", schedule_id):
            fail("Invalid backup schedule identifier.")
        fields = cron.split()
        if len(fields) != 5 or any(not re.fullmatch(r"[0-9*/?,\-]+", field) for field in fields):
            fail("Invalid backup schedule.")
        lines.append(
            f"{cron} masspanel set -a; . /etc/masspanel/masspanel.env; set +a; "
            f"/opt/masspanel/venv/bin/python /opt/masspanel/backend/scheduled_backup.py {schedule_id} "
            f">> /var/log/masspanel-backups.log 2>&1"
        )
    path = Path("/etc/cron.d/masspanel-backups")
    if schedules:
        atomic_write_text(path, "\n".join(lines) + "\n", 0o600)
    else:
        path.unlink(missing_ok=True)
    return {"schedule_count": len(schedules), "path": str(path)}


def service_list():
    services = []
    for unit, (description, critical) in MANAGED_SERVICES.items():
        loaded = subprocess.run(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"], capture_output=True, text=True, timeout=8, check=False).stdout.strip()
        if loaded in {"", "not-found"}:
            continue
        details = subprocess.run(
            ["/usr/bin/systemctl", "show", unit, "--property=ActiveState,SubState,UnitFileState,Description"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        values = {}
        for line in details.stdout.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value
        services.append({
            "name": unit,
            "label": values.get("Description") or description,
            "description": description,
            "state": values.get("ActiveState") or "unknown",
            "sub_state": values.get("SubState") or "unknown",
            "enabled": values.get("UnitFileState") in {"enabled", "enabled-runtime", "static", "indirect", "generated"},
            "critical": critical,
        })
    return {"services": services}


def service_action(payload):
    unit = str(payload.get("service", ""))
    action = str(payload.get("action", ""))
    if unit not in MANAGED_SERVICES or action not in {"start", "stop", "restart"}:
        fail("Unsupported service action.")
    if MANAGED_SERVICES[unit][1] and action == "stop":
        fail("This service keeps the panel reachable and cannot be stopped from the web interface.")
    if action == "restart" and unit in {"masspanel", "nginx"}:
        run(["/usr/bin/systemd-run", "--unit", f"masspanel-service-{unit.replace('.', '-')}--{int(time.time())}", "--on-active=2s", "/usr/bin/systemctl", "restart", unit], timeout=20)
        return {"service": unit, "action": action, "scheduled": True}
    result = subprocess.run(["/usr/bin/systemctl", action, unit], capture_output=True, text=True, timeout=90, check=False)
    if result.returncode:
        fail((result.stderr or result.stdout or "Service action failed.").strip())
    return {"service": unit, "action": action, "scheduled": False}


def cron_run(payload):
    owner = validate_username(payload.get("owner"))
    try: pwd.getpwnam(owner)
    except KeyError: fail("Hosting account does not exist.")
    command = str(payload.get("command", "")).strip()
    if not command or len(command) > 1000 or any(ch in command for ch in "\r\n\x00"): fail("Invalid cron command.")
    result = run(["/usr/sbin/runuser", "-u", owner, "--", "/bin/bash", "-lc", command], timeout=60)
    return {"owner": owner, "output": (result.stdout + result.stderr)[-16000:]}


def php_config(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    account, webroot = domain_paths(domain, payload.get("owner"), payload.get("webroot"))
    enabled = bool(payload.get("enabled"))
    memory = int(payload.get("memory_limit", 256)); upload = int(payload.get("upload_limit", 64)); execution = int(payload.get("execution_time", 120))
    if not 32 <= memory <= 2048 or not 2 <= upload <= 2048 or not 10 <= execution <= 3600: fail("Invalid PHP limits.")
    socket_path = Path("/run/php") / ("masspanel-" + account.pw_name + ".sock")
    if enabled and not socket_path.exists(): fail("The PHP-FPM pool for this hosting account is unavailable.")
    ini = webroot / ".user.ini"
    if enabled:
        atomic_write_text(ini, f"memory_limit={memory}M\nupload_max_filesize={upload}M\npost_max_size={upload}M\nmax_execution_time={execution}\n", 0o640)
        os.chown(ini, account.pw_uid, account.pw_gid)
    else:
        ini.unlink(missing_ok=True)
    write_domain_config(domain, webroot, str(payload.get("ssl_mode", "disabled")), bool(payload.get("suspended")), str(socket_path) if enabled else None)
    return {"domain": domain, "enabled": enabled, "php_socket": str(socket_path) if enabled else ""}


def website_logs(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    domain_paths(domain, payload.get("owner"), payload.get("webroot"))
    try: limit = min(500, max(20, int(payload.get("lines", 100))))
    except (TypeError, ValueError): limit = 100
    access_path = Path("/var/log/nginx") / ("masspanel-domain-" + domain + ".access.log")
    error_path = Path("/var/log/nginx") / ("masspanel-domain-" + domain + ".error.log")
    def tail(path):
        if not path.is_file(): return []
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    access = tail(access_path); errors = tail(error_path); statuses = {}; transferred = 0
    for line in access:
        match = re.search(r'"\s(\d{3})\s(\d+|-)\s', line)
        if match:
            statuses[match.group(1)] = statuses.get(match.group(1), 0) + 1
            if match.group(2).isdigit(): transferred += int(match.group(2))
    return {"domain":domain, "access":access, "errors":errors, "metrics":{"requests":len(access), "bytes":transferred, "statuses":statuses}}


def rebuild_dns_config():
    zone_dir = Path("/var/lib/bind/masspanel")
    include = Path("/etc/bind/masspanel-zones.conf")
    lines = []
    for zone in sorted(zone_dir.glob("*.zone")):
        domain = zone.stem
        if DOMAIN.fullmatch(domain):
            lines.append(f'zone "{domain}" {{ type primary; file "{zone}"; }};')
    include.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    include.chmod(0o644)
    run(["/usr/bin/named-checkconf"])
    run(["/usr/sbin/rndc", "reconfig"], timeout=40)


def dns_value(record_type, value):
    if any(ord(ch) < 32 for ch in value): fail("Invalid DNS record value.")
    if record_type in {"TXT", "SPF"}:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return " ".join('"' + escaped[offset:offset + 200] + '"' for offset in range(0, len(escaped), 200))
    if record_type in {"CNAME", "NS"}:
        return value.rstrip(".") + "."
    if record_type == "MX":
        priority, host = value.split()
        return priority + " " + host.rstrip(".") + "."
    if record_type == "SRV":
        parts = value.split()
        if len(parts) != 4 or not all(part.isdigit() for part in parts[:3]): fail("Invalid SRV record value.")
        return " ".join(parts[:3]) + " " + parts[3].rstrip(".") + "."
    if record_type == "A":
        if ipaddress.ip_address(value).version != 4: fail("Invalid A record value.")
    if record_type == "AAAA":
        if ipaddress.ip_address(value).version != 6: fail("Invalid AAAA record value.")
    return value


def sync_dns(payload):
    domain = payload.get("domain", "")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    primary_ns = str(payload.get("primary_ns") or f"ns1.{domain}").lower().strip().rstrip(".")
    secondary_ns = str(payload.get("secondary_ns") or f"ns2.{domain}").lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(primary_ns) or not DOMAIN.fullmatch(secondary_ns) or primary_ns == secondary_ns:
        fail("Invalid authoritative nameserver configuration.")
    records = payload.get("records", [])
    if not isinstance(records, list) or len(records) > 500: fail("Invalid DNS record set.")
    route = run(["/usr/sbin/ip", "-4", "route", "get", "1.1.1.1"]).stdout.split()
    try: server_ip = route[route.index("src") + 1]
    except (ValueError, IndexError): fail("Could not determine the server IPv4 address.")
    ipaddress.ip_address(server_ip)
    serial = str(int(dt.datetime.now(dt.timezone.utc).timestamp()))
    lines = [
        "$TTL 3600",
        f"@ IN SOA {primary_ns}. hostmaster.{domain}. ({serial} 3600 900 1209600 300)",
        f"@ 3600 IN NS {primary_ns}.",
        f"@ 3600 IN NS {secondary_ns}.",
    ]
    if primary_ns.endswith("." + domain):
        lines.append(f"{primary_ns[:-len(domain)-1]} 3600 IN A {server_ip}")
    if secondary_ns.endswith("." + domain):
        lines.append(f"{secondary_ns[:-len(domain)-1]} 3600 IN A {server_ip}")
    has_apex_a = False
    for record in records:
        rtype = str(record.get("type", "")).upper()
        name = str(record.get("name", "")).strip().lower().rstrip(".") or "@"
        value = str(record.get("value", "")).strip()
        try: ttl = int(record.get("ttl", 3600))
        except (TypeError, ValueError): fail("Invalid DNS TTL.")
        if rtype not in {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SPF", "SRV"} or ttl < 60 or ttl > 86400:
            fail("Invalid DNS record.")
        if name != "@" and not re.fullmatch(r"(?:\*|_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\._?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", name):
            fail("Invalid DNS record name.")
        has_apex_a = has_apex_a or (rtype == "A" and name == "@")
        lines.append(f"{name} {ttl} IN {rtype} {dns_value(rtype, value)}")
    if not has_apex_a: lines.append(f"@ 3600 IN A {server_ip}")
    zone_dir = Path("/var/lib/bind/masspanel"); zone_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
    zone = zone_dir / (domain + ".zone"); staged = zone.with_suffix(".zone.new")
    staged.write_text("\n".join(lines) + "\n", encoding="utf-8"); staged.chmod(0o644)
    run(["/usr/bin/named-checkzone", domain, str(staged)])
    staged.replace(zone)
    rebuild_dns_config()
    run(["/usr/sbin/rndc", "reload", domain], timeout=40)
    return {"domain": domain, "records": len(records)}


def email_hash(payload):
    password = str(payload.get("password", ""))
    if len(password) < 12 or len(password) > 256: fail("Mailbox password must contain 12-256 characters.")
    hashed = run(["/usr/bin/doveadm", "pw", "-s", "SHA512-CRYPT", "-p", password]).stdout.strip()
    if not hashed.startswith("{SHA512-CRYPT}"): fail("Could not hash mailbox password.")
    return {"password_hash": hashed}


def grommunio_domain_create(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(domain): fail("Invalid mail domain.")
    created = not grommunio_domain_users({"domain": domain})["exists"]
    if created:
        run(["/usr/sbin/grommunio-admin", "domain", "create", "--homeserver", "2", "--maxUser", "1000", domain], timeout=90)
    return {"domain": domain, "created": created}


def grommunio_domain_users(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(domain): fail("Invalid mail domain.")
    domain_query = run([
        "/usr/sbin/grommunio-admin", "domain", "query", "ID", "-f", "domainname=" + domain,
        "--format", "json-object",
    ], timeout=30)
    domains = grommunio_query_rows(domain_query.stdout, "ID")
    if not domains:
        return {"domain": domain, "exists": False, "user_count": 0, "users": []}
    domain_id = str(domains[0].get("ID", domains[0].get("id", "")))
    if not domain_id.isdigit(): fail("Could not identify the Grommunio domain.")
    user_query = run([
        "/usr/sbin/grommunio-admin", "user", "query", "username", "-f", "domainID=" + domain_id,
        "--format", "json-object",
    ], timeout=30)
    user_rows = grommunio_query_rows(user_query.stdout, "username")
    users = sorted(str(row.get("username", "unknown user")) for row in user_rows)
    return {"domain": domain, "exists": True, "user_count": len(user_rows), "users": users[:20]}


def grommunio_domain_delete(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(domain): fail("Invalid mail domain.")
    state = grommunio_domain_users({"domain": domain})
    if state["user_count"]:
        fail("Grommunio still contains users for this domain; remove or move them before deleting it.")
    shown = subprocess.run(["/usr/sbin/grommunio-admin", "domain", "show", domain], capture_output=True, text=True, timeout=30)
    if shown.returncode == 0:
        run(["/usr/sbin/grommunio-admin", "domain", "delete", domain], timeout=60)
        run(["/usr/sbin/grommunio-admin", "domain", "purge", "--files", "--yes", domain], timeout=120)
    return {"domain": domain}


def grommunio_email_create(payload):
    address = str(payload.get("full_email", "")).lower().strip()
    destination = str(payload.get("destination") or "").lower().strip()
    password = str(payload.get("password") or "")
    if not valid_email_address(address): fail("Invalid email address.")
    if destination:
        destinations = [item.strip() for item in destination.split(",") if item.strip()]
        if not destinations or len(destinations) > 4 or len(set(destinations)) != len(destinations) or any(not valid_email_address(item) for item in destinations):
            fail("Invalid forwarding address.")
        destination = ",".join(destinations)
        # A forwarding-only panel address has no local mailbox, so it must use
        # Grommunio redirect mode (1). Copy/BCC mode (0) also attempts local
        # delivery and creates an avoidable unknown-user bounce.
        sql = "INSERT INTO forwards(username,forward_type,destination) VALUES(%s,1,%s) ON DUPLICATE KEY UPDATE forward_type=1,destination=VALUES(destination)" % (sql_hex(address), sql_hex(destination))
        run(["/usr/bin/mariadb", "grommunio"], sql + ";\n", timeout=30)
    else:
        if len(password) < 12 or len(password) > 256: fail("Mailbox password must contain 12-256 characters.")
        shown = subprocess.run(["/usr/sbin/grommunio-admin", "user", "show", address], capture_output=True, text=True, timeout=30)
        if shown.returncode != 0:
            run(["/usr/sbin/grommunio-admin", "user", "create", "--homeserver", "2", "--lang", "en_US",
                 "--pop3-imap", "true", "--privWeb", "true", "--privDav", "true", "--privEas", "true", "--smtp", "true", address], timeout=120)
        run(["/usr/sbin/grommunio-admin", "passwd", "--password", password, address], timeout=60)
    return {"full_email": address, "forward": bool(destination)}


def grommunio_email_delete(payload):
    address = str(payload.get("full_email", "")).lower().strip()
    if not valid_email_address(address): fail("Invalid email address.")
    run(["/usr/bin/mariadb", "grommunio"], "DELETE FROM forwards WHERE username=%s;\n" % sql_hex(address), timeout=30)
    shown = subprocess.run(["/usr/sbin/grommunio-admin", "user", "show", address], capture_output=True, text=True, timeout=30)
    if shown.returncode == 0:
        deleted = subprocess.run(["/usr/sbin/grommunio-admin", "user", "delete", "--yes", address], capture_output=True, text=True, timeout=120)
        if deleted.returncode != 0:
            # Some compact single-server installations cannot ask exmdb to unload
            # a store. Removing the directory record is the supported end state;
            # orphaned store files are reclaimed by the normal purge maintenance.
            run(["/usr/bin/mariadb", "grommunio"], "DELETE FROM users WHERE username=%s;\n" % sql_hex(address), timeout=30)
    return {"full_email": address}


def grommunio_email_update(payload):
    address = str(payload.get("full_email", "")).lower().strip()
    destination = str(payload.get("destination") or "").lower().strip()
    forwarding_only = bool(payload.get("forwarding_only"))
    password = str(payload.get("password") or "")
    if not valid_email_address(address): fail("Invalid email address.")
    destinations = [item.strip() for item in destination.split(",") if item.strip()]
    if len(destinations) > 4 or len(set(destinations)) != len(destinations) or any(not valid_email_address(item) for item in destinations): fail("Invalid forwarding address.")
    destination = ",".join(destinations)
    if forwarding_only:
        if not destination: fail("A forwarding-only address needs a destination.")
        sql = "INSERT INTO forwards(username,forward_type,destination) VALUES(%s,1,%s) ON DUPLICATE KEY UPDATE forward_type=1,destination=VALUES(destination)" % (sql_hex(address), sql_hex(destination))
        run(["/usr/bin/mariadb", "grommunio"], sql + ";\n", timeout=30)
        return {"full_email": address, "forward": True}
    shown = subprocess.run(["/usr/sbin/grommunio-admin", "user", "show", address], capture_output=True, text=True, timeout=30)
    if shown.returncode != 0: fail("The Grommunio mailbox does not exist.")
    options = []
    for field, option in (("allow_smtp","--smtp"),("allow_imap","--pop3-imap"),("allow_web","--privWeb"),("allow_dav","--privDav"),("allow_eas","--privEas")):
        options.extend([option, "true" if bool(payload.get(field, True)) else "false"])
    run(["/usr/sbin/grommunio-admin", "user", "modify", *options, address], timeout=60)
    if password:
        if len(password) < 12 or len(password) > 256: fail("Mailbox password must contain 12-256 characters.")
        run(["/usr/sbin/grommunio-admin", "passwd", "--password", password, address], timeout=60)
    sql = ("INSERT INTO forwards(username,forward_type,destination) VALUES(%s,0,%s) ON DUPLICATE KEY UPDATE forward_type=0,destination=VALUES(destination)" % (sql_hex(address), sql_hex(destination))) if destination else ("DELETE FROM forwards WHERE username=%s" % sql_hex(address))
    run(["/usr/bin/mariadb", "grommunio"], sql + ";\n", timeout=30)
    return {"full_email": address, "forward": bool(destination)}


def grommunio_account_access(payload):
    addresses = payload.get("addresses", [])
    enabled = bool(payload.get("enabled"))
    if not isinstance(addresses, list) or len(addresses) > 2000: fail("Invalid mailbox list.")
    normalized = []
    for raw in addresses:
        address = str(raw).lower().strip()
        if not valid_email_address(address): fail("Invalid mailbox address.")
        normalized.append(address)
    value = "true" if enabled else "false"
    for address in normalized:
        shown = subprocess.run(["/usr/sbin/grommunio-admin", "user", "show", address], capture_output=True, text=True, timeout=30)
        if shown.returncode == 0:
            run(["/usr/sbin/grommunio-admin", "user", "modify", "--smtp", value, "--privWeb", value, address], timeout=60)
    # Gromox records the SMTP privilege, but this Postfix/Cyrus deployment does
    # not consult it during SASL authentication.  Enforce suspension at MAIL
    # FROM on the authenticated submission path while leaving port 25 recipient
    # delivery untouched.
    access_file = Path("/etc/postfix/masspanel_suspended_sasl")
    blocked = set()
    if access_file.exists():
        for line in access_file.read_text(encoding="utf-8").splitlines():
            candidate = line.split(None, 1)[0].lower().strip() if line.strip() else ""
            if valid_email_address(candidate): blocked.add(candidate)
    if enabled:
        blocked.difference_update(normalized)
    else:
        blocked.update(normalized)
    atomic_write_text(access_file, "".join(f"{address}\tREJECT Account suspended; outgoing mail is disabled\n" for address in sorted(blocked)), 0o640)
    # Grommunio Web uses this address-only deny-list to show a specific warning
    # before authentication. No passwords or other mailbox data are stored here.
    atomic_write_text(Path("/etc/grommunio-web/masspanel-suspended-mailboxes"), "".join(address + "\n" for address in sorted(blocked)), 0o644)
    run(["/usr/sbin/postmap", str(access_file)], timeout=30)
    setting = subprocess.run(["/usr/sbin/postconf", "-h", "smtpd_sender_restrictions"], capture_output=True, text=True, timeout=30)
    if setting.returncode != 0: fail("Could not read the Postfix sender policy.")
    policy = "check_sasl_access hash:/etc/postfix/masspanel_suspended_sasl"
    restrictions = setting.stdout.strip()
    if policy not in restrictions:
        restrictions = policy + ("," + restrictions if restrictions else "")
        run(["/usr/sbin/postconf", "-e", "smtpd_sender_restrictions=" + restrictions], timeout=30)
    run(["/usr/sbin/postfix", "reload"], timeout=30)
    return {"enabled": enabled, "mailboxes": len(normalized), "incoming_delivery": True}


def grommunio_impersonation_credentials(payload):
    address = str(payload.get("full_email", "")).lower().strip()
    if not valid_email_address(address): fail("Invalid mailbox address.")
    domain = address.rsplit("@", 1)[1]
    service = "masspanel-admin@" + domain
    GROMMUNIO_SSO_CREDENTIALS.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    credentials = {}
    if GROMMUNIO_SSO_CREDENTIALS.exists():
        try: credentials = json.loads(GROMMUNIO_SSO_CREDENTIALS.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): fail("Could not read the Grommunio SSO credentials.")
    password = credentials.get(service)
    shown = subprocess.run(["/usr/sbin/grommunio-admin", "user", "show", service], capture_output=True, text=True, timeout=30)
    if shown.returncode != 0:
        run(["/usr/sbin/grommunio-admin", "user", "create", "--changePassword", "false", "--pop3-imap", "true", "--privWeb", "true", "--privDav", "false", "--privEas", "false", "--smtp", "false", service], timeout=120)
    if not isinstance(password, str) or len(password) < 32:
        password = secrets.token_urlsafe(48)
        run(["/usr/sbin/grommunio-admin", "passwd", "--password", password, service], timeout=60)
        credentials[service] = password
        temp = GROMMUNIO_SSO_CREDENTIALS.with_name(GROMMUNIO_SSO_CREDENTIALS.name + "." + secrets.token_hex(8))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream: json.dump(credentials, stream)
        os.replace(temp, GROMMUNIO_SSO_CREDENTIALS)
        GROMMUNIO_SSO_CREDENTIALS.chmod(0o600)
    # Grommunio Web authenticates this technical account. MassPanel's Web hook
    # promotes the authorized target store to the session's default store.
    if address != service:
        run(["/usr/sbin/grommunio-admin", "user", "storeowner", address, "add", service], timeout=60)
    return {"username": service, "password": password, "mailbox": address}


def grommunio_system_mailbox_configure(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(domain): fail("Invalid owner system mail domain.")
    mailbox = "admin@" + domain
    grommunio_domain_create({"domain": domain})
    SYSTEM_MAILBOX_CREDENTIALS.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    credentials = {}
    if SYSTEM_MAILBOX_CREDENTIALS.exists():
        try: credentials = json.loads(SYSTEM_MAILBOX_CREDENTIALS.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): fail("Could not read the owner system mailbox credentials.")
    password = credentials.get(mailbox)
    shown = subprocess.run(["/usr/sbin/grommunio-admin", "user", "show", mailbox], capture_output=True, text=True, timeout=30)
    created = shown.returncode != 0
    if created:
        run(["/usr/sbin/grommunio-admin", "user", "create", "--changePassword", "false", "--homeserver", "2", "--lang", "en_US",
             "--pop3-imap", "true", "--privWeb", "true", "--privDav", "false", "--privEas", "false", "--smtp", "false", mailbox], timeout=120)
    else:
        run(["/usr/sbin/grommunio-admin", "user", "modify", "--pop3-imap", "true", "--privWeb", "true", "--smtp", "false", mailbox], timeout=60)
    if not isinstance(password, str) or len(password) < 32:
        password = secrets.token_urlsafe(48)
        run(["/usr/sbin/grommunio-admin", "passwd", "--password", password, mailbox], timeout=60)
        credentials = {mailbox: password}
        temp = SYSTEM_MAILBOX_CREDENTIALS.with_name(SYSTEM_MAILBOX_CREDENTIALS.name + "." + secrets.token_hex(8))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream: json.dump(credentials, stream)
        os.replace(temp, SYSTEM_MAILBOX_CREDENTIALS)
        SYSTEM_MAILBOX_CREDENTIALS.chmod(0o600)
    atomic_write_text(Path("/etc/masspanel/system-mail.env"),
        f"SYSTEM_MAILBOX={mailbox}\nSYSTEM_MAILBOX_CREDENTIALS={SYSTEM_MAILBOX_CREDENTIALS}\n", 0o600)
    aliases = Path("/etc/aliases")
    alias_text = aliases.read_text(encoding="utf-8") if aliases.exists() else ""
    root_line = f"root: {mailbox}"
    if re.search(r"(?m)^root\s*:", alias_text): alias_text = re.sub(r"(?m)^root\s*:.*$", root_line, alias_text)
    else: alias_text = alias_text.rstrip() + "\n" + root_line + "\n"
    atomic_write_text(aliases, alias_text, 0o644)
    newaliases = next((path for path in ("/usr/bin/newaliases", "/usr/sbin/newaliases") if Path(path).exists()), "")
    if newaliases:
        run([newaliases], timeout=30)
    if Path("/etc/systemd/system/masspanel-system-mail-sorter.timer").exists():
        run(["/usr/bin/systemctl", "daemon-reload"], timeout=30)
        run(["/usr/bin/systemctl", "enable", "--now", "masspanel-system-mail-sorter.timer"], timeout=30)
    return {"mailbox": mailbox, "created": created, "smtp_enabled": False}


def grommunio_system_mailbox_credentials(payload):
    mailbox = str(payload.get("full_email", "")).lower().strip()
    if not valid_email_address(mailbox): fail("Invalid owner system mailbox.")
    try: credentials = json.loads(SYSTEM_MAILBOX_CREDENTIALS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): fail("Owner system mailbox credentials are unavailable.")
    password = credentials.get(mailbox)
    if not isinstance(password, str) or len(password) < 32: fail("Owner system mailbox credentials are unavailable.")
    return {"username": mailbox, "password": password, "mailbox": mailbox}


def firewall_trust_admin_ip(payload):
    raw = str(payload.get("ip", "")).strip()
    try: address = ipaddress.ip_address(raw)
    except ValueError: fail("Invalid administrator IP address.")
    if not address.is_global: fail("Administrator trust requires a public IP address.")
    trusted_file = Path("/etc/masspanel/trusted-admin-ip")
    trusted_file.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    previous = trusted_file.read_text(encoding="utf-8").strip() if trusted_file.exists() else ""
    if previous != str(address):
        atomic_write_text(trusted_file, str(address) + "\n", 0o644)
    _firewall_sync_fail2ban_ignores()
    if Path("/usr/bin/fail2ban-client").exists():
        status = subprocess.run(["/usr/bin/fail2ban-client", "status"], capture_output=True, text=True, timeout=15)
        if status.returncode == 0:
            match = re.search(r"Jail list:\s*(.+)", status.stdout)
            for jail in (part.strip() for part in match.group(1).split(",")) if match else ():
                if jail: subprocess.run(["/usr/bin/fail2ban-client", "set", jail, "unbanip", str(address)], capture_output=True, timeout=10)
    return {"trusted_ip": str(address), "changed": previous != str(address)}


def _firewall_ignored():
    path = Path("/etc/masspanel/firewall-ignore.json")
    if not path.exists(): return []
    try: values = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError): return []
    result = []
    for value in values if isinstance(values, list) else []:
        try: result.append(str(ipaddress.ip_address(str(value))))
        except ValueError: continue
    return sorted(set(result))


def _firewall_sync_fail2ban_ignores():
    trusted_file = Path("/etc/masspanel/trusted-admin-ip")
    trusted = trusted_file.read_text(encoding="utf-8").strip() if trusted_file.exists() else ""
    addresses = ["127.0.0.1/8", "::1"] + _firewall_ignored()
    if trusted: addresses.append(trusted)
    config = "[DEFAULT]\nignoreip = " + " ".join(dict.fromkeys(addresses)) + "\n"
    target = Path("/etc/fail2ban/jail.d/masspanel-ignore.local")
    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write_text(target, config, 0o644)
    if Path("/usr/bin/fail2ban-client").exists():
        subprocess.run(["/usr/bin/fail2ban-client", "reload"], capture_output=True, text=True, timeout=30)


def _firewall_ensure():
    exists = subprocess.run(["/usr/sbin/nft", "list", "table", "inet", "masspanel"], capture_output=True, text=True, timeout=15)
    if exists.returncode == 0: return
    rules = """table inet masspanel {
 set blocked_ipv4 { type ipv4_addr; flags interval; }
 set blocked_ipv6 { type ipv6_addr; flags interval; }
 chain input { type filter hook input priority -5; policy accept; ip saddr @blocked_ipv4 drop; ip6 saddr @blocked_ipv6 drop; }
}
"""
    staged = Path("/tmp/masspanel-firewall.nft")
    staged.write_text(rules, encoding="utf-8")
    run(["/usr/sbin/nft", "-f", str(staged)])
    persist = Path("/etc/nftables.d/masspanel.nft")
    persist.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    atomic_write_text(persist, rules, 0o600)
    main = Path("/etc/nftables.conf")
    current = main.read_text(encoding="utf-8") if main.exists() else "#!/usr/sbin/nft -f\nflush ruleset\n"
    include = 'include "/etc/nftables.d/*.nft"'
    if include not in current: atomic_write_text(main, current.rstrip() + "\n" + include + "\n", 0o755)


def _firewall_addresses(family):
    name = "blocked_ipv4" if family == 4 else "blocked_ipv6"
    result = subprocess.run(["/usr/sbin/nft", "list", "set", "inet", "masspanel", name], capture_output=True, text=True, timeout=15)
    match = re.search(r"elements\s*=\s*\{([^}]*)\}", result.stdout, re.S)
    return sorted(part.strip() for part in match.group(1).split(",") if part.strip()) if match else []


def _firewall_persist():
    ipv4, ipv6 = _firewall_addresses(4), _firewall_addresses(6)
    def elements(values): return " elements = { " + ", ".join(values) + " };" if values else ""
    rules = "table inet masspanel {\n"
    rules += f" set blocked_ipv4 {{ type ipv4_addr; flags interval;{elements(ipv4)} }}\n"
    rules += f" set blocked_ipv6 {{ type ipv6_addr; flags interval;{elements(ipv6)} }}\n"
    rules += " chain input { type filter hook input priority -5; policy accept; ip saddr @blocked_ipv4 drop; ip6 saddr @blocked_ipv6 drop; }\n}\n"
    atomic_write_text(Path("/etc/nftables.d/masspanel.nft"), rules, 0o600)


def firewall_status(payload):
    _firewall_ensure()
    trusted_file = Path("/etc/masspanel/trusted-admin-ip")
    trusted = trusted_file.read_text(encoding="utf-8").strip() if trusted_file.exists() else ""
    listeners = []
    result = subprocess.run(["/usr/bin/ss", "-H", "-lntup"], capture_output=True, text=True, timeout=15)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5: continue
        protocol = parts[0].lower(); endpoint = parts[4]; port = endpoint.rsplit(":", 1)[-1]
        process = ""
        process_match = re.search(r'users:\(\("([^\"]+)', line)
        if process_match: process = process_match.group(1)
        if port.isdigit(): listeners.append({"protocol":protocol, "port":int(port), "process":process, "address":endpoint})
    jails, banned = [], []
    if Path("/usr/bin/fail2ban-client").exists():
        status = subprocess.run(["/usr/bin/fail2ban-client", "status"], capture_output=True, text=True, timeout=15)
        match = re.search(r"Jail list:\s*(.+)", status.stdout)
        for jail in (part.strip() for part in match.group(1).split(",")) if match else ():
            detail = subprocess.run(["/usr/bin/fail2ban-client", "status", jail], capture_output=True, text=True, timeout=15).stdout
            ips = re.search(r"Banned IP list:\s*(.*)", detail)
            jail_ips = ips.group(1).split() if ips else []
            jails.append({"name":jail, "banned":len(jail_ips)}); banned.extend(jail_ips)
    return {"engine":"nftables", "active":True, "trusted_ip":trusted, "ignored":_firewall_ignored(), "blocked":_firewall_addresses(4)+_firewall_addresses(6),
            "listeners":sorted(listeners, key=lambda item:(item["port"],item["protocol"])), "fail2ban_active":bool(jails), "jails":jails, "fail2ban_banned":sorted(set(banned))}


def firewall_address(payload, remove=False):
    raw = str(payload.get("ip", "")).strip()
    try: address = ipaddress.ip_address(raw)
    except ValueError: fail("Enter a valid IPv4 or IPv6 address.")
    if address.is_loopback or address.is_unspecified or address.is_multicast: fail("That address cannot be managed here.")
    trusted = Path("/etc/masspanel/trusted-admin-ip").read_text(encoding="utf-8").strip() if Path("/etc/masspanel/trusted-admin-ip").exists() else ""
    if not remove and str(address) in {trusted, str(payload.get("admin_ip", ""))}: fail("The current trusted administrator address cannot be blocked.")
    if not remove and str(address) in _firewall_ignored(): fail("This address is on the always-allow list. Remove it there before blocking it.")
    _firewall_ensure(); name = "blocked_ipv4" if address.version == 4 else "blocked_ipv6"
    action = "delete" if remove else "add"
    command = ["/usr/sbin/nft", action, "element", "inet", "masspanel", name, "{", str(address), "}"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    if result.returncode != 0 and not (remove and "No such file" in result.stderr) and not (not remove and "File exists" in result.stderr): fail(result.stderr.strip() or "Firewall update failed.")
    for jail in firewall_status({}).get("jails", []):
        if remove: subprocess.run(["/usr/bin/fail2ban-client", "set", jail["name"], "unbanip", str(address)], capture_output=True, timeout=10)
    _firewall_persist()
    return {"ip":str(address), "blocked":not remove}


def firewall_ignore(payload, remove=False):
    raw = str(payload.get("ip", "")).strip()
    try: address = ipaddress.ip_address(raw)
    except ValueError: fail("Enter a valid IPv4 or IPv6 address.")
    if address.is_unspecified or address.is_multicast: fail("That address cannot be managed here.")
    value = str(address); ignored = set(_firewall_ignored())
    if remove: ignored.discard(value)
    else: ignored.add(value)
    path = Path("/etc/masspanel/firewall-ignore.json")
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    atomic_write_text(path, json.dumps(sorted(ignored), indent=2) + "\n", 0o600)
    if not remove:
        firewall_address({"ip":value}, True)
        status = firewall_status({})
        for jail in status.get("jails", []):
            subprocess.run(["/usr/bin/fail2ban-client", "set", jail["name"], "unbanip", value], capture_output=True, timeout=10)
    _firewall_sync_fail2ban_ignores()
    return {"ip":value, "ignored":not remove}


def mail_dns_plan(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    hostname = str(payload.get("mail_hostname", "")).lower().strip().rstrip(".")
    server_ip = str(payload.get("server_ip", "")).strip()
    if not DOMAIN.fullmatch(domain) or not DOMAIN.fullmatch(hostname): fail("Invalid mail DNS domain or hostname.")
    try: ipaddress.ip_address(server_ip)
    except ValueError: fail("Invalid mail server IP address.")
    if ipaddress.ip_address(server_ip).is_loopback:
        route = run(["/usr/sbin/ip", "-4", "route", "get", "1.1.1.1"]).stdout.split()
        try: server_ip = route[route.index("src") + 1]
        except (ValueError, IndexError): fail("Could not determine the public mail server address.")
    key_dir = Path("/var/lib/rspamd/dkim"); key_dir.mkdir(mode=0o750, parents=True, exist_ok=True)
    key = key_dir / (domain + ".mail.key")
    if not key.exists():
        run(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)], timeout=60)
    key.chmod(0o640)
    try: rspamd = pwd.getpwnam("_rspamd")
    except KeyError: rspamd = pwd.getpwnam("rspamd")
    os.chown(key_dir, rspamd.pw_uid, rspamd.pw_gid)
    key_dir.chmod(0o750)
    os.chown(key, 0, rspamd.pw_gid)
    public_pem = run(["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout"], timeout=30).stdout
    public_b64 = "".join(line.strip() for line in public_pem.splitlines() if not line.startswith("---"))
    config = Path("/etc/rspamd/local.d/dkim_signing.conf")
    config.write_text('enabled = true;\nselector = "mail";\npath = "/var/lib/rspamd/dkim/$domain.$selector.key";\nallow_username_mismatch = true;\nsign_authenticated = true;\nsign_local = true;\n', encoding="utf-8")
    config.chmod(0o644)
    run(["/usr/sbin/postconf", "-e", "smtpd_milters = inet:127.0.0.1:11332", "non_smtpd_milters = inet:127.0.0.1:11332", "milter_protocol = 6", "milter_default_action = tempfail"])
    run(["/usr/sbin/postfix", "check"])
    run(["/usr/bin/systemctl", "reload", "postfix"], timeout=30)
    run(["/usr/bin/systemctl", "reload", "rspamd"], timeout=30)
    if subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", "rspamd"], timeout=15).returncode != 0:
        fail("Rspamd did not remain active after enabling DKIM signing.")
    records = [
        {"type":"MX", "name":"@", "value":"10 " + hostname + ".", "ttl":300, "purpose":"Incoming mail"},
        {"type":"TXT", "name":"@", "value":"v=spf1 mx a:" + hostname + " -all", "ttl":300, "purpose":"SPF sender policy"},
        {"type":"TXT", "name":"mail._domainkey", "value":"v=DKIM1; k=rsa; p=" + public_b64, "ttl":300, "purpose":"DKIM signature"},
        {"type":"TXT", "name":"_dmarc", "value":"v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "; adkim=s; aspf=s", "ttl":300, "purpose":"DMARC policy"},
        {"type":"CNAME", "name":"autodiscover", "value":hostname + ".", "ttl":300, "purpose":"Outlook autodiscover"},
        {"type":"CNAME", "name":"autoconfig", "value":hostname + ".", "ttl":300, "purpose":"Mail client setup"},
        {"type":"SRV", "name":"_autodiscover._tcp", "value":"0 0 443 " + hostname + ".", "ttl":300, "purpose":"Autodiscover service"},
    ]
    if hostname.endswith("." + domain):
        records.insert(0, {"type":"A", "name":hostname[:-len(domain)-1], "value":server_ip, "ttl":300, "purpose":"Mail server"})
    return {"domain": domain, "selector":"mail", "mail_host":{"name":hostname, "value":server_ip}, "records":records}


def cloudflare_request(method, path, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, data=data, method=method,
        headers={"Authorization":"Bearer " + token, "Content-Type":"application/json", "User-Agent":"MassPanel/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as response: result = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("errors", [])
        except (ValueError, AttributeError):
            detail = str(exc)
        fail("Cloudflare rejected the request: " + str(detail)[:220])
    except (urllib.error.URLError, ValueError) as exc: fail("Cloudflare request failed: " + str(exc)[:180])
    if not result.get("success"): fail("Cloudflare rejected the request: " + str(result.get("errors", []))[:180])
    return result.get("result")


def _cloudflare_connections():
    try:
        value = json.loads(CLOUDFLARE_CONNECTIONS.read_text(encoding="utf-8"))
        if isinstance(value, list): return [item for item in value if isinstance(item, dict) and item.get("token")]
    except (OSError, ValueError):
        pass
    if CLOUDFLARE_LEGACY_TOKEN.is_file():
        token = CLOUDFLARE_LEGACY_TOKEN.read_text(encoding="utf-8").strip()
        if token: return [{"id":hashlib.sha256(token.encode()).hexdigest()[:16], "label":"Legacy connection", "account_id":"", "account_name":"", "token_type":"user", "token":token}]
    return []


def _save_cloudflare_connections(connections):
    CLOUDFLARE_CONNECTIONS.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    temporary = CLOUDFLARE_CONNECTIONS.with_suffix(".tmp")
    temporary.write_text(json.dumps(connections, separators=(",", ":")), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(CLOUDFLARE_CONNECTIONS)
    CLOUDFLARE_CONNECTIONS.chmod(0o600)


def _cloudflare_public_connections(connections):
    return [{key:item.get(key, "") for key in ("id", "label", "account_id", "account_name", "token_type", "zones")} for item in connections]


def cloudflare_connect(payload):
    token = str(payload.get("token", "")).strip()
    account_id = str(payload.get("account_id", "")).lower().strip()
    label = str(payload.get("label", "")).strip()[:80]
    if len(token) < 20 or len(token) > 256: fail("Invalid Cloudflare API token.")
    if account_id and not re.fullmatch(r"[a-f0-9]{32}", account_id): fail("Cloudflare Account ID must contain 32 hexadecimal characters.")
    token_type = "account" if account_id else "user"
    verify_path = "/accounts/%s/tokens/verify" % account_id if account_id else "/user/tokens/verify"
    verified = cloudflare_request("GET", verify_path, token)
    if not isinstance(verified, dict) or verified.get("status") != "active": fail("Cloudflare token is not active.")
    zone_path = "/zones?per_page=50&status=active"
    if account_id: zone_path += "&account.id=" + urllib.parse.quote(account_id)
    zones = cloudflare_request("GET", zone_path, token)
    if not isinstance(zones, list): fail("Cloudflare did not return a valid zone list.")
    account_name = ""
    if zones and isinstance(zones[0].get("account"), dict): account_name = str(zones[0]["account"].get("name", ""))[:120]
    connection_id = hashlib.sha256((account_id + "\0" + token).encode()).hexdigest()[:16]
    connection = {"id":connection_id, "label":label or account_name or ("Cloudflare account " + account_id[-6:] if account_id else "Cloudflare user token"), "account_id":account_id, "account_name":account_name, "token_type":token_type, "token":token, "zones":[str(zone.get("name", "")) for zone in zones[:50]]}
    connections = [item for item in _cloudflare_connections() if item.get("id") != connection_id]
    connections.append(connection)
    _save_cloudflare_connections(connections)
    return {"connected":True, "connection":_cloudflare_public_connections([connection])[0], "connections":_cloudflare_public_connections(connections)}


def cloudflare_status(payload):
    connections = _cloudflare_connections()
    return {"connected":bool(connections), "connections":_cloudflare_public_connections(connections)}


def cloudflare_disconnect(payload):
    connection_id = str(payload.get("connection_id", "")).strip()
    connections = _cloudflare_connections()
    remaining = [item for item in connections if item.get("id") != connection_id]
    if len(remaining) == len(connections): fail("Cloudflare connection was not found.")
    _save_cloudflare_connections(remaining)
    return {"connected":bool(remaining), "connections":_cloudflare_public_connections(remaining)}


def _cloudflare_record_body(domain, item, comment):
    rtype = str(item.get("type", "")).upper()
    name = str(item.get("name", "")).lower().strip().rstrip(".") or "@"
    value = str(item.get("value", "")).strip()
    if rtype not in {"A", "AAAA", "CNAME", "MX", "TXT", "SRV"}:
        return None
    try:
        ttl = int(item.get("ttl", 300))
    except (TypeError, ValueError):
        fail("Invalid Cloudflare DNS TTL.")
    if ttl < 60 or ttl > 86400: fail("Invalid Cloudflare DNS TTL.")
    fqdn = domain if name == "@" else (name if name.endswith("." + domain) else name + "." + domain)
    content, priority = value.rstrip(".") if rtype == "CNAME" else value, None
    if rtype == "MX":
        parts = value.split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit(): fail("Invalid Cloudflare MX record.")
        priority, content = int(parts[0]), parts[1].rstrip(".")
    body = {"type":rtype, "name":fqdn, "content":content, "ttl":ttl, "proxied":False, "comment":comment}
    if priority is not None: body["priority"] = priority
    if rtype == "SRV":
        parts = value.split()
        if len(parts) != 4 or not all(part.isdigit() for part in parts[:3]): fail("Invalid Cloudflare SRV record.")
        body.pop("content", None)
        body["data"] = {"priority":int(parts[0]), "weight":int(parts[1]), "port":int(parts[2]), "target":parts[3].rstrip(".")}
    return body


def _cloudflare_record_matches(existing, desired):
    if str(existing.get("type", "")).upper() != desired["type"] or str(existing.get("name", "")).lower().rstrip(".") != desired["name"].lower().rstrip("."):
        return False
    if desired["type"] == "SRV":
        current = existing.get("data") or {}
        expected = desired["data"]
        try:
            priority, weight, port = int(current.get("priority", -1)), int(current.get("weight", -1)), int(current.get("port", -1))
        except (TypeError, ValueError):
            return False
        return (
            priority == expected["priority"] and weight == expected["weight"] and port == expected["port"] and
            str(current.get("target", "")).rstrip(".") == expected["target"]
        )
    current_content, desired_content = str(existing.get("content", "")), str(desired.get("content", ""))
    if desired["type"] in {"CNAME", "MX"}:
        current_content, desired_content = current_content.rstrip("."), desired_content.rstrip(".")
    if current_content != desired_content:
        return False
    if desired["type"] != "MX": return True
    try: return int(existing.get("priority", -1)) == desired["priority"]
    except (TypeError, ValueError): return False


def cloudflare_sync(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    scope = str(payload.get("scope") or domain).lower().strip().rstrip(".")
    records = payload.get("records", [])
    prune = bool(payload.get("prune"))
    adopt_legacy = bool(payload.get("adopt_legacy"))
    if not DOMAIN.fullmatch(domain) or not DOMAIN.fullmatch(scope) or not isinstance(records, list) or len(records) > 500: fail("Invalid Cloudflare DNS request.")
    records = list(records)
    if bool(payload.get("ensure_apex")) and not any(str(item.get("type", "")).upper() == "A" and str(item.get("name", "")).strip().rstrip(".") in {"", "@"} for item in records):
        route = run(["/usr/sbin/ip", "-4", "route", "get", "1.1.1.1"]).stdout.split()
        try: server_ip = route[route.index("src") + 1]
        except (ValueError, IndexError): fail("Could not determine the public server address for Cloudflare.")
        if ipaddress.ip_address(server_ip).version != 4: fail("Could not determine the public server address for Cloudflare.")
        records.append({"type":"A", "name":"@", "value":server_ip, "ttl":300})
    connections = _cloudflare_connections()
    if not connections: fail("Connect Cloudflare first.")
    labels = domain.split("."); zone = None; token = ""; connection = None
    for candidate_connection in connections:
        candidate_token = str(candidate_connection.get("token", ""))
        for offset in range(0, len(labels)-1):
            candidate = ".".join(labels[offset:])
            query = "/zones?name=" + urllib.parse.quote(candidate) + "&status=active"
            if candidate_connection.get("account_id"): query += "&account.id=" + urllib.parse.quote(candidate_connection["account_id"])
            zones = cloudflare_request("GET", query, candidate_token)
            if zones: zone, token, connection = zones[0], candidate_token, candidate_connection; break
        if zone: break
    if not zone: fail("No active Cloudflare zone was found for this domain.")
    managed_comment = "Managed by MassPanel:" + scope
    existing_records = cloudflare_request("GET", "/zones/%s/dns_records?per_page=5000" % zone["id"], token)
    if not isinstance(existing_records, list): fail("Cloudflare returned an invalid DNS record list.")
    used_ids, created, updated = set(), 0, 0
    for item in records:
        body = _cloudflare_record_body(domain, item, managed_comment)
        if body is None: continue
        exact = next((record for record in existing_records if record.get("id") not in used_ids and _cloudflare_record_matches(record, body)), None)
        reusable = exact or next((record for record in existing_records if record.get("id") not in used_ids and str(record.get("type", "")).upper() == body["type"] and str(record.get("name", "")).lower().rstrip(".") == body["name"].lower().rstrip(".") and str(record.get("comment") or "") in {managed_comment, "Managed by MassPanel"}), None)
        if reusable:
            cloudflare_request("PUT", "/zones/%s/dns_records/%s" % (zone["id"], reusable["id"]), token, body)
            used_ids.add(reusable["id"]); updated += 1
        else:
            created_record = cloudflare_request("POST", "/zones/%s/dns_records" % zone["id"], token, body)
            if isinstance(created_record, dict) and created_record.get("id"): used_ids.add(created_record["id"])
            created += 1
    deleted = 0
    if prune:
        for record in existing_records:
            comment = str(record.get("comment") or "")
            managed = comment == managed_comment or (adopt_legacy and comment == "Managed by MassPanel")
            if managed and record.get("id") not in used_ids:
                cloudflare_request("DELETE", "/zones/%s/dns_records/%s" % (zone["id"], record["id"]), token)
                deleted += 1
    return {"domain":domain, "scope":scope, "zone":zone["name"], "connection_id":connection.get("id", ""), "connection_label":connection.get("label", ""), "records_synced":created + updated, "records_created":created, "records_updated":updated, "records_deleted":deleted}


def sync_email(payload):
    accounts = payload.get("accounts", [])
    if not isinstance(accounts, list) or len(accounts) > 5000: fail("Invalid mail account set.")
    domains, mailboxes, aliases, users = set(), [], [], []
    vmail = pwd.getpwnam("vmail")
    for item in accounts:
        address = str(item.get("full_email", "")).lower().strip()
        domain = str(item.get("domain", "")).lower().strip()
        localpart = str(item.get("localpart", "")).lower().strip()
        destination = str(item.get("destination") or "").lower().strip()
        password_hash = str(item.get("password_hash") or "")
        if address != f"{localpart}@{domain}" or not DOMAIN.fullmatch(domain) or not re.fullmatch(r"[a-z0-9._%+-]{1,64}", localpart):
            fail("Invalid mail account identity.")
        domains.add(domain)
        if destination:
            if not valid_email_address(destination): fail("Invalid forwarding address.")
            aliases.append(f"{address} {destination}")
        else:
            if not password_hash.startswith("{SHA512-CRYPT}"): fail("Mailbox password is missing.")
            relative = f"{domain}/{localpart}/Maildir/"
            mailboxes.append(f"{address} {relative}")
            quota = int(item.get("quota_mb") or 0)
            if quota < 0 or quota > 1048576: fail("Invalid mailbox quota.")
            quota_field = f" userdb_quota_rule=*:storage={quota}M" if quota else ""
            users.append(f"{address}:{password_hash}:5000:5000::/var/vmail/{domain}/{localpart}::userdb_mail=maildir:/var/vmail/{domain}/{localpart}/Maildir{quota_field}")
            home = Path("/var/vmail") / domain / localpart
            maildir = home / "Maildir"
            run(["/usr/bin/maildirmake.dovecot", str(maildir)]) if not maildir.exists() else None
            for directory in (home.parent, home, maildir):
                os.chown(directory, vmail.pw_uid, vmail.pw_gid)
            run(["/usr/bin/chown", "-R", f"{vmail.pw_uid}:{vmail.pw_gid}", str(home)])
    files = {
        Path("/etc/postfix/masspanel-domains"): [f"{domain} OK" for domain in sorted(domains)],
        Path("/etc/postfix/masspanel-mailboxes"): mailboxes,
        Path("/etc/postfix/masspanel-aliases"): aliases,
        Path("/etc/dovecot/masspanel-users"): users,
    }
    for path, lines in files.items():
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        if path.name == "masspanel-users":
            dovecot_gid = grp.getgrnam("dovecot").gr_gid
            os.chown(path, 0, dovecot_gid)
            path.chmod(0o640)
        else:
            path.chmod(0o644)
    for name in ("masspanel-domains", "masspanel-mailboxes", "masspanel-aliases"):
        run(["/usr/sbin/postmap", "/etc/postfix/" + name])
    run(["/usr/sbin/postfix", "check"])
    run(["/usr/bin/systemctl", "reload", "postfix"])
    run(["/usr/bin/systemctl", "reload", "dovecot"])
    return {"accounts": len(accounts), "domains": len(domains)}


def mail_certificate(payload):
    hostname = str(payload.get("hostname", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(hostname): fail("Invalid mail hostname.")
    webroot = Path("/var/www/snappymail")
    if not webroot.is_dir(): fail("Mail certificate webroot is unavailable.")
    permanent = Path("/etc/nginx/sites-available/masspanel-mail")
    enabled = Path("/etc/nginx/sites-enabled/masspanel-mail")
    acme_available = Path("/etc/nginx/sites-available/masspanel-mail-acme")
    acme_enabled = Path("/etc/nginx/sites-enabled/masspanel-mail-acme")
    gromox_bundle = Path("/etc/grommunio-common/ssl/server-bundle.pem")
    gromox_key = Path("/etc/grommunio-common/ssl/server.key")
    renewal_hook = Path("/etc/letsencrypt/renewal-hooks/deploy/masspanel-mail-certificate")
    paths = (permanent, enabled, acme_available, acme_enabled, gromox_bundle, gromox_key, renewal_hook)
    snapshots = {path: snapshot_path(path) for path in paths}
    success = False
    try:
        current = permanent.read_text(encoding="utf-8") if permanent.is_file() else ""
        if not enabled.exists() or "/.well-known/acme-challenge/" not in current or f"server_name {hostname};" not in current:
            atomic_write_text(acme_available,
                "server {\n  listen 80; listen [::]:80;\n  server_name " + hostname + ";\n"
                "  location ^~ /.well-known/acme-challenge/ { root " + str(webroot) + "; try_files $uri =404; }\n"
                "  location / { return 301 https://$host$request_uri; }\n}\n")
            if acme_enabled.is_symlink() or acme_enabled.is_file(): acme_enabled.unlink()
            if acme_enabled.exists(): fail("Mail ACME Nginx path is not a file.")
            os.symlink(acme_available, acme_enabled)
            run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"])

        email = str(payload.get("email", "")).strip()
        command = ["/usr/bin/certbot", "certonly", "--webroot", "-w", str(webroot), "-d", hostname,
                   "--non-interactive", "--agree-tos", "--keep-until-expiring"]
        if bool(payload.get("force")): command.append("--force-renewal")
        command += ["--email", email] if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) else ["--register-unsafely-without-email"]
        run(command, timeout=180)
        cert = f"/etc/letsencrypt/live/{hostname}/fullchain.pem"
        key = f"/etc/letsencrypt/live/{hostname}/privkey.pem"
        if not Path(cert).is_file() or not Path(key).is_file(): fail("Certbot did not install the mail certificate.")
        gromox_account = pwd.getpwnam("gromox")
        gromox_bundle.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        atomic_write_bytes(gromox_bundle, Path(cert).read_bytes(), 0o640)
        atomic_write_bytes(gromox_key, Path(key).read_bytes(), 0o600)
        os.chown(gromox_bundle, gromox_account.pw_uid, gromox_account.pw_gid)
        os.chown(gromox_key, gromox_account.pw_uid, gromox_account.pw_gid)
        renewal_hook.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        hook_lineage = f"/etc/letsencrypt/live/{hostname}"
        hook_content = (
            "#!/bin/sh\nset -eu\n"
            f"[ \"${{RENEWED_LINEAGE:-}}\" = \"{hook_lineage}\" ] || exit 0\n"
            f"install -o gromox -g gromox -m 0640 \"{hook_lineage}/fullchain.pem\" \"{gromox_bundle}\"\n"
            f"install -o gromox -g gromox -m 0600 \"{hook_lineage}/privkey.pem\" \"{gromox_key}\"\n"
            "systemctl reload-or-restart gromox-http gromox-imap gromox-pop3\n"
        )
        atomic_write_text(renewal_hook, hook_content, 0o750)
        final_config = (
            "server {\n  listen 80; listen [::]:80;\n  server_name " + hostname + ";\n"
            "  location ^~ /.well-known/acme-challenge/ { root " + str(webroot) + "; try_files $uri =404; }\n"
            "  location / { return 301 https://$host$request_uri; }\n}\n\n"
            "server {\n  listen 443 ssl http2; listen [::]:443 ssl http2;\n  server_name " + hostname + ";\n"
            "  ssl_certificate " + cert + ";\n  ssl_certificate_key " + key + ";\n"
            "  include /usr/share/grommunio-common/nginx/proxy_params.conf;\n"
            "  include /usr/share/grommunio-common/nginx/proxy_headers.conf;\n"
            "  include /usr/share/grommunio-common/nginx/brotli-params*.conf;\n  server_tokens off;\n"
            "  include /etc/grommunio-common/nginx/locations.d/*.conf;\n"
            "  include /usr/share/grommunio-common/nginx/locations.d/*.conf;\n}\n"
        )
        atomic_write_text(permanent, final_config)
        if enabled.is_symlink() or enabled.is_file(): enabled.unlink()
        if enabled.exists(): fail("Mail Nginx enabled path is not a file.")
        os.symlink(permanent, enabled)
        acme_enabled.unlink(missing_ok=True); acme_available.unlink(missing_ok=True)
        atomic_write_text(Path("/etc/mailname"), hostname + "\n")
        run(["/usr/sbin/postconf", "-e", f"myhostname = {hostname}"])
        run(["/usr/sbin/postconf", "-e", f"smtp_helo_name = {hostname}"])
        run(["/usr/sbin/postconf", "-e", f"smtpd_tls_cert_file = {cert}"])
        run(["/usr/sbin/postconf", "-e", f"smtpd_tls_key_file = {key}"])
        run(["/usr/sbin/postfix", "check"]); run(["/usr/sbin/nginx", "-t"])
        run(["/usr/bin/systemctl", "reload", "postfix"]); run(["/usr/bin/systemctl", "reload", "nginx"])
        for service in ("gromox-http", "gromox-imap", "gromox-pop3"):
            subprocess.run(["/usr/bin/systemctl", "reload-or-restart", service], capture_output=True, text=True, timeout=30)
        success = True
        return {"hostname": hostname, "certificate": cert, "mail_identity_configured": True}
    finally:
        if not success:
            for path in paths: restore_path(path, snapshots[path])
            checked = subprocess.run(["/usr/sbin/nginx", "-t"], capture_output=True, text=True, timeout=30)
            if checked.returncode == 0:
                subprocess.run(["/usr/bin/systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=30)


def panel_certificate(payload):
    hostname = str(payload.get("hostname", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(hostname): fail("Invalid panel hostname.")
    webroot = Path("/var/www/masspanel-panel-acme"); webroot.mkdir(mode=0o755, parents=True, exist_ok=True)
    permanent = Path("/etc/nginx/sites-available/masspanel-panel-host")
    enabled = Path("/etc/nginx/sites-enabled/masspanel-panel-host")
    acme_available = Path("/etc/nginx/sites-available/masspanel-panel-acme")
    acme_enabled = Path("/etc/nginx/sites-enabled/masspanel-panel-acme")
    paths = (permanent, enabled, acme_available, acme_enabled)
    snapshots = {path: snapshot_path(path) for path in paths}
    success = False
    try:
        current = permanent.read_text(encoding="utf-8") if permanent.is_file() else ""
        if not enabled.exists() or "/.well-known/acme-challenge/" not in current or f"server_name {hostname};" not in current:
            atomic_write_text(acme_available,
                "server { listen 80; listen [::]:80; server_name " + hostname + "; "
                "location ^~ /.well-known/acme-challenge/ { root " + str(webroot) + "; try_files $uri =404; } "
                "location / { return 301 https://$host$request_uri; } }\n")
            if acme_enabled.is_symlink() or acme_enabled.is_file(): acme_enabled.unlink()
            if acme_enabled.exists(): fail("Panel ACME Nginx path is not a file.")
            os.symlink(acme_available, acme_enabled)
            run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"])

        email = str(payload.get("email", "")).strip()
        command = ["/usr/bin/certbot", "certonly", "--webroot", "-w", str(webroot), "-d", hostname,
                   "--non-interactive", "--agree-tos", "--keep-until-expiring"]
        if bool(payload.get("force")): command.append("--force-renewal")
        command += ["--email", email] if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) else ["--register-unsafely-without-email"]
        run(command, timeout=180)
        cert = f"/etc/letsencrypt/live/{hostname}/fullchain.pem"; key = f"/etc/letsencrypt/live/{hostname}/privkey.pem"
        if not Path(cert).is_file() or not Path(key).is_file(): fail("Certbot did not install the panel certificate.")
        final_config = (
            "server { listen 80; listen [::]:80; server_name " + hostname + "; location ^~ /.well-known/acme-challenge/ { root " + str(webroot) + "; try_files $uri =404; } location / { return 301 https://$host$request_uri; } }\n"
            "server { listen 443 ssl http2; listen [::]:443 ssl http2; server_name " + hostname + ";\n"
            "ssl_certificate " + cert + "; ssl_certificate_key " + key + "; ssl_protocols TLSv1.2 TLSv1.3;\n"
            "root /opt/masspanel/frontend; index index.html; client_max_body_size 64m;\n"
            "add_header X-Content-Type-Options nosniff always; add_header X-Frame-Options DENY always;\n"
            "include /etc/nginx/snippets/masspanel-tools.conf;\n"
            "location = /masspanel-source { alias /usr/share/doc/masspanel/masspanel-source.html; default_type text/html; }\n"
            "location = /masspanel-corresponding-source.tar.gz { alias /usr/share/masspanel/source/masspanel-corresponding-source.tar.gz; default_type application/gzip; add_header Content-Disposition 'attachment; filename=masspanel-corresponding-source.tar.gz'; }\n"
            "location = /masspanel-open-source-license { alias /usr/share/doc/masspanel/LICENSE; default_type text/plain; }\n"
            "location /api/ { proxy_pass http://127.0.0.1:8100; proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto https; proxy_read_timeout 600s; }\n"
            "location ^~ /assets/ { try_files $uri =404; expires 1y; add_header Cache-Control \"public, immutable\"; }\n"
            "location = /index.html { add_header Cache-Control \"no-store\"; }\n"
            "location / { try_files $uri $uri/ /index.html; add_header Cache-Control \"no-store\"; }\n}\n"
        )
        atomic_write_text(permanent, final_config)
        if enabled.is_symlink() or enabled.is_file(): enabled.unlink()
        if enabled.exists(): fail("Panel Nginx enabled path is not a file.")
        os.symlink(permanent, enabled)
        acme_enabled.unlink(missing_ok=True); acme_available.unlink(missing_ok=True)
        run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"])
        success = True
        return {"hostname":hostname, "certificate":cert, "url":"https://" + hostname}
    finally:
        if not success:
            for path in paths: restore_path(path, snapshots[path])
            checked = subprocess.run(["/usr/sbin/nginx", "-t"], capture_output=True, text=True, timeout=30)
            if checked.returncode == 0:
                subprocess.run(["/usr/bin/systemctl", "reload", "nginx"], capture_output=True, text=True, timeout=30)


def storefront_config(payload):
    enabled_flag = bool(payload.get("enabled"))
    hostname = str(payload.get("hostname", "")).lower().strip().rstrip(".")
    available = Path("/etc/nginx/sites-available/masspanel-store")
    enabled = Path("/etc/nginx/sites-enabled/masspanel-store")
    if not enabled_flag:
        enabled.unlink(missing_ok=True); available.unlink(missing_ok=True)
        run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"])
        return {"enabled": False}
    if not DOMAIN.fullmatch(hostname): fail("Invalid storefront hostname.")
    webroot = Path("/var/www/masspanel-store-acme"); webroot.mkdir(mode=0o755, parents=True, exist_ok=True)
    cert = Path(f"/etc/letsencrypt/live/{hostname}/fullchain.pem"); key = Path(f"/etc/letsencrypt/live/{hostname}/privkey.pem")
    proxy = "location / { proxy_pass http://127.0.0.1:8100/store/; proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto $scheme; client_max_body_size 2m; }"
    http_tail = "location / { return 301 https://$host$request_uri; }" if cert.is_file() and key.is_file() else proxy
    config = "server { listen 80; listen [::]:80; server_name " + hostname + "; location ^~ /.well-known/acme-challenge/ { root " + str(webroot) + "; try_files $uri =404; } " + http_tail + " }\n"
    if cert.is_file() and key.is_file():
        config += "server { listen 443 ssl http2; listen [::]:443 ssl http2; server_name " + hostname + "; ssl_certificate " + str(cert) + "; ssl_certificate_key " + str(key) + "; ssl_protocols TLSv1.2 TLSv1.3; add_header X-Content-Type-Options nosniff always; add_header Referrer-Policy strict-origin-when-cross-origin always; " + proxy + " }\n"
    atomic_write_text(available, config)
    if enabled.is_symlink() or enabled.is_file(): enabled.unlink()
    if enabled.exists(): fail("Storefront Nginx enabled path is not a file.")
    os.symlink(available, enabled)
    run(["/usr/sbin/nginx", "-t"]); run(["/usr/bin/systemctl", "reload", "nginx"])
    return {"enabled": True, "hostname": hostname, "tls_ready": cert.is_file() and key.is_file()}


def storefront_certificate(payload):
    hostname = str(payload.get("hostname", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(hostname): fail("Invalid storefront hostname.")
    storefront_config({"enabled": True, "hostname": hostname})
    webroot = Path("/var/www/masspanel-store-acme")
    email = str(payload.get("email", "")).strip()
    command = ["/usr/bin/certbot", "certonly", "--webroot", "-w", str(webroot), "-d", hostname, "--non-interactive", "--agree-tos", "--keep-until-expiring"]
    if bool(payload.get("force")): command.append("--force-renewal")
    command += ["--email", email] if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) else ["--register-unsafely-without-email"]
    run(command, timeout=180)
    result = storefront_config({"enabled": True, "hostname": hostname})
    if not result["tls_ready"]: fail("Certbot did not install the storefront certificate.")
    return {"hostname": hostname, "url": "https://" + hostname, "tls_ready": True}


def configure_domain(payload):
    domain = payload.get("domain", "")
    account, webroot = domain_paths(domain, payload.get("owner"), payload.get("webroot"))
    mode = payload.get("ssl_mode", "disabled")
    suspended = bool(payload.get("suspended", False))
    php_socket = f"/run/php/masspanel-{account.pw_name}.sock" if payload.get("wordpress") else None
    if mode == "letsencrypt":
        bootstrap_mode = "self" if (Path("/etc/letsencrypt/live") / domain / "fullchain.pem").exists() else "disabled"
        write_domain_config(domain, webroot, bootstrap_mode, suspended, php_socket)
        if not suspended and bootstrap_mode == "disabled":
            email = str(payload.get("email", "")).strip()
            command = ["/usr/bin/certbot", "certonly", "--webroot", "-w", str(webroot), "-d", domain,
                       "--non-interactive", "--agree-tos", "--keep-until-expiring"]
            command += ["--email", email] if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) else ["--register-unsafely-without-email"]
            run(command, timeout=180)
    write_domain_config(domain, webroot, mode, suspended, php_socket)
    grant_panel_access(account, webroot)
    return {"domain": domain, "ssl_mode": mode, "suspended": suspended}


def regenerate_domain_certificate(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    account, webroot = domain_paths(domain, payload.get("owner"), payload.get("webroot"))
    if not DOMAIN.fullmatch(domain): fail("Invalid certificate domain.")
    if not webroot.is_dir(): fail("Website document root is unavailable.")
    email = str(payload.get("email", "")).strip()
    command = ["/usr/bin/certbot", "certonly", "--webroot", "-w", str(webroot), "-d", domain,
               "--non-interactive", "--agree-tos", "--force-renewal"]
    command += ["--email", email] if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) else ["--register-unsafely-without-email"]
    run(command, timeout=240)
    cert = Path("/etc/letsencrypt/live") / domain / "fullchain.pem"
    key = Path("/etc/letsencrypt/live") / domain / "privkey.pem"
    if not cert.is_file() or not key.is_file(): fail("Certbot did not install the renewed certificate.")
    run(["/usr/sbin/nginx", "-t"], timeout=30)
    run(["/usr/bin/systemctl", "reload", "nginx"], timeout=30)
    return {"domain":domain, "certificate":str(cert), "regenerated":True}

def list_users():
    users = []
    for entry in pwd.getpwall():
        if entry.pw_uid < 1000 or entry.pw_uid >= 60000:
            continue
        try:
            locked = spwd.getspnam(entry.pw_name).sp_pwdp.startswith(("!", "*"))
        except (KeyError, PermissionError):
            locked = True
        try:
            stamp = os.stat(entry.pw_dir).st_ctime
            created = dt.datetime.fromtimestamp(stamp).strftime("%Y-%m-%d %H:%M")
        except OSError:
            created = "—"
        users.append({"username":entry.pw_name,"uid":entry.pw_uid,"home":entry.pw_dir,"shell":entry.pw_shell,"locked":locked,"created":created,"protected":entry.pw_name in PROTECTED})
    return sorted(users, key=lambda item: item["uid"])

def create_user(payload):
    username = validate_username(payload.get("username"))
    if username in PROTECTED: fail("This username is reserved.")
    try:
        pwd.getpwnam(username); fail("That username already exists.")
    except KeyError: pass
    shell = payload.get("shell", "/bin/bash")
    if shell not in SHELLS: fail("Unsupported shell.")
    display = payload.get("display_name", "")
    if not isinstance(display, str) or len(display) > 80 or any(ch in display for ch in ":\n\r"): fail("Invalid display name.")
    password = payload.get("password", "")
    if not isinstance(password, str) or len(password) < 12 or len(password) > 256: fail("Password must contain 12-256 characters.")
    run(["/usr/sbin/useradd", "--create-home", "--shell", shell, "--comment", display, "--", username])
    try: run(["/usr/sbin/chpasswd"], f"{username}:{password}\n")
    except SystemExit:
        subprocess.run(["/usr/sbin/userdel", "--remove", "--", username], capture_output=True, timeout=20)
        raise
    return {"username": username}

def mutate(payload, operation):
    username = validate_username(payload.get("username"))
    if username in PROTECTED: fail("Protected accounts cannot be changed in MassPanel.")
    try: pwd.getpwnam(username)
    except KeyError: fail("User not found.")
    if operation == "lock": run(["/usr/sbin/usermod", "--lock", "--", username])
    elif operation == "unlock": run(["/usr/sbin/usermod", "--unlock", "--", username])
    elif operation == "password":
        password = payload.get("password", "")
        if not isinstance(password, str) or len(password) < 12 or len(password) > 256: fail("Password must contain 12-256 characters.")
        run(["/usr/sbin/chpasswd"], f"{username}:{password}\n")
    return {"username": username}

def remove_new(payload):
    username = validate_username(payload.get("username"))
    if username in PROTECTED: fail("Protected accounts cannot be removed.")
    run(["/usr/sbin/userdel", "--remove", "--", username])
    return {"username": username}


def domain_delete(payload):
    domain = payload.get("domain", "")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain.strip().strip(".")):
        fail("Invalid domain name.")

    owner = payload.get("owner")
    webroot = payload.get("webroot", "")
    if webroot:
        _, root = domain_paths(domain, owner, webroot, require_exists=False)
        domain_dir = root.parent
        if root.exists():
            run(["/usr/bin/rm", "-rf", str(domain_dir)])

    conf = Path("/etc/nginx/sites-available") / ("masspanel-domain-" + domain + ".conf")
    enabled = Path("/etc/nginx/sites-enabled") / conf.name
    if enabled.exists():
        enabled.unlink()
    if conf.exists():
        conf.unlink()
    rules = Path("/etc/nginx/masspanel-domain-rules") / (domain + ".conf")
    rules.unlink(missing_ok=True)
    zone = Path("/var/lib/bind/masspanel") / (domain + ".zone")
    if zone.exists():
        zone.unlink()
        rebuild_dns_config()
    db_name = str(payload.get("db_name", ""))
    db_user = str(payload.get("db_user", ""))
    if db_name or db_user:
        if not re.fullmatch(r"mp_[a-f0-9]{12}", db_name) or not re.fullmatch(r"mpu_[a-f0-9]{12}", db_user):
            fail("Invalid application database identity.")
        run(["/usr/bin/mariadb"], f"DROP DATABASE IF EXISTS `{db_name}`;DROP USER IF EXISTS `{db_user}`@`localhost`;", timeout=40)
    run(["/usr/sbin/nginx", "-t"])
    run(["/usr/bin/systemctl", "reload", "nginx"])
    return {"domain": domain}

def create_domain(payload):
    domain = payload.get("domain", "")
    owner = validate_username(payload.get("owner"))
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    try: account = pwd.getpwnam(owner)
    except KeyError: fail("Website owner does not exist.")
    Path(account.pw_dir).chmod(0o711)
    webroot = Path(account.pw_dir) / "domains" / domain / "public_html"
    webroot.mkdir(mode=0o750, parents=True, exist_ok=False)
    page = "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Website ready</title></head><body><h1>Website ready</h1><p>" + domain + " is hosted by MassPanel.</p></body></html>\n"
    index = webroot / "index.html"; index.write_text(page, encoding="utf-8")
    for path in [webroot.parent.parent, webroot.parent, webroot, index]: os.chown(path, account.pw_uid, account.pw_gid)
    webroot.parent.parent.chmod(0o755); webroot.parent.chmod(0o755); webroot.chmod(0o755); index.chmod(0o644)
    try:
        grant_panel_access(account, webroot)
        write_domain_config(domain, webroot, "disabled", False)
    except BaseException:
        import shutil
        shutil.rmtree(webroot.parent, ignore_errors=True)
        raise
    return {"domain": domain, "webroot": str(webroot)}


def wordpress_install(payload):
    domain = payload.get("domain", "")
    owner = validate_username(payload.get("owner"))
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    account, webroot = domain_paths(domain, owner, payload.get("webroot"))
    existing = [item for item in webroot.iterdir() if item.name != "index.html"]
    if existing: fail("The website root is not empty. Back it up or use a fresh domain.")
    admin_user = str(payload.get("admin_user", "admin")).strip()
    admin_email = str(payload.get("admin_email", "")).strip()
    admin_password = str(payload.get("admin_password", ""))
    title = str(payload.get("title", domain)).strip()[:120]
    application_slug = str(payload.get("application_slug", "wordpress")).lower()
    presets = {"wordpress":None, "woocommerce":"woocommerce", "elementor":"elementor", "bbpress":"bbpress"}
    if application_slug not in presets: fail("Unsupported application preset.")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,60}", admin_user): fail("Invalid WordPress administrator username.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", admin_email): fail("Invalid WordPress administrator email.")
    if len(admin_password) < 12 or len(admin_password) > 256: fail("WordPress administrator password must contain 12-256 characters.")
    token = hashlib.sha256(domain.encode()).hexdigest()[:12]
    db_name = "mp_" + token
    db_user = "mpu_" + token
    db_password = secrets.token_urlsafe(30)
    pool = Path("/etc/php/8.3/fpm/pool.d") / ("masspanel-" + owner + ".conf")
    socket = "/run/php/masspanel-" + owner + ".sock"
    group_name = grp.getgrgid(account.pw_gid).gr_name
    pool_existed = pool.exists()
    old_pool = pool.read_text(encoding="utf-8") if pool_existed else None
    index = webroot / "index.html"
    if not index.is_file() or index.is_symlink(): fail("A fresh website placeholder is required before installation.")
    sql = (
        f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
        f"CREATE USER `{db_user}`@`localhost` IDENTIFIED BY '{db_password}';"
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO `{db_user}`@`localhost`;FLUSH PRIVILEGES;"
    )
    try:
        pool.write_text(f'''[{owner}]
user = {owner}
group = {group_name}
listen = {socket}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
php_admin_value[upload_tmp_dir] = /home/{owner}/tmp
php_admin_value[session.save_path] = /home/{owner}/tmp
php_admin_value[open_basedir] = /home/{owner}:/tmp:/usr/share/php
''', encoding="utf-8")
        tmp = Path(account.pw_dir) / "tmp"; tmp.mkdir(mode=0o700, exist_ok=True); os.chown(tmp, account.pw_uid, account.pw_gid)
        run(["/usr/bin/systemctl", "reload", "php8.3-fpm"], timeout=40)
        run(["/usr/bin/mariadb"], sql, timeout=40)
        index.unlink()
    except BaseException:
        subprocess.run(["/usr/bin/mariadb"], input=f"DROP DATABASE IF EXISTS `{db_name}`;DROP USER IF EXISTS `{db_user}`@`localhost`;", text=True, capture_output=True, timeout=40)
        if pool_existed: pool.write_text(old_pool, encoding="utf-8")
        else: pool.unlink(missing_ok=True)
        subprocess.run(["/usr/bin/systemctl", "reload", "php8.3-fpm"], capture_output=True, timeout=40)
        raise
    try:
        run(["/usr/sbin/runuser", "-u", owner, "--", "/usr/local/bin/wp", "core", "download", "--path=" + str(webroot)], timeout=180)
        run(["/usr/sbin/runuser", "-u", owner, "--", "/usr/local/bin/wp", "config", "create", "--path=" + str(webroot), "--dbname=" + db_name, "--dbuser=" + db_user, "--dbpass=" + db_password, "--dbhost=localhost", "--skip-check"], timeout=60)
        run(["/usr/sbin/runuser", "-u", owner, "--", "/usr/local/bin/wp", "core", "install", "--path=" + str(webroot), "--url=https://" + domain, "--title=" + title, "--admin_user=" + admin_user, "--admin_email=" + admin_email, "--skip-email", "--prompt=admin_password"], admin_password + "\n", timeout=120)
        if presets[application_slug]:
            run(["/usr/sbin/runuser", "-u", owner, "--", "/usr/local/bin/wp", "plugin", "install", presets[application_slug], "--activate", "--path=" + str(webroot)], timeout=180)
        version = run(["/usr/sbin/runuser", "-u", owner, "--", "/usr/local/bin/wp", "core", "version", "--path=" + str(webroot)]).stdout.strip()
        wordpress_sso_install({"owner": owner, "domain": domain})
        grant_panel_access(account, webroot)
        write_domain_config(domain, webroot, "self", False, socket)
        return {"domain": domain, "version": version, "db_name": db_name, "db_user": db_user, "admin_user": admin_user, "ssl_mode": "self"}
    except BaseException:
        subprocess.run(["/usr/bin/mariadb"], input=f"DROP DATABASE IF EXISTS `{db_name}`;DROP USER IF EXISTS `{db_user}`@`localhost`;", text=True, capture_output=True, timeout=40)
        for item in list(webroot.iterdir()):
            if item.is_dir():
                import shutil
                shutil.rmtree(item)
            else:
                item.unlink(missing_ok=True)
        index.write_text("MassPanel website ready.\n", encoding="utf-8")
        os.chown(index, account.pw_uid, account.pw_gid)
        if pool_existed:
            pool.write_text(old_pool, encoding="utf-8")
        else:
            pool.unlink(missing_ok=True)
        subprocess.run(["/usr/bin/systemctl", "reload", "php8.3-fpm"], capture_output=True, timeout=40)
        raise


def application_install(payload):
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    owner = validate_username(payload.get("owner"))
    slug = str(payload.get("application_slug", "")).lower()
    if slug not in {"nextcloud", "joomla"}: fail("Unsupported application.")
    if not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    account, webroot = domain_paths(domain, owner, payload.get("webroot"))
    existing = [item for item in webroot.iterdir() if item.name != "index.html"]
    if existing: fail("The website root is not empty. Back it up or use a fresh domain.")
    admin_user = str(payload.get("admin_user", "")).strip()
    admin_email = str(payload.get("admin_email", "")).strip()
    admin_password = str(payload.get("admin_password", ""))
    title = str(payload.get("title", domain)).strip()[:120]
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{3,60}", admin_user): fail("Invalid administrator username.")
    if not valid_email_address(admin_email): fail("Invalid administrator email.")
    if len(admin_password) < 12 or len(admin_password) > 256: fail("Administrator password must contain 12-256 characters.")
    token = hashlib.sha256(domain.encode()).hexdigest()[:12]
    db_name, db_user, db_password = "mp_" + token, "mpu_" + token, secrets.token_urlsafe(30)
    pool = Path("/etc/php/8.3/fpm/pool.d") / ("masspanel-" + owner + ".conf")
    socket = "/run/php/masspanel-" + owner + ".sock"
    group_name = grp.getgrgid(account.pw_gid).gr_name
    pool_existed = pool.exists(); old_pool = pool.read_text(encoding="utf-8") if pool_existed else None
    index = webroot / "index.html"
    if not index.is_file() or index.is_symlink(): fail("A fresh website placeholder is required before installation.")
    sql = f"CREATE DATABASE `{db_name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;CREATE USER `{db_user}`@`localhost` IDENTIFIED BY '{db_password}';GRANT ALL PRIVILEGES ON `{db_name}`.* TO `{db_user}`@`localhost`;FLUSH PRIVILEGES;"
    try:
        pool.write_text(f'''[{owner}]
user = {owner}
group = {group_name}
listen = {socket}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 6
pm.process_idle_timeout = 10s
php_admin_value[memory_limit] = 512M
php_admin_value[upload_max_filesize] = 512M
php_admin_value[post_max_size] = 512M
php_admin_value[upload_tmp_dir] = /home/{owner}/tmp
php_admin_value[session.save_path] = /home/{owner}/tmp
php_admin_value[open_basedir] = /home/{owner}:/tmp:/usr/share/php
''', encoding="utf-8")
        tmp = Path(account.pw_dir) / "tmp"; tmp.mkdir(mode=0o700, exist_ok=True); os.chown(tmp, account.pw_uid, account.pw_gid)
        run(["/usr/bin/systemctl", "reload", "php8.3-fpm"], timeout=40)
        run(["/usr/bin/mariadb"], sql, timeout=40)
        index.unlink()
        with tempfile.TemporaryDirectory(prefix="masspanel-app-") as temp_dir:
            temp = Path(temp_dir)
            if slug == "nextcloud":
                archive = temp / "nextcloud.tar.bz2"
                run(["/usr/bin/curl", "--proto", "=https", "--tlsv1.2", "--fail", "--location", "--max-time", "420", "-o", str(archive), "https://download.nextcloud.com/server/releases/latest.tar.bz2"], timeout=450)
                run(["/usr/bin/tar", "-xjf", str(archive), "-C", str(temp), "--no-same-owner"], timeout=240)
                run(["/usr/bin/cp", "-a", str(temp / "nextcloud") + "/.", str(webroot) + "/"], timeout=180)
            else:
                req = urllib.request.Request("https://api.github.com/repos/joomla/joomla-cms/releases/latest", headers={"User-Agent":"MassPanel/1.0","Accept":"application/vnd.github+json"})
                with urllib.request.urlopen(req, timeout=30) as response: release = json.loads(response.read())
                asset = next((item for item in release.get("assets", []) if re.fullmatch(r"Joomla_[0-9.]+-Stable-Full_Package\.tar\.gz", item.get("name", ""))), None)
                if not asset: fail("The current Joomla installation package could not be located.")
                archive = temp / "joomla.tar.gz"
                run(["/usr/bin/curl", "--proto", "=https", "--tlsv1.2", "--fail", "--location", "--max-time", "240", "-o", str(archive), asset["browser_download_url"]], timeout=270)
                run(["/usr/bin/tar", "-xzf", str(archive), "-C", str(webroot), "--no-same-owner"], timeout=180)
        run(["/usr/bin/chown", "-R", f"{owner}:{group_name}", str(webroot)], timeout=180)
        if slug == "nextcloud":
            data_dir = Path(account.pw_dir) / "nextcloud-data" / domain
            data_dir.mkdir(mode=0o750, parents=True, exist_ok=False); os.chown(data_dir, account.pw_uid, account.pw_gid)
            occ = ["/usr/sbin/runuser", "-u", owner, "--", "/usr/bin/php", str(webroot / "occ")]
            run(occ + ["maintenance:install", "--database=mysql", "--database-host=localhost", "--database-name=" + db_name, "--database-user=" + db_user, "--database-pass=" + db_password, "--admin-user=" + admin_user, "--admin-pass=" + admin_password, "--data-dir=" + str(data_dir), "--no-interaction"], timeout=300)
            run(occ + ["config:system:set", "trusted_domains", "1", "--value=" + domain], timeout=60)
            run(occ + ["config:system:set", "overwrite.cli.url", "--value=https://" + domain], timeout=60)
            run(occ + ["config:system:set", "overwriteprotocol", "--value=https"], timeout=60)
            run(occ + ["user:setting", admin_user, "settings", "email", admin_email], timeout=60)
            status = json.loads(run(occ + ["status", "--output=json"], timeout=60).stdout)
            version = status.get("versionstring") or status.get("version") or "installed"
            cron = Path("/etc/cron.d") / ("masspanel-nextcloud-" + token)
            atomic_write_text(cron, f"*/5 * * * * {owner} /usr/bin/php -f {webroot}/cron.php >/dev/null 2>&1\n", 0o644)
        else:
            prefix = "mp" + token[:5] + "_"
            cli = ["/usr/sbin/runuser", "-u", owner, "--", "/usr/bin/php", str(webroot / "installation" / "joomla.php"), "install", "--no-interaction", "--site-name=" + title, "--admin-user=" + title, "--admin-username=" + admin_user, "--admin-password=" + admin_password, "--admin-email=" + admin_email, "--db-type=mysqli", "--db-host=localhost", "--db-user=" + db_user, "--db-pass=" + db_password, "--db-name=" + db_name, "--db-prefix=" + prefix]
            run(cli, timeout=300)
            manifest = (webroot / "administrator" / "manifests" / "files" / "joomla.xml").read_text(encoding="utf-8", errors="ignore")
            match = re.search(r"<version>\s*([^<]+)", manifest); version = match.group(1).strip() if match else release.get("tag_name", "installed")
        grant_panel_access(account, webroot)
        write_domain_config(domain, webroot, "self", False, socket)
        return {"domain":domain,"version":version,"db_name":db_name,"db_user":db_user,"admin_user":admin_user,"ssl_mode":"self"}
    except BaseException:
        subprocess.run(["/usr/bin/mariadb"], input=f"DROP DATABASE IF EXISTS `{db_name}`;DROP USER IF EXISTS `{db_user}`@`localhost`;", text=True, capture_output=True, timeout=40)
        import shutil
        for item in list(webroot.iterdir()):
            if item.is_dir(): shutil.rmtree(item, ignore_errors=True)
            else: item.unlink(missing_ok=True)
        index.write_text("MassPanel website ready.\n", encoding="utf-8"); os.chown(index, account.pw_uid, account.pw_gid)
        if pool_existed: pool.write_text(old_pool, encoding="utf-8")
        else: pool.unlink(missing_ok=True)
        subprocess.run(["/usr/bin/systemctl", "reload", "php8.3-fpm"], capture_output=True, timeout=40)
        raise


def application_action(payload):
    owner = validate_username(payload.get("owner")); domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    slug, action = str(payload.get("application_slug", "")), str(payload.get("action", ""))
    if slug != "nextcloud" or action not in {"maintenance_on", "maintenance_off", "update"}: fail("This application manages updates from its own administrator area.")
    account, webroot = domain_paths(domain, owner, f"/home/{owner}/domains/{domain}/public_html")
    occ = ["/usr/sbin/runuser", "-u", owner, "--", "/usr/bin/php", str(webroot / "occ")]
    if action == "update": run(occ + ["app:update", "--all", "--no-interaction"], timeout=300)
    else: run(occ + ["maintenance:mode", "--on" if action == "maintenance_on" else "--off", "--no-interaction"], timeout=90)
    status = json.loads(run(occ + ["status", "--output=json"], timeout=60).stdout)
    return {"domain":domain,"version":status.get("versionstring") or status.get("version") or "installed","action":action}


def wordpress_sso_install(payload):
    owner = validate_username(payload.get("owner"))
    domain = str(payload.get("domain", "")).lower().strip().rstrip(".")
    if not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    try: account = pwd.getpwnam(owner)
    except KeyError: fail("Website owner does not exist.")
    home = Path(account.pw_dir).resolve()
    webroot = home / "domains" / domain / "public_html"
    for candidate in (home / "domains", home / "domains" / domain, webroot, webroot / "wp-content"):
        try: metadata = candidate.lstat()
        except FileNotFoundError: fail("WordPress installation was not found.")
        if candidate.is_symlink() or not candidate.is_dir(): fail("Unsafe WordPress path.")
        if metadata.st_uid != account.pw_uid: fail("WordPress path has an unexpected owner.")
    wp_config = webroot / "wp-config.php"
    if not wp_config.is_file() or wp_config.is_symlink(): fail("WordPress installation was not found.")
    plugin_dir = webroot / "wp-content" / "mu-plugins"
    if plugin_dir.exists() and (plugin_dir.is_symlink() or not plugin_dir.is_dir()): fail("Unsafe WordPress plugin path.")
    plugin_dir.mkdir(mode=0o755, exist_ok=True)
    os.chown(plugin_dir, account.pw_uid, account.pw_gid)
    content = r'''<?php
/* Plugin Name: MassPanel Secure Administrator Access */
if (!defined('ABSPATH')) { exit; }
add_action('init', function () {
    if (!isset($_GET['masspanel_impersonate']) || $_GET['masspanel_impersonate'] !== '1') { return; }
    nocache_headers();
    header('Referrer-Policy: no-referrer');
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { status_header(405); exit('POST required.'); }
    $token = isset($_POST['token']) ? sanitize_text_field(wp_unslash($_POST['token'])) : '';
    if ($token === '' || strlen($token) > 256) { status_header(400); exit('Invalid handoff.'); }
    $response = wp_remote_post('http://127.0.0.1:8100/api/apps/impersonation/exchange', array(
        'timeout' => 10,
        'headers' => array('Content-Type' => 'application/json'),
        'body' => wp_json_encode(array('token' => $token, 'domain' => strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST)))),
    ));
    if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) { status_header(403); exit('This administrator handoff is invalid or expired.'); }
    $data = json_decode(wp_remote_retrieve_body($response), true);
    $user = isset($data['username']) ? get_user_by('login', $data['username']) : false;
    if (!$user || !user_can($user, 'manage_options')) { status_header(403); exit('WordPress administrator was not found.'); }
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID, false, is_ssl());
    wp_safe_redirect(admin_url());
    exit;
}, 0);
'''
    dir_fd = os.open(plugin_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp_name = ".masspanel-impersonation-" + secrets.token_hex(8)
    try:
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dir_fd)
        with os.fdopen(fd, "w", encoding="utf-8") as stream: stream.write(content)
        os.chown(temp_name, account.pw_uid, account.pw_gid, dir_fd=dir_fd, follow_symlinks=False)
        os.rename(temp_name, "masspanel-impersonation.php", src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    finally:
        try: os.unlink(temp_name, dir_fd=dir_fd)
        except FileNotFoundError: pass
        os.close(dir_fd)
    plugin_dir.chmod(0o755)
    return {"domain": domain, "installed": True}


def wordpress_action(payload):
    owner = validate_username(payload.get("owner")); domain = payload.get("domain", "")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain): fail("Invalid domain name.")
    try: account = pwd.getpwnam(owner)
    except KeyError: fail("Website owner does not exist.")
    path = Path(account.pw_dir) / "domains" / domain / "public_html"
    action = payload.get("action")
    base = ["/usr/sbin/runuser", "-u", owner, "--", "/usr/local/bin/wp", "--path=" + str(path)]
    if action == "update":
        run(base + ["core", "update"], timeout=180); run(base + ["plugin", "update", "--all"], timeout=180); run(base + ["theme", "update", "--all"], timeout=180)
    elif action == "maintenance_on": run(base + ["maintenance-mode", "activate"], timeout=60)
    elif action == "maintenance_off": run(base + ["maintenance-mode", "deactivate"], timeout=60)
    else: fail("Unsupported WordPress action.")
    version = run(base + ["core", "version"]).stdout.strip()
    return {"domain": domain, "version": version, "action": action}


def mail_quarantine_release(payload):
    root = Path("/var/lib/masspanel/mail-quarantine").resolve()
    path = Path(str(payload.get("path") or "")).resolve()
    if path.parent != root or path.suffix != ".eml" or not path.is_file(): fail("Quarantined message is unavailable.")
    recipients = payload.get("recipients")
    if not isinstance(recipients, list): fail("Invalid quarantine recipients.")
    recipients = list(dict.fromkeys(str(item).lower().strip() for item in recipients if valid_email_address(item)))
    if not recipients or len(recipients) > 100: fail("The quarantined message has no valid recipients.")
    if path.stat().st_size > 64 * 1024 * 1024: fail("Quarantined message is too large.")
    raw = path.read_bytes()
    try:
        with smtplib.SMTP("127.0.0.1", 10026, timeout=30) as smtp:
            refused = smtp.sendmail("", recipients, raw)
    except (OSError, smtplib.SMTPException) as exc:
        fail(f"Could not release the message: {exc}")
    if refused: fail("The mail server refused one or more recipients.")
    return {"released": True, "recipients": recipients}

def updater_control(payload):
    action = str(payload.get("action", "status"))
    updater = "/usr/local/sbin/masspanel-update"
    status_path = Path("/var/lib/masspanel-updater/status.json")
    backups_path = Path("/var/lib/masspanel-updater/backups")
    if action in {"status", "check"}:
        manifest = None
        if action == "check":
            checked = subprocess.run([updater, "check"], text=True, capture_output=True, timeout=45, check=False)
            if checked.returncode: fail((checked.stderr or checked.stdout or "Update check failed.").strip())
            try: manifest = json.loads(checked.stdout)
            except json.JSONDecodeError: fail("The update server returned an invalid manifest.")
        try: status = json.loads(status_path.read_text()) if status_path.is_file() else {"state":"never_checked"}
        except (OSError, json.JSONDecodeError): status = {"state":"unknown", "message":"Updater status could not be read."}
        backups = []
        if backups_path.is_dir():
            for item in sorted(backups_path.glob("*.tar.gz"), key=lambda entry: entry.stat().st_mtime, reverse=True):
                backups.append({"name":item.name,"size":item.stat().st_size,"created_at":dt.datetime.fromtimestamp(item.stat().st_mtime, dt.timezone.utc).replace(microsecond=0).isoformat()})
        lock_path = Path("/var/lib/masspanel/runtime.lock.json")
        try: package_lock = json.loads(lock_path.read_text()) if lock_path.is_file() else {}
        except (OSError, json.JSONDecodeError): package_lock = {}
        return {"status":status,"manifest":manifest,"backups":backups,"package_lock":package_lock}
    if action not in {"apply", "rollback"}: fail("Unsupported updater action.")
    command = [updater, action]
    if action == "rollback":
        snapshot = Path(str(payload.get("snapshot", ""))).name
        if not snapshot or not re.fullmatch(r"[A-Za-z0-9._-]+\.tar\.gz", snapshot): fail("Choose a valid rollback snapshot.")
        command.append(snapshot)
    unit = f"masspanel-update-{action}-{int(time.time())}"
    started = subprocess.run(["/usr/bin/systemd-run","--unit",unit,"--collect","--property=Type=oneshot",*command], text=True, capture_output=True, timeout=20, check=False)
    if started.returncode: fail((started.stderr or started.stdout or "Could not start the updater.").strip())
    return {"started":True,"unit":unit,"action":action}

def main():
    if os.geteuid() != 0: fail("Privileged helper must run as root.")
    payload = read_helper_payload(sys.stdin.buffer)
    operation = payload.get("operation")
    if operation == "list": result = {"users": list_users()}
    elif operation == "create": result = create_user(payload)
    elif operation == "remove_new": result = remove_new(payload)
    elif operation == "remove": result = remove_new(payload)
    elif operation == "domain_create": result = create_domain(payload)
    elif operation == "domain_delete": result = domain_delete(payload)
    elif operation == "domain_config": result = configure_domain(payload)
    elif operation == "dns_sync": result = sync_dns(payload)
    elif operation == "email_hash": result = email_hash(payload)
    elif operation == "email_sync": result = sync_email(payload)
    elif operation == "grommunio_domain_create": result = grommunio_domain_create(payload)
    elif operation == "grommunio_domain_users": result = grommunio_domain_users(payload)
    elif operation == "grommunio_domain_delete": result = grommunio_domain_delete(payload)
    elif operation == "grommunio_email_create": result = grommunio_email_create(payload)
    elif operation == "grommunio_email_update": result = grommunio_email_update(payload)
    elif operation == "grommunio_email_delete": result = grommunio_email_delete(payload)
    elif operation == "grommunio_account_access": result = grommunio_account_access(payload)
    elif operation == "grommunio_impersonation_credentials": result = grommunio_impersonation_credentials(payload)
    elif operation == "grommunio_system_mailbox_configure": result = grommunio_system_mailbox_configure(payload)
    elif operation == "grommunio_system_mailbox_credentials": result = grommunio_system_mailbox_credentials(payload)
    elif operation == "firewall_trust_admin_ip": result = firewall_trust_admin_ip(payload)
    elif operation == "firewall_status": result = firewall_status(payload)
    elif operation == "firewall_block": result = firewall_address(payload)
    elif operation == "firewall_unblock": result = firewall_address(payload, True)
    elif operation == "firewall_ignore": result = firewall_ignore(payload)
    elif operation == "firewall_unignore": result = firewall_ignore(payload, True)
    elif operation == "database_browse": result = database_browse(payload)
    elif operation == "database_update_row": result = database_update_row(payload)
    elif operation == "database_tool_access": result = database_tool_access(payload)
    elif operation == "hosting_storage_usage": result = hosting_storage_usage(payload)
    elif operation == "filebrowser_workspace_sync": result = filebrowser_workspace_sync(payload)
    elif operation == "mail_quarantine_release": result = mail_quarantine_release(payload)
    elif operation == "updater_control": result = updater_control(payload)
    elif operation == "mail_dns_plan": result = mail_dns_plan(payload)
    elif operation == "cloudflare_connect": result = cloudflare_connect(payload)
    elif operation == "cloudflare_status": result = cloudflare_status(payload)
    elif operation == "cloudflare_disconnect": result = cloudflare_disconnect(payload)
    elif operation == "cloudflare_sync": result = cloudflare_sync(payload)
    elif operation == "mail_certificate": result = mail_certificate(payload)
    elif operation == "panel_certificate": result = panel_certificate(payload)
    elif operation == "storefront_config": result = storefront_config(payload)
    elif operation == "storefront_certificate": result = storefront_certificate(payload)
    elif operation == "domain_certificate_regenerate": result = regenerate_domain_certificate(payload)
    elif operation == "wordpress_install": result = wordpress_install(payload)
    elif operation == "application_install": result = application_install(payload)
    elif operation == "wordpress_sso_install": result = wordpress_sso_install(payload)
    elif operation == "wordpress_action": result = wordpress_action(payload)
    elif operation == "application_action": result = application_action(payload)
    elif operation == "cron_sync": result = cron_sync(payload)
    elif operation == "cron_run": result = cron_run(payload)
    elif operation == "backup_schedule_sync": result = backup_schedule_sync(payload)
    elif operation == "service_list": result = service_list()
    elif operation == "service_action": result = service_action(payload)
    elif operation == "php_config": result = php_config(payload)
    elif operation == "website_logs": result = website_logs(payload)
    elif operation == "website_rules_sync": result = website_rules_sync(payload)
    elif operation in {"lock", "unlock", "password"}: result = mutate(payload, operation)
    else: fail("Unsupported operation.")
    print(json.dumps({"ok": True, **result}))

if __name__ == "__main__": main()
