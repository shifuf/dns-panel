#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
import bcrypt
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from modules.provider_catalog import get_all_provider_capabilities, get_provider_capabilities
from modules.two_factor import generate_base32_secret, make_otpauth_url, make_qr_data_url, verify_totp
from modules.cloudflare_api import CloudflareApi, CloudflareApiError
from modules.dnspod_api import DnspodApi, DnspodApiError

# ── Application version ─────────────────────────────────────────
APP_VERSION = "1.3"
UPSTREAM_GITHUB_REPO = os.getenv("UPSTREAM_GITHUB_REPO", "shifuf/dns-panel").strip() or "shifuf/dns-panel"
UPSTREAM_GITHUB_REPO_URL = f"https://github.com/{UPSTREAM_GITHUB_REPO}"
VERSION_CACHE_TTL_SECONDS = 1800
from modules.aliyun_esa_api import (
    AliyunEsaError,
    apply_certificate as esa_apply_certificate,
    check_cname_status as esa_check_cname_status,
    create_record as esa_create_record,
    create_site as esa_create_site,
    delete_record as esa_delete_record,
    delete_site as esa_delete_site,
    get_certificate as esa_get_certificate,
    get_record as esa_get_record,
    list_certificates_by_record as esa_list_certificates_by_record,
    list_instances as esa_list_instances,
    list_records as esa_list_records,
    list_site_tags as esa_list_site_tags,
    list_sites as esa_list_sites,
    update_record as esa_update_record,
    update_site_pause as esa_update_site_pause,
    update_site_tags as esa_update_site_tags,
    verify_site as esa_verify_site,
)
from modules.tencent_ssl_api import TencentSslApi, TencentSslApiError
from migrate import migrate as run_db_migrations
from modules.route_handlers import attach_route_methods

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = (BASE_DIR / "db" / "database.db").resolve()
PORT = int(os.getenv("PORT", "4001"))
LEGACY = os.getenv("LEGACY_NODE_BASE_URL", "http://127.0.0.1:4101").rstrip("/")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-jwt-secret-key-min-32-char-123456")
CJWT_EXPIRES_IN = os.getenv("JWT_EXPIRES_IN", "7d")
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "http://localhost:5174")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "please-change-to-32-char-key!!")


def normalize_db_path(raw_path: str) -> Path:
    p = Path(raw_path)
    return p if p.is_absolute() else (BASE_DIR / p).resolve()


DEFAULT_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

MAX_SYNC, MAX_RULES, MAX_EVENTS, MAX_VIEWS, MAX_TAG_ROWS, MAX_TAGS = 300, 100, 500, 100, 5000, 20
VALID_SCOPE = {"all", "provider", "credential"}
VALID_SYNC_STATUS = {"pending", "running", "success", "failed"}
VALID_ALERT_STATUS = {"open", "acknowledged", "resolved"}
VALID_ALERT_LEVEL = {"critical", "high", "medium", "low"}
VALID_RULE_TYPE = {"status_issue", "expiry_warning", "sync_failure"}
VALID_CH = {"webhook", "email", "inapp"}
PROVIDER_NAMES = {
    "cloudflare": "Cloudflare",
    "aliyun": "阿里云 DNS",
    "dnspod": "DNSPod",
    "dnspod_token": "DNSPod",
    "huawei": "华为云 DNS",
    "jdcloud": "京东云 DNS",
    "baidu": "百度云 DNS",
    "huoshan": "火山引擎 DNS",
    "namesilo": "NameSilo",
    "spaceship": "Spaceship",
    "west": "西部数码",
    "powerdns": "PowerDNS",
    "dnsla": "DNSLA",
    "tencent_ssl": "腾讯云 SSL",
}
DEFAULT_LOG_RETENTION_DAYS = 90
VALID_BACKUP_SCOPES = {"dns", "ssl"}


def resolve_db() -> Path:
    url = os.getenv("DATABASE_URL", f"file:{DEFAULT_DB_PATH.as_posix()}").strip().strip('"')
    if url.startswith("file:"):
        return normalize_db_path(url[5:])
    return DEFAULT_DB_PATH


DB = resolve_db()
DB.parent.mkdir(parents=True, exist_ok=True)


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().isoformat().replace("+00:00", "Z")


def parse_dt(v: Any) -> datetime | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        d = datetime.fromisoformat(s)
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc)
    except Exception:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except Exception:
                continue
    return None


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(str(DB))
    c.row_factory = sqlite3.Row
    return c


def table_exists(name: str) -> bool:
    with conn() as c:
        row = c.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1",
            (name,),
        ).fetchone()
    return row is not None


def column_exists(table: str, column: str) -> bool:
    try:
        with conn() as c:
            rows = c.execute(f"PRAGMA table_info({table})").fetchall()
        return any(str(row["name"]) == column for row in rows)
    except Exception:
        return False


def has_any_users() -> bool:
    if not table_exists("users"):
        return False
    try:
        with conn() as c:
            row = c.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        return bool(row and int(row["c"]) > 0)
    except Exception:
        return False


def get_user_role(user_id: int) -> str:
    if user_id <= 0 or not table_exists("users") or not column_exists("users", "role"):
        return "admin"
    try:
        with conn() as c:
            row = c.execute("SELECT role FROM users WHERE id = ? LIMIT 1", (user_id,)).fetchone()
        role = str(row["role"] or "").strip().lower() if row else ""
        return role or "admin"
    except Exception:
        return "admin"


def is_admin_user_id(user_id: int) -> bool:
    return get_user_role(user_id) == "admin"


def get_system_setting(key: str, default: str = "") -> str:
    try:
        with conn() as c:
            row = c.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
            return str(row["value"]) if row else default
    except Exception:
        return default


def set_system_setting(key: str, value: str) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO system_settings (key, value, updatedAt) VALUES (?, ?, CURRENT_TIMESTAMP) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updatedAt = CURRENT_TIMESTAMP",
            (key, value),
        )
        c.commit()


def get_log_retention_days() -> int:
    return p_int(get_system_setting("log_retention_days", str(DEFAULT_LOG_RETENTION_DAYS)), DEFAULT_LOG_RETENTION_DAYS, 36500)


def cleanup_logs_older_than(retention_days: int | None = None) -> int:
    if not table_exists("logs"):
        return 0
    retention = p_int(retention_days if retention_days is not None else get_log_retention_days(), DEFAULT_LOG_RETENTION_DAYS, 36500)
    cutoff = (now() - timedelta(days=retention))
    cutoff_str = cutoff.isoformat().replace("+00:00", "Z")
    with conn() as c:
        row = c.execute(
            "SELECT COUNT(*) AS c FROM logs WHERE datetime(timestamp) < datetime(?)",
            (cutoff_str,),
        ).fetchone()
        count = int(row["c"] or 0) if row else 0
        if count > 0:
            c.execute("DELETE FROM logs WHERE datetime(timestamp) < datetime(?)", (cutoff_str,))
            c.commit()
    return count


def setup_status_dict() -> Dict[str, Any]:
    complete = has_any_users()
    stored = get_system_setting("setup_complete", "1" if complete else "0")
    return {
        "setupComplete": complete or stored == "1",
        "hasUsers": complete,
        "logRetentionDays": get_log_retention_days(),
        "registrationOpen": False,
    }


def export_backup_payload(user_id: int, scopes: List[str]) -> Dict[str, Any]:
    selected = [scope for scope in scopes if scope in VALID_BACKUP_SCOPES]
    if not selected:
        raise ValueError("至少选择一个备份范围")

    payload: Dict[str, Any] = {
        "version": 1,
        "exportedAt": now_iso(),
        "scopes": selected,
        "data": {},
    }
    with conn() as c:
        if "dns" in selected:
            rows = c.execute(
                """
                SELECT id, name, provider, secrets, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials
                WHERE userId = ? AND provider != 'tencent_ssl'
                ORDER BY createdAt ASC, id ASC
                """,
                (user_id,),
            ).fetchall()
            payload["data"]["dns"] = {
                "credentials": [
                    {
                        "id": int(row["id"]),
                        "name": row["name"],
                        "provider": row["provider"],
                        "accountId": row["accountId"],
                        "isDefault": bool(row["isDefault"]),
                        "secrets": safe_json_loads(decrypt_text(row["secrets"])) or {},
                        "createdAt": row["createdAt"],
                        "updatedAt": row["updatedAt"],
                    }
                    for row in rows
                ]
            }

        if "ssl" in selected:
            cred_rows = c.execute(
                """
                SELECT id, name, provider, secrets, accountId, isDefault, createdAt, updatedAt
                FROM dns_credentials
                WHERE userId = ? AND provider = 'tencent_ssl'
                ORDER BY createdAt ASC, id ASC
                """,
                (user_id,),
            ).fetchall()
            cert_rows = c.execute(
                """
                SELECT id, credentialId, provider, remoteCertId, domain, san, certType, productName,
                       status, statusMsg, issuer, notBefore, notAfter, dvAuthMethod, isUploaded,
                       remoteCreatedAt, syncedAt, createdAt, updatedAt
                FROM ssl_certificates
                WHERE userId = ?
                ORDER BY createdAt ASC, id ASC
                """,
                (user_id,),
            ).fetchall() if table_exists("ssl_certificates") else []
            payload["data"]["ssl"] = {
                "credentials": [
                    {
                        "id": int(row["id"]),
                        "name": row["name"],
                        "provider": row["provider"],
                        "accountId": row["accountId"],
                        "isDefault": bool(row["isDefault"]),
                        "secrets": safe_json_loads(decrypt_text(row["secrets"])) or {},
                        "createdAt": row["createdAt"],
                        "updatedAt": row["updatedAt"],
                    }
                    for row in cred_rows
                ],
                "certificates": [
                    {
                        "id": int(row["id"]),
                        "credentialId": int(row["credentialId"]),
                        "provider": row["provider"],
                        "remoteCertId": row["remoteCertId"],
                        "domain": row["domain"],
                        "san": row["san"],
                        "certType": row["certType"],
                        "productName": row["productName"],
                        "status": row["status"],
                        "statusMsg": row["statusMsg"],
                        "issuer": row["issuer"],
                        "notBefore": row["notBefore"],
                        "notAfter": row["notAfter"],
                        "dvAuthMethod": row["dvAuthMethod"],
                        "isUploaded": bool(row["isUploaded"]),
                        "remoteCreatedAt": row["remoteCreatedAt"],
                        "syncedAt": row["syncedAt"],
                        "createdAt": row["createdAt"],
                        "updatedAt": row["updatedAt"],
                    }
                    for row in cert_rows
                ],
            }

    return payload


def restore_backup_payload(user_id: int, payload: Dict[str, Any], scopes: List[str], overwrite: bool) -> Dict[str, int]:
    if not isinstance(payload, dict):
        raise ValueError("备份文件格式无效")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise ValueError("备份文件缺少 data 字段")

    selected = [scope for scope in scopes if scope in VALID_BACKUP_SCOPES]
    if not selected:
        raise ValueError("至少选择一个恢复范围")

    result = {
        "dnsCredentials": 0,
        "sslCredentials": 0,
        "sslCertificates": 0,
    }

    with conn() as c:
        if "dns" in selected:
            dns_block = data.get("dns")
            if isinstance(dns_block, dict):
                cred_items = dns_block.get("credentials")
                if isinstance(cred_items, list):
                    if overwrite:
                        c.execute("DELETE FROM dns_credentials WHERE userId = ? AND provider != 'tencent_ssl'", (user_id,))
                    for item in cred_items:
                        if not isinstance(item, dict):
                            continue
                        name = str(item.get("name") or "").strip()
                        provider = str(item.get("provider") or "").strip()
                        secrets = item.get("secrets")
                        if not name or not provider or not isinstance(secrets, dict):
                            continue
                        c.execute(
                            """
                            INSERT INTO dns_credentials (userId, name, provider, secrets, accountId, isDefault, createdAt, updatedAt)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                user_id,
                                name,
                                provider,
                                encrypt_text(json.dumps(secrets, ensure_ascii=False)),
                                str(item.get("accountId") or "").strip() or None,
                                1 if bool(item.get("isDefault")) else 0,
                                str(item.get("createdAt") or now_iso()),
                                str(item.get("updatedAt") or now_iso()),
                            ),
                        )
                        result["dnsCredentials"] += 1

        if "ssl" in selected:
            ssl_block = data.get("ssl")
            credential_id_map: Dict[int, int] = {}
            if isinstance(ssl_block, dict):
                cred_items = ssl_block.get("credentials")
                cert_items = ssl_block.get("certificates")

                if overwrite:
                    c.execute("DELETE FROM ssl_certificates WHERE userId = ?", (user_id,))
                    c.execute("DELETE FROM dns_credentials WHERE userId = ? AND provider = 'tencent_ssl'", (user_id,))

                if isinstance(cred_items, list):
                    for item in cred_items:
                        if not isinstance(item, dict):
                            continue
                        name = str(item.get("name") or "").strip()
                        provider = str(item.get("provider") or "tencent_ssl").strip() or "tencent_ssl"
                        secrets = item.get("secrets")
                        if not name or not isinstance(secrets, dict):
                            continue
                        cur = c.execute(
                            """
                            INSERT INTO dns_credentials (userId, name, provider, secrets, accountId, isDefault, createdAt, updatedAt)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                user_id,
                                name,
                                provider,
                                encrypt_text(json.dumps(secrets, ensure_ascii=False)),
                                str(item.get("accountId") or "").strip() or None,
                                1 if bool(item.get("isDefault")) else 0,
                                str(item.get("createdAt") or now_iso()),
                                str(item.get("updatedAt") or now_iso()),
                            ),
                        )
                        old_id = int(item.get("id") or 0)
                        if old_id > 0:
                            credential_id_map[old_id] = int(cur.lastrowid)
                        result["sslCredentials"] += 1

                if isinstance(cert_items, list) and table_exists("ssl_certificates"):
                    for item in cert_items:
                        if not isinstance(item, dict):
                            continue
                        remote_cert_id = str(item.get("remoteCertId") or "").strip()
                        old_cred_id = int(item.get("credentialId") or 0)
                        new_cred_id = credential_id_map.get(old_cred_id)
                        if not remote_cert_id or not new_cred_id:
                            continue
                        c.execute(
                            """
                            INSERT INTO ssl_certificates (
                              userId, credentialId, provider, remoteCertId, domain, san, certType, productName,
                              status, statusMsg, issuer, notBefore, notAfter, dvAuthMethod, isUploaded,
                              remoteCreatedAt, syncedAt, createdAt, updatedAt
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                user_id,
                                new_cred_id,
                                str(item.get("provider") or "tencent_ssl").strip() or "tencent_ssl",
                                remote_cert_id,
                                str(item.get("domain") or "").strip(),
                                item.get("san"),
                                str(item.get("certType") or ""),
                                str(item.get("productName") or ""),
                                str(item.get("status") or "unknown"),
                                str(item.get("statusMsg") or ""),
                                str(item.get("issuer") or ""),
                                item.get("notBefore"),
                                item.get("notAfter"),
                                str(item.get("dvAuthMethod") or ""),
                                1 if bool(item.get("isUploaded")) else 0,
                                item.get("remoteCreatedAt"),
                                item.get("syncedAt"),
                                str(item.get("createdAt") or now_iso()),
                                str(item.get("updatedAt") or now_iso()),
                            ),
                        )
                        result["sslCertificates"] += 1

        c.commit()

    return result


def init_db() -> None:
    run_db_migrations(DB)
    with conn() as c:
        if table_exists("users"):
            cols = {str(row["name"]) for row in c.execute("PRAGMA table_info(users)").fetchall()}
            if "role" not in cols:
                c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'admin'")
            c.execute("UPDATE users SET role = 'admin' WHERE role IS NULL OR TRIM(role) = ''")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              key TEXT UNIQUE NOT NULL,
              value TEXT NOT NULL,
              expiresAt DATETIME NOT NULL,
              createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS ssl_certificates (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              userId INTEGER NOT NULL,
              credentialId INTEGER NOT NULL,
              provider TEXT NOT NULL DEFAULT 'tencent_ssl',
              remoteCertId TEXT NOT NULL,
              domain TEXT NOT NULL DEFAULT '',
              san TEXT,
              certType TEXT DEFAULT '',
              productName TEXT DEFAULT '',
              status TEXT NOT NULL DEFAULT 'applying',
              statusMsg TEXT DEFAULT '',
              issuer TEXT DEFAULT '',
              notBefore TEXT,
              notAfter TEXT,
              dvAuthMethod TEXT DEFAULT '',
              isUploaded INTEGER NOT NULL DEFAULT 0,
              remoteCreatedAt TEXT,
              syncedAt TEXT,
              createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
              updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(userId, provider, remoteCertId)
            )
            """
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_ssl_certs_user ON ssl_certificates(userId)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ssl_certs_cred ON ssl_certificates(credentialId)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_ssl_certs_status ON ssl_certificates(status)")
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS system_settings (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL,
              updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        defaults = {
            "registration_open": "0",
            "log_retention_days": str(DEFAULT_LOG_RETENTION_DAYS),
            "setup_complete": "1" if has_any_users() else "0",
        }
        for key, value in defaults.items():
            c.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)", (key, value))
        c.execute(
            "UPDATE system_settings SET value = ?, updatedAt = CURRENT_TIMESTAMP WHERE key = 'setup_complete'",
            ("1" if has_any_users() else "0",),
        )
        c.commit()
    cleanup_logs_older_than(get_log_retention_days())


def ckey(uid: int, scope: str) -> str:
    return f"py-dashboard:{scope}:user:{uid}"


def read_state(uid: int, scope: str, fallback: Any) -> Any:
    with conn() as c:
        row = c.execute("SELECT value, expiresAt FROM cache WHERE key = ?", (ckey(uid, scope),)).fetchone()
    if not row:
        return fallback
    exp = parse_dt(row["expiresAt"])
    if not exp or exp <= now():
        return fallback
    try:
        return json.loads(row["value"])
    except Exception:
        return fallback


def write_state(uid: int, scope: str, value: Any) -> None:
    exp = (now() + timedelta(days=3650)).isoformat().replace("+00:00", "Z")
    created = now_iso()
    with conn() as c:
        c.execute(
            """
            INSERT INTO cache (key, value, expiresAt, createdAt) VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, expiresAt = excluded.expiresAt
            """,
            (ckey(uid, scope), json.dumps(value, ensure_ascii=False), exp, created),
        )
        c.commit()


def make_id(prefix: str) -> str:
    return f"{prefix}-{int(now().timestamp() * 1000)}-{os.urandom(3).hex()}"


def norm_domain(v: Any) -> str:
    s = str(v or "").strip().lower()
    if not s:
        return ""
    if s.startswith("http://"):
        s = s[7:]
    elif s.startswith("https://"):
        s = s[8:]
    if "/" in s:
        s = s.split("/", 1)[0]
    if s.endswith("."):
        s = s[:-1]
    return s


def sanitize_tags(v: Any) -> List[str]:
    if not isinstance(v, list):
        return []
    out, seen = [], set()
    for x in v:
        t = str(x or "").strip()[:50]
        if not t or t.lower() in seen:
            continue
        seen.add(t.lower())
        out.append(t)
        if len(out) >= MAX_TAGS:
            break
    return out


def parse_exp_seconds(value: str, fallback: int) -> int:
    raw = str(value or "").strip().lower()
    if not raw:
        return fallback
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", raw)
    if not m:
        return fallback
    n = int(m.group(1))
    unit = m.group(2) or "s"
    mul = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 1)
    return max(1, n * mul)


JWT_EXPIRES_SECONDS = parse_exp_seconds(CJWT_EXPIRES_IN, 7 * 86400)
TEMP_2FA_EXPIRES_SECONDS = 5 * 60


def pad_key_32(text: str) -> bytes:
    return str(text or "").ljust(32, "0")[:32].encode("utf-8")


def encrypt_text(plain: str) -> str:
    raw = str(plain or "").encode("utf-8")
    iv = os.urandom(16)
    key = pad_key_32(ENCRYPTION_KEY)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(raw) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    enc = encryptor.update(padded) + encryptor.finalize()
    return f"{iv.hex()}:{enc.hex()}"


def decrypt_text(cipher_text: str | None) -> str:
    if not cipher_text:
        return ""
    parts = str(cipher_text).split(":")
    if len(parts) < 2:
        return ""
    iv = bytes.fromhex(parts[0])
    enc = bytes.fromhex(":".join(parts[1:]))
    key = pad_key_32(ENCRYPTION_KEY)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    dec_padded = decryptor.update(enc) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    dec = unpadder.update(dec_padded) + unpadder.finalize()
    return dec.decode("utf-8")


def sign_access_token(payload: Dict[str, Any], expires_seconds: int = JWT_EXPIRES_SECONDS) -> str:
    now_ts = int(now().timestamp())
    body = dict(payload)
    body["iat"] = now_ts
    body["exp"] = now_ts + int(expires_seconds)
    return pyjwt.encode(body, JWT_SECRET, algorithm="HS256")


def password_is_strong(password: str) -> bool:
    if len(password) < 8:
        return False
    has_lower = re.search(r"[a-z]", password) is not None
    has_upper = re.search(r"[A-Z]", password) is not None
    has_digit = re.search(r"\d", password) is not None
    return has_lower and has_upper and has_digit


def normalize_ip(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if "," in text:
        text = text.split(",", 1)[0].strip()
    return text or None


def first_or_none(query: Dict[str, List[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    return values[0]


def safe_json_loads(text: Any) -> Any:
    if not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def read_cache_json(key: str) -> Any:
    if not table_exists("cache"):
        return None
    try:
        with conn() as c:
            row = c.execute("SELECT value, expiresAt FROM cache WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        exp = parse_dt(row["expiresAt"])
        if not exp or exp <= now():
            return None
        return safe_json_loads(row["value"])
    except Exception:
        return None


def write_cache_json(key: str, value: Any, ttl_seconds: int) -> None:
    if not table_exists("cache"):
        return
    with conn() as c:
        c.execute(
            """
            INSERT INTO cache (key, value, expiresAt, createdAt)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, expiresAt = excluded.expiresAt
            """,
            (
                key,
                json.dumps(value, ensure_ascii=False),
                (now() + timedelta(seconds=ttl_seconds)).isoformat().replace("+00:00", "Z"),
                now_iso(),
            ),
        )
        c.commit()


def _fetch_github_version_payload(repo: str) -> Dict[str, Any]:
    encoded_repo = urllib.parse.quote(repo, safe="/")
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "dns-panel-python/1.0",
    }
    sources = [
        (
            "github-release",
            f"https://api.github.com/repos/{encoded_repo}/releases/latest",
            lambda payload: str(payload.get("tag_name") or payload.get("name") or "").strip() if isinstance(payload, dict) else "",
        ),
        (
            "github-tag",
            f"https://api.github.com/repos/{encoded_repo}/tags?per_page=1",
            lambda payload: str(payload[0].get("name") or "").strip() if isinstance(payload, list) and payload else "",
        ),
    ]
    last_error = ""
    for source, url, reader in sources:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            version = reader(payload)
            if version:
                return {
                    "version": version,
                    "source": source,
                    "repo": UPSTREAM_GITHUB_REPO_URL,
                    "checkedAt": now_iso(),
                }
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue
            last_error = f"http {exc.code}"
        except Exception as exc:
            last_error = str(exc)
    fallback_payload: Dict[str, Any] = {
        "version": APP_VERSION,
        "source": "local-fallback",
        "repo": UPSTREAM_GITHUB_REPO_URL,
        "checkedAt": now_iso(),
    }
    if last_error:
        fallback_payload["error"] = last_error
    return fallback_payload


def get_public_version_payload() -> Dict[str, Any]:
    cache_key = f"publicVersion:{UPSTREAM_GITHUB_REPO}"
    cached = read_cache_json(cache_key)
    if isinstance(cached, dict) and str(cached.get("version") or "").strip():
        return cached
    payload = _fetch_github_version_payload(UPSTREAM_GITHUB_REPO)
    write_cache_json(cache_key, payload, VERSION_CACHE_TTL_SECONDS if payload.get("source") != "local-fallback" else 300)
    return payload


def user_public_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"] if "role" in row.keys() and row["role"] else "admin",
        "cfAccountId": row["cfAccountId"],
        "twoFactorEnabled": bool(row["twoFactorEnabled"]) if row["twoFactorEnabled"] is not None else False,
        "domainExpiryDisplayMode": row["domainExpiryDisplayMode"],
        "domainExpiryThresholdDays": row["domainExpiryThresholdDays"],
        "domainExpiryNotifyEnabled": bool(row["domainExpiryNotifyEnabled"]) if row["domainExpiryNotifyEnabled"] is not None else False,
        "domainExpiryNotifyWebhookUrl": row["domainExpiryNotifyWebhookUrl"],
        "domainExpiryNotifyEmailEnabled": bool(row["domainExpiryNotifyEmailEnabled"]) if row["domainExpiryNotifyEmailEnabled"] is not None else False,
        "domainExpiryNotifyEmailTo": row["domainExpiryNotifyEmailTo"],
        "smtpHost": row["smtpHost"],
        "smtpPort": row["smtpPort"],
        "smtpSecure": bool(row["smtpSecure"]) if row["smtpSecure"] is not None else None,
        "smtpUser": row["smtpUser"],
        "smtpFrom": row["smtpFrom"],
        "smtpPassConfigured": bool(row["smtpPass"]),
        "createdAt": row["createdAt"] if "createdAt" in row.keys() else None,
        "updatedAt": row["updatedAt"] if "updatedAt" in row.keys() else None,
    }


def create_log(
    *,
    user_id: int,
    action: str,
    resource_type: str,
    status: str,
    domain: str | None = None,
    record_name: str | None = None,
    record_type: str | None = None,
    old_value: str | None = None,
    new_value: str | None = None,
    error_message: str | None = None,
    ip_address: str | None = None,
) -> None:
    with conn() as c:
        c.execute(
            """
            INSERT INTO logs (
              userId, action, resourceType, domain, recordName, recordType,
              oldValue, newValue, status, errorMessage, ipAddress
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                action,
                resource_type,
                domain,
                record_name,
                record_type,
                old_value,
                new_value,
                status,
                error_message,
                ip_address,
            ),
        )
        c.commit()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode((s + "=" * ((4 - len(s) % 4) % 4)).encode())


def verify_jwt(token: str) -> Dict[str, Any]:
    p = token.split(".")
    if len(p) != 3:
        raise ValueError("invalid jwt")
    hb, pb, sb = p
    header = json.loads(b64u_decode(hb).decode())
    if header.get("alg") != "HS256":
        raise ValueError("unsupported alg")
    sign_in = f"{hb}.{pb}".encode()
    sig = b64u_decode(sb)
    exp = hmac.new(JWT_SECRET.encode(), sign_in, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, exp):
        raise ValueError("bad signature")
    payload = json.loads(b64u_decode(pb).decode())
    if isinstance(payload.get("exp"), (int, float)) and now().timestamp() >= float(payload["exp"]):
        raise ValueError("expired")
    return payload


def dflt_rules() -> List[Dict[str, Any]]:
    t = now_iso()
    return [
        {"id": "rule-status-issue", "name": "异常状态告警", "enabled": True, "type": "status_issue", "threshold": 1, "channels": ["inapp"], "createdAt": t},
        {"id": "rule-expiry-warning", "name": "到期预警告警", "enabled": True, "type": "expiry_warning", "threshold": 7, "channels": ["inapp"], "createdAt": t},
        {"id": "rule-sync-failure", "name": "同步失败告警", "enabled": True, "type": "sync_failure", "threshold": 1, "channels": ["inapp"], "createdAt": t},
    ]


def p_int(v: Any, fallback: int, maxv: int) -> int:
    try:
        n = int(str(v))
        if n <= 0:
            return fallback
        return min(n, maxv)
    except Exception:
        return fallback


def with_default_list(v: Any) -> List[Dict[str, Any]]:
    return v if isinstance(v, list) else []


class H(BaseHTTPRequestHandler):
    server_version = "PyBackendV2/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[py-v2] {self.address_string()} - {fmt % args}")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None: self._handle()
    def do_POST(self) -> None: self._handle()
    def do_PUT(self) -> None: self._handle()
    def do_PATCH(self) -> None: self._handle()
    def do_DELETE(self) -> None: self._handle()

    def _cors(self) -> None:
        ro = self.headers.get("Origin")
        ao = ro if ro == CORS_ORIGIN else CORS_ORIGIN
        self.send_header("Access-Control-Allow-Origin", ao)
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")

    def _json(self, code: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _ok(self, data: Any = None, msg: str = "操作成功", code: int = 200) -> None:
        self._json(code, {"success": True, "message": msg, "data": data})

    def _err(self, msg: str = "操作失败", code: int = 400, err: Any = None) -> None:
        body: Dict[str, Any] = {"success": False, "message": msg}
        if err is not None and os.getenv("NODE_ENV", "development") != "production":
            body["error"] = err
        self._json(code, body)

    def _paged(self, data: List[Any], total: int, page: int, limit: int, msg: str = "查询成功") -> None:
        self._json(
            200,
            {
                "success": True,
                "message": msg,
                "data": data,
                "pagination": {
                    "total": int(total),
                    "page": int(page),
                    "limit": int(limit),
                    "pages": int((total + limit - 1) // limit) if limit > 0 else 0,
                },
            },
        )

    def _binary(self, data: bytes, filename: str, content_type: str = "application/octet-stream") -> None:
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> bytes:
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except Exception:
            n = 0
        return self.rfile.read(n) if n > 0 else b""

    def _json_body(self, raw: bytes) -> Dict[str, Any]:
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            return {}
        return data if isinstance(data, dict) else {}

    def _auth(self) -> Dict[str, Any] | None:
        ah = self.headers.get("Authorization", "")
        if not ah.startswith("Bearer "):
            self._err("未提供认证令牌", 401)
            return None
        tok = ah.split(" ", 1)[1].strip()
        try:
            p = verify_jwt(tok)
        except Exception as e:
            self._err(f"无效或过期的令牌: {e}", 401)
            return None
        if p.get("type") == "2fa_pending":
            self._err("请完成两步验证", 401)
            return None
        return p

    def _handle(self) -> None:
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        b = self._body()

        if path == "/health":
            self._json(200, {"status": "ok", "backend": "python-v2", "legacyProxy": LEGACY, "timestamp": now_iso()})
            return
        if path == "/api/version":
            self._json(200, get_public_version_payload())
            return
        if path == "/api/_python/migration-status":
            self._ok(
                {
                    "nativeRoutes": [
                        "/api/auth/*",
                        "/api/dns-credentials/*",
                        "/api/dns-records/*",
                        "/api/hostnames/*",
                        "/api/tunnels/*",
                        "/api/aliyun-esa/*",
                        "/api/logs/*",
                        "/api/domain-expiry/*",
                        "/api/dashboard/*",
                        "/api/ssl/*",
                    ],
                    "proxyBase": LEGACY,
                    "databasePath": str(DB),
                },
                "Python migration gateway is running",
            )
            return
        if path.startswith("/api/auth"):
            self._auth_routes(path, q, b)
            return
        if path.startswith("/api/logs"):
            self._logs_routes(path, q, b)
            return
        if path.startswith("/api/domain-expiry"):
            self._domain_expiry_routes(path, q, b)
            return
        if path.startswith("/api/dns-credentials"):
            self._dns_credentials_routes(path, q, b)
            return
        if path.startswith("/api/dns-records"):
            self._dns_records_routes(path, q, b)
            return
        if path.startswith("/api/hostnames"):
            self._hostnames_routes(path, q, b)
            return
        if path.startswith("/api/tunnels"):
            self._tunnels_routes(path, q, b)
            return
        if path.startswith("/api/aliyun-esa"):
            self._aliyun_esa_routes(path, q, b)
            return
        if path.startswith("/api/dashboard"):
            self._dashboard(path, q, b)
            return
        if path.startswith("/api/ssl"):
            self._ssl_routes(path, q, b)
            return
        self._proxy(b)

    def _client_ip(self) -> str | None:
        xf = self.headers.get("X-Forwarded-For")
        if xf:
            return normalize_ip(xf)
        xr = self.headers.get("X-Real-IP")
        if xr:
            return normalize_ip(xr)
        if self.client_address and len(self.client_address) > 0:
            return normalize_ip(self.client_address[0])
        return None

    def _provider_supported(self, provider: str) -> bool:
        return get_provider_capabilities(provider) is not None

    def _parse_int(self, value: Any) -> int | None:
        try:
            n = int(str(value))
        except Exception:
            return None
        return n

    def _json_loads_safe(self, text: Any) -> Dict[str, Any]:
        if not isinstance(text, str):
            return {}
        try:
            obj = json.loads(text)
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}

    def _get_credential_row(
        self,
        user_id: int,
        credential_id: str | int | None = None,
        provider: str | None = None,
        default_only: bool = False,
    ) -> sqlite3.Row | None:
        with conn() as c:
            if credential_id is not None and str(credential_id).strip():
                cid = self._parse_int(credential_id)
                if cid is None:
                    return None
                if provider:
                    return c.execute(
                        "SELECT * FROM dns_credentials WHERE id = ? AND userId = ? AND provider = ? LIMIT 1",
                        (cid, user_id, provider),
                    ).fetchone()
                return c.execute(
                    "SELECT * FROM dns_credentials WHERE id = ? AND userId = ? LIMIT 1",
                    (cid, user_id),
                ).fetchone()

            if default_only:
                if provider:
                    return c.execute(
                        "SELECT * FROM dns_credentials WHERE userId = ? AND provider = ? AND isDefault = 1 LIMIT 1",
                        (user_id, provider),
                    ).fetchone()
                return c.execute(
                    "SELECT * FROM dns_credentials WHERE userId = ? AND isDefault = 1 LIMIT 1",
                    (user_id,),
                ).fetchone()

            if provider:
                return c.execute(
                    "SELECT * FROM dns_credentials WHERE userId = ? AND provider = ? ORDER BY isDefault DESC, createdAt ASC LIMIT 1",
                    (user_id, provider),
                ).fetchone()
            return c.execute(
                "SELECT * FROM dns_credentials WHERE userId = ? ORDER BY isDefault DESC, createdAt ASC LIMIT 1",
                (user_id,),
            ).fetchone()

    def _credential_secrets(self, row: sqlite3.Row) -> Dict[str, Any]:
        plain = decrypt_text(row["secrets"])
        parsed = self._json_loads_safe(plain)
        return parsed

    def _ssl_context(self, user_id: int, credential_id: str | int | None) -> Dict[str, Any]:
        """Resolve a credential for Tencent SSL operations.

        Accepts any credential that contains secretId + secretKey
        (both 'tencent_ssl' and 'dnspod' store these fields).
        """
        if not credential_id:
            raise ValueError("缺少 credentialId 参数")
        row = self._get_credential_row(user_id, credential_id)
        if not row:
            raise ValueError("凭证不存在或无权访问")
        provider = str(row["provider"] or "")
        if provider not in ("tencent_ssl", "dnspod"):
            raise ValueError("该凭证不支持 SSL 操作（需要腾讯云凭证）")
        secrets = self._credential_secrets(row)
        sid = str(secrets.get("secretId") or "").strip()
        skey = str(secrets.get("secretKey") or "").strip()
        if not sid or not skey:
            raise ValueError("该凭证缺少 SecretId / SecretKey，无法操作 SSL")
        api = TencentSslApi(sid, skey)
        return {"credential": row, "api": api}

    def _cf_context(self, user_id: int, credential_id: str | None, require_account: bool = False) -> Dict[str, Any]:
        if not credential_id:
            raise ValueError("缺少 credentialId 参数，请先选择一个 Cloudflare 账户")
        row = self._get_credential_row(user_id, credential_id, "cloudflare")
        if not row:
            raise ValueError("凭证不存在或无权访问")
        secrets = self._credential_secrets(row)
        token = str(secrets.get("apiToken") or "").strip()
        if not token:
            raise ValueError("缺少 Cloudflare API Token")
        cf = CloudflareApi(token)
        account_id = str(row["accountId"] or "").strip()
        if require_account and not account_id:
            account_id = cf.get_default_account_id()
            if not account_id:
                raise ValueError("缺少 Cloudflare Account ID，请检查 Token 权限（账户读取或区域读取）")
        return {"credential": row, "cf": cf, "accountId": account_id}

    def _cloudflare_token_for_zone(self, user_id: int, zone_id: str, credential_id: str | None = None) -> Dict[str, Any]:
        # explicit credential first
        if credential_id:
            row = self._get_credential_row(user_id, credential_id, "cloudflare")
            if not row:
                raise ValueError("凭证不存在或无权访问")
            secrets = self._credential_secrets(row)
            token = str(secrets.get("apiToken") or "").strip()
            if not token:
                raise ValueError("缺少 Cloudflare API Token")
            return {"token": token, "credential": row, "cf": CloudflareApi(token)}

        with conn() as c:
            rows = c.execute(
                "SELECT * FROM dns_credentials WHERE userId = ? AND provider = 'cloudflare' ORDER BY isDefault DESC, createdAt ASC",
                (user_id,),
            ).fetchall()
        if not rows:
            raise ValueError("未配置 Cloudflare 凭证")

        for row in rows:
            try:
                secrets = self._credential_secrets(row)
                token = str(secrets.get("apiToken") or "").strip()
                if not token:
                    continue
                cf = CloudflareApi(token)
                cf.get_zone(zone_id)
                return {"token": token, "credential": row, "cf": cf}
            except Exception:
                continue
        raise ValueError("无法访问该域名，请确认选择了正确的 Cloudflare 账户/凭证")

    def _aliyun_auth(self, user_id: int, credential_id: int | None) -> Dict[str, Any]:
        row = self._get_credential_row(user_id, credential_id, "aliyun", default_only=credential_id is None)
        if not row:
            raise ValueError("凭证不存在或无权访问")
        secrets = self._credential_secrets(row)
        access_key_id = str(secrets.get("accessKeyId") or "").strip()
        access_key_secret = str(secrets.get("accessKeySecret") or "").strip()
        if not access_key_id or not access_key_secret:
            raise ValueError("缺少阿里云 AccessKeyId/AccessKeySecret")
        return {"credentialId": row["id"], "accessKeyId": access_key_id, "accessKeySecret": access_key_secret}

    @staticmethod
    def _norm_hostname(value: Any) -> str:
        return str(value or "").strip().rstrip(".").lower()

    @staticmethod
    def _extract_tunnel_config(raw: Any) -> Dict[str, Any] | None:
        value = raw
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception:
                return None
        if not isinstance(value, dict):
            return None
        cfg = value.get("config")
        if isinstance(cfg, dict):
            return cfg
        if "ingress" in value or "originRequest" in value or "warp-routing" in value:
            return value
        return None

    @staticmethod
    def _is_fallback_ingress_rule(rule: Any) -> bool:
        if not isinstance(rule, dict):
            return False
        host = str(rule.get("hostname") or "").strip()
        path = str(rule.get("path") or "").strip()
        return not host and not path

    def _ensure_fallback_rule(self, ingress: Any) -> List[Dict[str, Any]]:
        rules = [x for x in ingress] if isinstance(ingress, list) else []
        rules = [x for x in rules if isinstance(x, dict)]
        if not rules:
            return [{"service": "http_status:404"}]
        if self._is_fallback_ingress_rule(rules[-1]):
            return rules
        return [*rules, {"service": "http_status:404"}]

    def _parse_credential_id(self, value: Any) -> int | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return None
        n = self._parse_int(value)
        if n is None or n <= 0:
            return None
        return n

    def _normalize_region(self, value: Any) -> str | None:
        s = str(value or "").strip()
        if not s:
            return None
        if not re.match(r"^[a-z]{2}-[a-z0-9-]+$", s, re.IGNORECASE):
            return None
        return s

    @staticmethod
    def _parse_bool(v: Any) -> bool:
        s = str(v or "").strip().lower()
        return s in {"1", "true", "yes", "y"}

    @staticmethod
    def _map_cidr_route(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"id": "", "network": ""}
        return {
            "id": str(raw.get("id") or "").strip(),
            "network": str(raw.get("network") or "").strip(),
            "comment": str(raw.get("comment") or "").strip() or None,
            "tunnelId": str(raw.get("tunnel_id") or "").strip() or None,
            "virtualNetworkId": str(raw.get("virtual_network_id") or "").strip() or None,
            "createdAt": str(raw.get("created_at") or "").strip() or None,
        }

    @staticmethod
    def _map_hostname_route(raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            return {"id": "", "hostname": ""}
        return {
            "id": str(raw.get("id") or raw.get("hostname_route_id") or "").strip(),
            "hostname": str(raw.get("hostname") or raw.get("hostname_pattern") or "").strip(),
            "comment": str(raw.get("comment") or "").strip() or None,
            "tunnelId": str(raw.get("tunnel_id") or "").strip() or None,
            "createdAt": str(raw.get("created_at") or "").strip() or None,
        }

    def _find_best_zone(self, hostname: str, zones: List[Dict[str, str]]) -> Dict[str, str] | None:
        host = self._norm_hostname(hostname).lstrip("*.").strip()
        best = None
        for z in zones:
            zn = self._norm_hostname(z.get("name")).strip()
            if not zn:
                continue
            if host == zn or host.endswith("." + zn):
                if best is None or len(zn) > len(self._norm_hostname(best.get("name"))):
                    best = z
        return best

    def _lookup_domain_expiry_single(self, domain: str) -> Dict[str, Any]:
        key = f"domainExpiry:{domain}"
        with conn() as c:
            row = c.execute("SELECT value, expiresAt, createdAt FROM cache WHERE key = ?", (key,)).fetchone()
        if row:
            exp = parse_dt(row["expiresAt"])
            if exp and exp > now():
                parsed = safe_json_loads(row["value"])
                if isinstance(parsed, dict):
                    return {
                        "domain": domain,
                        "expiresAt": parsed.get("expiresAt"),
                        "source": parsed.get("source") or "unknown",
                        "checkedAt": parsed.get("checkedAt") or now_iso(),
                        **({"error": parsed.get("error")} if parsed.get("error") else {}),
                    }

        checked_at = now_iso()
        result: Dict[str, Any] = {
            "domain": domain,
            "source": "unknown",
            "checkedAt": checked_at,
        }

        try:
            url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/rdap+json, application/json",
                    "User-Agent": "dns-panel-python/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            events = payload.get("events") if isinstance(payload, dict) else []
            expires_iso = None
            if isinstance(events, list):
                for ev in events:
                    if not isinstance(ev, dict):
                        continue
                    act = str(ev.get("eventAction") or "").lower()
                    if act not in ("expiration", "expiry", "expires"):
                        continue
                    raw_date = str(ev.get("eventDate") or "").strip()
                    if not raw_date:
                        continue
                    dt = parse_dt(raw_date)
                    if not dt:
                        continue
                    expires_iso = datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
                    break
            if expires_iso:
                result["expiresAt"] = expires_iso
                result["source"] = "rdap"
            else:
                result["error"] = "rdap: expiration event not found"
        except Exception as e:
            result["error"] = f"rdap: {e}"

        ttl_days = 7
        with conn() as c:
            c.execute(
                """
                INSERT INTO cache (key, value, expiresAt, createdAt)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, expiresAt = excluded.expiresAt
                """,
                (
                    key,
                    json.dumps(result, ensure_ascii=False),
                    (now() + timedelta(days=ttl_days)).isoformat().replace("+00:00", "Z"),
                    now_iso(),
                ),
            )
            c.commit()

        return result

    def _dns_context(self, uid: int, q: Dict[str, List[str]]) -> Dict[str, Any]:
        credential_id = first_or_none(q, "credentialId")
        if credential_id:
            row = self._get_credential_row(uid, credential_id)
            if not row:
                raise ValueError("凭证不存在或无权访问")
        else:
            row = self._get_credential_row(uid, None, default_only=True)
            if not row:
                raise ValueError("未配置默认凭证")
        provider = str(row["provider"] or "").strip().lower()
        secrets = self._credential_secrets(row)

        if provider == "cloudflare":
            token = str(secrets.get("apiToken") or "").strip()
            if not token:
                raise ValueError("缺少 Cloudflare API Token")
            return {"credential": row, "provider": provider, "cf": CloudflareApi(token)}

        if provider in ("dnspod", "dnspod_token"):
            api = DnspodApi(secrets)
            return {"credential": row, "provider": provider, "dnspod": api}

        raise ValueError(f"当前 Python 版本暂不支持 {provider} 的 DNS 记录操作")

    @staticmethod
    def _parse_domains(input_value: Any) -> List[str]:
        if isinstance(input_value, list):
            raw = input_value
        elif isinstance(input_value, str):
            raw = re.split(r"[\s,;]+", input_value)
        else:
            raw = []
        out = []
        seen = set()
        for item in raw:
            d = norm_domain(item)
            if not d or d in seen:
                continue
            seen.add(d)
            out.append(d)
        return out

    @staticmethod
    def _parse_record_ids(input_value: Any, max_count: int = 200) -> List[str]:
        if not isinstance(input_value, list):
            return []
        out = []
        seen = set()
        for item in input_value:
            rid = str(item or "").strip()
            if not rid or rid in seen:
                continue
            seen.add(rid)
            out.append(rid)
            if len(out) >= max_count:
                break
        return out

    def _map_cf_zone(self, zone: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(zone.get("id") or ""),
            "name": str(zone.get("name") or ""),
            "status": str(zone.get("status") or "active"),
            "recordCount": zone.get("meta", {}).get("dns_records_count") if isinstance(zone.get("meta"), dict) else None,
            "updatedAt": zone.get("modified_on"),
        }

    def _map_cf_record(self, zone_id: str, zone_name: str, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(row.get("id") or ""),
            "zoneId": str(zone_id or ""),
            "zoneName": str(zone_name or ""),
            "name": str(row.get("name") or ""),
            "type": str(row.get("type") or ""),
            "value": str(row.get("content") or ""),
            "ttl": row.get("ttl"),
            "line": None,
            "weight": None,
            "priority": row.get("priority"),
            "status": None,
            "remark": row.get("comment"),
            "proxied": bool(row.get("proxied")),
            "updatedAt": row.get("modified_on"),
            "meta": {"raw": row},
        }

    def _map_dnspod_zone(self, zone: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(zone.get("id") or ""),
            "name": str(zone.get("name") or ""),
            "status": str(zone.get("status") or "active"),
            "recordCount": zone.get("recordCount"),
            "updatedAt": zone.get("updatedAt"),
        }

    def _map_dnspod_record(self, zone_id: str, zone_name: str, row: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "id": str(row.get("id") or ""),
            "zoneId": str(zone_id or ""),
            "zoneName": str(zone_name or ""),
            "name": str(row.get("name") or ""),
            "type": str(row.get("type") or ""),
            "value": str(row.get("value") or ""),
            "ttl": row.get("ttl"),
            "line": row.get("line"),
            "weight": row.get("weight"),
            "priority": row.get("priority"),
            "status": row.get("status"),
            "remark": row.get("remark"),
            "proxied": False,
            "updatedAt": row.get("updatedAt"),
            "meta": {"raw": row},
        }

    def _normalize_txt_for_cf(self, record_type: str, value: Any) -> str:
        t = str(record_type or "").upper()
        raw = str(value or "")
        if t != "TXT":
            return raw
        s = raw.strip()
        if not s:
            return raw
        if s.startswith('"') and s.endswith('"'):
            return s
        if '"' in s:
            return s
        return f'"{s}"'

    def _esa_region_candidates(self, preferred_region: str | None) -> List[str | None]:
        seen = set()
        out: List[str | None] = []
        for r in [preferred_region, "cn-hangzhou", "ap-southeast-1", None]:
            key = str(r or "__default__")
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    def _esa_with_region_fallback(self, preferred_region: str | None, fn) -> Any:
        last = None
        for region in self._esa_region_candidates(preferred_region):
            try:
                return fn(region)
            except AliyunEsaError as e:
                last = e
                if e.code not in {"InvalidParameter.ArgValue", "InvalidPaused", "SiteNotFound"}:
                    raise
        if last:
            raise last
        raise ValueError("ESA 请求失败")

    def _esa_resolve_site_by_name(self, access_key_id: str, access_key_secret: str, preferred_region: str | None, site_name: str) -> Dict[str, Any] | None:
        target = self._norm_hostname(site_name)
        if not target:
            return None
        for region in self._esa_region_candidates(preferred_region):
            try:
                page = 1
                while page <= 50:
                    data = esa_list_sites(access_key_id, access_key_secret, region, page, 100, site_name)
                    sites = data.get("sites") if isinstance(data, dict) else []
                    if not isinstance(sites, list):
                        sites = []
                    for s in sites:
                        if not isinstance(s, dict):
                            continue
                        name = self._norm_hostname(s.get("siteName"))
                        site_id = str(s.get("siteId") or "").strip()
                        if site_id and name == target:
                            return {"siteId": site_id, "region": region}
                    total = int(data.get("total") or 0) if isinstance(data, dict) else 0
                    if len(sites) < 100:
                        break
                    if total > 0 and page * 100 >= total:
                        break
                    page += 1
            except Exception:
                continue
        return None

    def _sum(self, uid: int) -> None:
        from modules.cache import cache_get, cache_set, dashboard_summary_key
        ck = dashboard_summary_key(uid)
        cached = cache_get(ck)
        if cached is not None:
            self._ok(cached, "获取仪表盘摘要成功")
            return
        sj = with_default_list(read_state(uid, "sync-jobs", []))
        ae = with_default_list(read_state(uid, "alert-events", []))
        t24 = now() - timedelta(hours=24)
        jobs = [x for x in sj if parse_dt(x.get("createdAt")) and parse_dt(x.get("createdAt")) >= t24]
        done = [x for x in jobs if x.get("status") in ("success", "failed")]
        suc = sum(1 for x in done if x.get("status") == "success")
        fail = sum(1 for x in done if x.get("status") == "failed")
        dur = [int(x.get("durationMs") or 0) for x in jobs if isinstance(x.get("durationMs"), int) and int(x.get("durationMs") or 0) > 0]
        with conn() as c:
            creds = c.execute("SELECT provider FROM dns_credentials WHERE userId = ?", (uid,)).fetchall()
            logs = c.execute("SELECT action,status,recordType,newValue,oldValue FROM logs WHERE userId = ? AND datetime(timestamp)>=datetime(?)", (uid, t24.isoformat().replace("+00:00", "Z"))).fetchall()
            exp7 = c.execute("SELECT COUNT(*) c FROM domain_expiry_notifications WHERE userId = ? AND datetime(expiresAt)>=datetime('now') AND datetime(expiresAt)<=datetime(?)", (uid, (now() + timedelta(days=7)).isoformat().replace("+00:00", "Z"))).fetchone()["c"]
            exp30 = c.execute("SELECT COUNT(*) c FROM domain_expiry_notifications WHERE userId = ? AND datetime(expiresAt)>=datetime('now') AND datetime(expiresAt)<=datetime(?)", (uid, (now() + timedelta(days=30)).isoformat().replace("+00:00", "Z"))).fetchone()["c"]
        risky, dist = 0, {}
        for r in logs:
            txt = f"{r['newValue'] or ''} {r['oldValue'] or ''}".lower()
            if r["action"] == "DELETE" or r["status"] == "FAILED" or (r["action"] == "UPDATE" and any(k in txt for k in ["disable", "paused", "inactive"])):
                risky += 1
            rt = str(r["recordType"] or "").strip().upper()
            if rt:
                dist[rt] = dist.get(rt, 0) + 1
        providers = sorted({str(x["provider"] or "") for x in creds if str(x["provider"] or "").strip()})
        pav = []
        for p in providers:
            rj = [x for x in jobs if x.get("scope") == "all" or str(x.get("provider") or "") == p]
            rd = [x for x in rj if x.get("status") in ("success", "failed")]
            rs, rf = sum(1 for x in rd if x.get("status") == "success"), sum(1 for x in rd if x.get("status") == "failed")
            pav.append({"provider": p, "successRate": round((rs / len(rd)) * 100) if rd else 100, "timeoutRate": round((rf / len(rd)) * 100) if rd else 0})
        data = {"summary": {"syncSuccessRate24h": round((suc / len(done)) * 100) if done else 100, "syncFailedCount24h": fail, "syncAvgDurationMs24h": round(sum(dur) / len(dur)) if dur else 0, "riskyChangeCount24h": risky, "providerAvailability": pav, "expiring7d": int(exp7), "expiring30d": int(exp30), "recordTypeDistribution": dist, "pendingAlertCount": sum(1 for x in ae if x.get("status") == "open")}}
        cache_set(ck, data, 60)
        self._ok(data, "获取仪表盘摘要成功")

    def _inspect(self, uid: int, body: Dict[str, Any]) -> None:
        raw = body.get("domains") if isinstance(body.get("domains"), list) else []
        d, seen = [], set()
        for x in raw:
            v = norm_domain(x)
            if not v or v in seen:
                continue
            seen.add(v); d.append(v)
            if len(d) >= 1000:
                break
        if not d:
            self._ok({"inspected": 0, "issues": 0}, "巡检完成"); return
        q = ",".join("?" for _ in d)
        with conn() as c:
            rows = c.execute(f"SELECT domain FROM logs WHERE userId = ? AND domain IN ({q}) AND (status='FAILED' OR action='DELETE')", [uid, *d]).fetchall()
        issues = {norm_domain(x["domain"]) for x in rows if norm_domain(x["domain"])}
        sj = with_default_list(read_state(uid, "sync-jobs", []))
        scope = "credential" if isinstance(body.get("credentialId"), (int, float)) else ("provider" if body.get("provider") else "all")
        sj.insert(0, {"id": make_id("inspect"), "status": "success", "scope": scope, "provider": str(body.get("provider")).strip() if body.get("provider") else None, "credentialId": int(body["credentialId"]) if isinstance(body.get("credentialId"), (int, float)) else None, "durationMs": 0, "createdAt": now_iso(), "updatedAt": now_iso()})
        write_state(uid, "sync-jobs", sj[:MAX_SYNC])
        if issues:
            ev = with_default_list(read_state(uid, "alert-events", []))
            ev.insert(0, {"id": make_id("inspect-alert"), "level": "high" if len(issues) > 3 else "medium", "status": "open", "title": "巡检发现异常", "message": f"本次巡检发现 {len(issues)} 个异常域名", "createdAt": now_iso()})
            write_state(uid, "alert-events", ev[:MAX_EVENTS])
        self._ok({"inspected": len(d), "issues": len(issues)}, "巡检完成")

    def _sync_list(self, uid: int, q: Dict[str, List[str]]) -> None:
        page, limit = p_int((q.get("page") or ["1"])[0], 1, 100000), p_int((q.get("limit") or ["50"])[0], 50, 200)
        st = str((q.get("status") or [""])[0]).strip()
        items = with_default_list(read_state(uid, "sync-jobs", []))
        if st in VALID_SYNC_STATUS:
            items = [x for x in items if x.get("status") == st]
        items.sort(key=lambda x: parse_dt(x.get("createdAt")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        start = (page - 1) * limit
        self._ok({"jobs": items[start:start + limit], "total": len(items), "page": page, "limit": limit}, "获取同步任务成功")

    def _sync_create(self, uid: int, body: Dict[str, Any]) -> None:
        scope = str(body.get("scope") or "").strip()
        if scope not in VALID_SCOPE:
            self._err("无效的 scope，需为 all/provider/credential", 400); return
        cred = int(body["credentialId"]) if isinstance(body.get("credentialId"), (int, float)) else None
        if scope == "credential" and cred is None:
            self._err("scope 为 credential 时必须提供 credentialId", 400); return
        items = with_default_list(read_state(uid, "sync-jobs", []))
        job = {"id": make_id("sync"), "status": "pending", "scope": scope, "provider": str(body.get("provider")).strip() if body.get("provider") else None, "credentialId": cred, "createdAt": now_iso(), "updatedAt": now_iso()}
        items.insert(0, job); write_state(uid, "sync-jobs", items[:MAX_SYNC]); self._ok({"job": job}, "创建同步任务成功", 201)

    def _sync_retry(self, uid: int, sid: str) -> None:
        items = with_default_list(read_state(uid, "sync-jobs", []))
        src = next((x for x in items if x.get("id") == sid), None)
        job = {"id": make_id("retry"), "status": "success", "scope": src.get("scope") if src else "all", "provider": src.get("provider") if src else None, "credentialId": src.get("credentialId") if src else None, "durationMs": 0, "createdAt": now_iso(), "updatedAt": now_iso()}
        items.insert(0, job); write_state(uid, "sync-jobs", items[:MAX_SYNC]); self._ok({"job": job}, "同步任务已重试")

    def _rules_list(self, uid: int) -> None:
        items = with_default_list(read_state(uid, "alert-rules", []))
        if not items:
            items = dflt_rules(); write_state(uid, "alert-rules", items)
        self._ok({"rules": items[:MAX_RULES]}, "获取告警规则成功")

    def _rules_upsert(self, uid: int, body: Dict[str, Any]) -> None:
        name, tp = str(body.get("name") or "").strip()[:60], str(body.get("type") or "").strip()
        if not name: self._err("缺少参数: name", 400); return
        if tp not in VALID_RULE_TYPE: self._err("无效的告警类型", 400); return
        rid = str(body.get("id") or "").strip() or make_id("rule")
        ch = [str(x).strip() for x in (body.get("channels") if isinstance(body.get("channels"), list) else ["inapp"]) if str(x).strip() in VALID_CH] or ["inapp"]
        items = with_default_list(read_state(uid, "alert-rules", []))
        row = {"id": rid, "name": name, "enabled": body.get("enabled") is not False, "type": tp, "threshold": int(body["threshold"]) if isinstance(body.get("threshold"), (int, float)) else None, "channels": ch, "createdAt": now_iso(), "updatedAt": now_iso()}
        i = next((k for k, x in enumerate(items) if x.get("id") == rid), -1)
        if i >= 0:
            row["createdAt"] = items[i].get("createdAt") or row["createdAt"]; items[i] = row
        else:
            items.insert(0, row)
        write_state(uid, "alert-rules", items[:MAX_RULES]); self._ok({"rule": row}, "告警规则已保存")

    def _events_list(self, uid: int, q: Dict[str, List[str]]) -> None:
        lim, st = p_int((q.get("limit") or ["100"])[0], 100, 500), str((q.get("status") or [""])[0]).strip()
        items = with_default_list(read_state(uid, "alert-events", []))
        if st in VALID_ALERT_STATUS: items = [x for x in items if x.get("status") == st]
        items.sort(key=lambda x: parse_dt(x.get("createdAt")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        self._ok({"events": items[:lim]}, "获取告警事件成功")

    def _event_ack(self, uid: int, eid: str) -> None:
        if not eid: self._err("无效的事件 ID", 400); return
        items = with_default_list(read_state(uid, "alert-events", []))
        for x in items:
            if x.get("id") == eid: x["status"] = "acknowledged"
        write_state(uid, "alert-events", items[:MAX_EVENTS]); self._ok({"ok": True}, "告警已确认")

    def _views_list(self, uid: int) -> None:
        items = with_default_list(read_state(uid, "views", []))
        items.sort(key=lambda x: parse_dt(x.get("createdAt")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        self._ok({"views": items[:MAX_VIEWS]}, "获取视图成功")

    def _views_create(self, uid: int, body: Dict[str, Any]) -> None:
        name = str(body.get("name") or "").strip()[:60]
        if not name: self._err("缺少参数: name", 400); return
        items = with_default_list(read_state(uid, "views", []))
        row = {"id": make_id("view"), "name": name, "payload": body.get("payload") if isinstance(body.get("payload"), dict) else {}, "createdAt": now_iso()}
        items.insert(0, row); write_state(uid, "views", items[:MAX_VIEWS]); self._ok({"view": row}, "视图已保存", 201)

    def _views_delete(self, uid: int, vid: str) -> None:
        if not vid: self._err("无效的视图 ID", 400); return
        items = [x for x in with_default_list(read_state(uid, "views", [])) if x.get("id") != vid]
        write_state(uid, "views", items[:MAX_VIEWS]); self._ok({"ok": True}, "视图已删除")

    def _tags_list(self, uid: int, q: Dict[str, List[str]]) -> None:
        d = norm_domain((q.get("domain") or [""])[0]); items = with_default_list(read_state(uid, "domain-tags", []))
        if d: items = [x for x in items if norm_domain(x.get("domain")) == d]
        self._ok({"items": items[:MAX_TAG_ROWS]}, "获取域名标签成功")

    def _tags_upsert(self, uid: int, body: Dict[str, Any]) -> None:
        d = norm_domain(body.get("domain"))
        if not d: self._err("缺少参数: domain", 400); return
        tags = sanitize_tags(body.get("tags")); items = with_default_list(read_state(uid, "domain-tags", []))
        i = next((k for k, x in enumerate(items) if norm_domain(x.get("domain")) == d), -1)
        row = {"domain": d, "tags": tags}
        if i >= 0: items[i] = row
        else: items.insert(0, row)
        write_state(uid, "domain-tags", items[:MAX_TAG_ROWS]); self._ok({"item": row}, "域名标签已保存")

    def _audit(self, uid: int, q: Dict[str, List[str]], user: Dict[str, Any]) -> None:
        page, limit = p_int((q.get("page") or ["1"])[0], 1, 100000), p_int((q.get("limit") or ["50"])[0], 50, 200)
        dm, off = str((q.get("domain") or [""])[0] or "").strip(), (page - 1) * limit
        with conn() as c:
            if dm:
                rows = c.execute("SELECT id,action,resourceType,status,domain,recordName,timestamp FROM logs WHERE userId = ? AND domain LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?", (uid, f"%{dm}%", limit, off)).fetchall()
            else:
                rows = c.execute("SELECT id,action,resourceType,status,domain,recordName,timestamp FROM logs WHERE userId = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?", (uid, limit, off)).fetchall()
        items = []
        for r in rows:
            dt = parse_dt(r["timestamp"])
            items.append({"id": str(r["id"]), "action": r["action"], "resourceType": r["resourceType"], "status": r["status"], "domain": r["domain"] or None, "recordName": r["recordName"] or None, "operator": user.get("username"), "timestamp": dt.isoformat().replace("+00:00", "Z") if dt else str(r["timestamp"])})
        self._ok({"items": items, "page": page, "limit": limit}, "获取审计记录成功")

    def _proxy(self, body: bytes) -> None:
        url = f"{LEGACY}{self.path}"
        req = urllib.request.Request(url, data=body if self.command in {"POST", "PUT", "PATCH", "DELETE"} else None, method=self.command)
        for k, v in self.headers.items():
            if k.lower() in {"host", "content-length", "connection", "accept-encoding"}:
                continue
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                p = r.read()
                self.send_response(r.status); self._cors()
                for k, v in r.getheaders():
                    if k.lower() in {"content-length", "connection", "transfer-encoding", "access-control-allow-origin", "access-control-allow-credentials"}:
                        continue
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(p))); self.end_headers(); self.wfile.write(p); return
        except urllib.error.HTTPError as e:
            p = e.read() if e.fp else b""
            self.send_response(e.code); self._cors()
            for k, v in (e.headers.items() if e.headers else []):
                if k.lower() in {"content-length", "connection", "transfer-encoding", "access-control-allow-origin", "access-control-allow-credentials"}:
                    continue
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(p))); self.end_headers()
            if p: self.wfile.write(p)
        except Exception as e:
            self._err(f"代理请求失败: {e}", 502)


attach_route_methods(H, globals())

def main() -> None:
    init_db()
    from modules.cache import cache_ping
    redis_ok = cache_ping()
    s = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    print(json.dumps({"message": "Python Backend V2 started", "port": PORT, "legacyProxy": LEGACY, "databasePath": str(DB), "redis": "connected" if redis_ok else "unavailable (degraded mode)"}, ensure_ascii=False))
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        s.server_close()


if __name__ == "__main__":
    main()
