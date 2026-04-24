#!/usr/bin/env python3
"""Database migration script.

Runs all CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS statements
so the schema stays in sync after updates. Safe to run repeatedly (idempotent).

Usage:
    python migrate.py              # uses DATABASE_URL or backend/db/database.db
    python migrate.py /path/to.db  # explicit path
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys
from pathlib import Path

from modules.provider_catalog import (
    get_supported_provider_types,
    get_supported_provider_types_by_category,
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = (BASE_DIR / "db" / "database.db").resolve()


def normalize_db_path(raw_path: str) -> Path:
    p = Path(raw_path)
    return p if p.is_absolute() else (BASE_DIR / p).resolve()


def resolve_db(override: str | None = None) -> Path:
    if override:
        return normalize_db_path(override)

    url = os.getenv("DATABASE_URL", f"file:{DEFAULT_DB_PATH.as_posix()}").strip().strip('"')
    if url.startswith("file:"):
        return normalize_db_path(url[5:])
    return DEFAULT_DB_PATH


MIGRATIONS: list[str] = [
    # ── users table ──
    """
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT UNIQUE,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'admin',
      cfApiToken TEXT,
      cfAccountId TEXT,
      twoFactorSecret TEXT,
      twoFactorEnabled BOOLEAN NOT NULL DEFAULT false,
      domainExpiryDisplayMode TEXT NOT NULL DEFAULT 'date',
      domainExpiryThresholdDays INTEGER NOT NULL DEFAULT 7,
      domainExpiryNotifyEnabled BOOLEAN NOT NULL DEFAULT false,
      domainExpiryNotifyWebhookUrl TEXT,
      domainExpiryNotifyEmailEnabled BOOLEAN NOT NULL DEFAULT false,
      domainExpiryNotifyEmailTo TEXT,
      smtpHost TEXT,
      smtpPort INTEGER,
      smtpSecure BOOLEAN,
      smtpUser TEXT,
      smtpPass TEXT,
      smtpFrom TEXT,
      createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)",

    # ── logs table ──
    """
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      action TEXT NOT NULL,
      resourceType TEXT NOT NULL,
      domain TEXT,
      recordName TEXT,
      recordType TEXT,
      oldValue TEXT,
      newValue TEXT,
      status TEXT NOT NULL,
      errorMessage TEXT,
      ipAddress TEXT,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_logs_user_time ON logs(userId, timestamp DESC)",
    "CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action)",
    "CREATE INDEX IF NOT EXISTS idx_logs_resource ON logs(resourceType)",

    # ── dns_credentials table ──
    """
    CREATE TABLE IF NOT EXISTS dns_credentials (
      id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      name TEXT NOT NULL,
      provider TEXT NOT NULL,
      secrets TEXT NOT NULL,
      accountId TEXT,
      isDefault BOOLEAN NOT NULL DEFAULT false,
      createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_dns_credentials_user ON dns_credentials(userId)",
    "CREATE INDEX IF NOT EXISTS idx_dns_credentials_provider ON dns_credentials(provider)",

    # ── cache table ──
    """
    CREATE TABLE IF NOT EXISTS cache (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      value TEXT NOT NULL,
      expiresAt DATETIME NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache(expiresAt)",

    # ── ssl_certificates table ──
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
    """,
    "CREATE INDEX IF NOT EXISTS idx_ssl_certs_user ON ssl_certificates(userId)",
    "CREATE INDEX IF NOT EXISTS idx_ssl_certs_cred ON ssl_certificates(credentialId)",
    "CREATE INDEX IF NOT EXISTS idx_ssl_certs_status ON ssl_certificates(status)",

    # ── system_settings table (global config, not per-user) ──
    """
    CREATE TABLE IF NOT EXISTS system_settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('registration_open', '0')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('setup_complete', '0')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('log_retention_days', '90')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('retry_max_attempts', '3')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('retry_interval_seconds', '2')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('retry_timeout_seconds', '15')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('backup_snapshot_dir', 'backups')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('backup_file_prefix', 'dns-panel-backup')",
    "INSERT OR IGNORE INTO system_settings (key, value) VALUES ('backup_write_server_copy', '1')",

    # ── dns acceleration states table ──
    """
    CREATE TABLE IF NOT EXISTS dns_record_acceleration_states (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      dnsCredentialId INTEGER NOT NULL,
      zoneId TEXT NOT NULL,
      zoneName TEXT NOT NULL DEFAULT '',
      recordId TEXT NOT NULL,
      recordName TEXT NOT NULL DEFAULT '',
      accelerationProvider TEXT NOT NULL DEFAULT 'edgeone',
      accelerationCredentialId INTEGER,
      accelerationSiteId TEXT,
      accelerationDomain TEXT,
      accelerationTarget TEXT,
      originalRecord TEXT NOT NULL,
      acceleratedRecord TEXT,
      enabled INTEGER NOT NULL DEFAULT 1,
      createdAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_record_accel_record ON dns_record_acceleration_states(userId, dnsCredentialId, zoneId, recordId)",
    "CREATE INDEX IF NOT EXISTS idx_dns_record_accel_zone ON dns_record_acceleration_states(userId, dnsCredentialId, zoneId)",
]

TABLE_NAME_RE = re.compile(r"CREATE TABLE IF NOT EXISTS\s+([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
ACTIVE_TABLES = frozenset(
    match.group(1)
    for stmt in MIGRATIONS
    if (match := TABLE_NAME_RE.search(stmt))
)
SUPPORTED_PROVIDER_TYPES = tuple(get_supported_provider_types())
SUPPORTED_PROVIDER_SET = frozenset(SUPPORTED_PROVIDER_TYPES)
SUPPORTED_DNS_PROVIDER_TYPES = tuple(get_supported_provider_types_by_category("dns"))
SUPPORTED_SSL_PROVIDER_TYPES = tuple(get_supported_provider_types_by_category("ssl"))
SUPPORTED_SSL_PROVIDER_SET = frozenset(SUPPORTED_SSL_PROVIDER_TYPES)
SUPPORTED_DNS_PROVIDER_SET = frozenset(SUPPORTED_DNS_PROVIDER_TYPES)
SUPPORTED_PROVIDER_SQL = ", ".join("?" for _ in SUPPORTED_PROVIDER_TYPES)
SUPPORTED_DNS_PROVIDER_SQL = ", ".join("?" for _ in SUPPORTED_DNS_PROVIDER_TYPES)
SUPPORTED_SSL_PROVIDER_SQL = ", ".join("?" for _ in SUPPORTED_SSL_PROVIDER_TYPES)


def migrate(db_path: Path) -> None:
    print(f"[migrate] database: {db_path}")
    db_path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(db_path))
    applied = 0
    for stmt in MIGRATIONS:
        try:
            c.execute(stmt)
            applied += 1
        except sqlite3.OperationalError as e:
            print(f"[migrate] WARN: {e}")
    cleanup_removed_features(c)
    c.commit()
    c.close()
    print(f"[migrate] done — {applied} statements executed")


def cleanup_removed_features(conn: sqlite3.Connection) -> None:
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    for table_name in sorted(
        name
        for name in tables
        if name not in ACTIVE_TABLES
        and not name.startswith("sqlite_")
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
    ):
        conn.execute(f'DROP TABLE "{table_name}"')

    removed_providers: list[str] = []
    if "dns_credentials" in tables and SUPPORTED_PROVIDER_TYPES:
        removed_providers = [
            str(row[0] or "").strip()
            for row in conn.execute(
                f"""
                SELECT DISTINCT TRIM(provider)
                FROM dns_credentials
                WHERE provider IS NOT NULL
                  AND TRIM(provider) != ''
                  AND provider NOT IN ({SUPPORTED_PROVIDER_SQL})
                """,
                SUPPORTED_PROVIDER_TYPES,
            ).fetchall()
            if str(row[0] or "").strip()
        ]
        conn.execute(
            f"""
            DELETE FROM dns_credentials
            WHERE provider IS NULL
               OR TRIM(provider) = ''
               OR provider NOT IN ({SUPPORTED_PROVIDER_SQL})
            """,
            SUPPORTED_PROVIDER_TYPES,
        )

        category_provider_types = (
            SUPPORTED_DNS_PROVIDER_TYPES,
            SUPPORTED_SSL_PROVIDER_TYPES,
        )
        for provider_types in category_provider_types:
            if not provider_types:
                continue
            provider_sql = ", ".join("?" for _ in provider_types)
            user_ids = conn.execute(
                f"SELECT DISTINCT userId FROM dns_credentials WHERE provider IN ({provider_sql})",
                provider_types,
            ).fetchall()
            for row in user_ids:
                user_id = int(row[0] or 0)
                if user_id <= 0:
                    continue
                preferred = conn.execute(
                    f"""
                    SELECT id
                    FROM dns_credentials
                    WHERE userId = ? AND provider IN ({provider_sql})
                    ORDER BY isDefault DESC, createdAt ASC, id ASC
                    LIMIT 1
                    """,
                    (user_id, *provider_types),
                ).fetchone()
                if not preferred:
                    continue
                conn.execute(
                    f"""
                    UPDATE dns_credentials
                    SET isDefault = CASE WHEN id = ? THEN 1 ELSE 0 END,
                        updatedAt = CURRENT_TIMESTAMP
                    WHERE userId = ? AND provider IN ({provider_sql})
                    """,
                    (int(preferred[0] or 0), user_id, *provider_types),
                )

    if "ssl_certificates" in tables and SUPPORTED_SSL_PROVIDER_TYPES:
        conn.execute(
            f"""
            DELETE FROM ssl_certificates
            WHERE provider IS NULL
               OR TRIM(provider) = ''
               OR provider NOT IN ({SUPPORTED_SSL_PROVIDER_SQL})
            """,
            SUPPORTED_SSL_PROVIDER_TYPES,
        )
        conn.execute(
            "DELETE FROM ssl_certificates WHERE credentialId NOT IN (SELECT id FROM dns_credentials WHERE provider = 'tencent_ssl')"
        )

    if "cache" in tables:
        for provider in removed_providers:
            like = f"%{provider}%"
            conn.execute("DELETE FROM cache WHERE key LIKE ? OR value LIKE ?", (like, like))

    if "logs" in tables:
        for provider in removed_providers:
            like = f"%{provider}%"
            conn.execute(
                """
                DELETE FROM logs
                WHERE domain LIKE ?
                   OR recordName LIKE ?
                   OR oldValue LIKE ?
                   OR newValue LIKE ?
                   OR errorMessage LIKE ?
                """,
                (like, like, like, like, like),
            )


if __name__ == "__main__":
    override = sys.argv[1] if len(sys.argv) > 1 else None
    db = resolve_db(override)
    migrate(db)
