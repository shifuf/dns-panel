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
import sqlite3
import sys
from pathlib import Path

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

    # ── domain_accelerations table ──
    """
    CREATE TABLE IF NOT EXISTS domain_accelerations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      dnsCredentialId INTEGER NOT NULL,
      zoneName TEXT NOT NULL,
      pluginProvider TEXT NOT NULL,
      pluginCredentialId INTEGER NOT NULL,
      remoteSiteId TEXT DEFAULT '',
      siteStatus TEXT DEFAULT '',
      verifyStatus TEXT DEFAULT '',
      verified INTEGER NOT NULL DEFAULT 0,
      paused INTEGER NOT NULL DEFAULT 0,
      accessType TEXT DEFAULT 'partial',
      area TEXT DEFAULT 'global',
      planId TEXT DEFAULT '',
      verifyRecordName TEXT DEFAULT '',
      verifyRecordType TEXT DEFAULT '',
      verifyRecordValue TEXT DEFAULT '',
      lastError TEXT DEFAULT '',
      lastSyncedAt TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(userId, dnsCredentialId, zoneName, pluginProvider)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_domain_accelerations_user_zone ON domain_accelerations(userId, zoneName)",
    "CREATE INDEX IF NOT EXISTS idx_domain_accelerations_dns_cred ON domain_accelerations(dnsCredentialId)",

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
]


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
    c.commit()
    c.close()
    print(f"[migrate] done — {applied} statements executed")


if __name__ == "__main__":
    override = sys.argv[1] if len(sys.argv) > 1 else None
    db = resolve_db(override)
    migrate(db)
