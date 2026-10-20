"""Tests for the duplicate-upload guard, effective certificate resolution and
deduplication added for the SSL certificate lifecycle (v2.0).
"""
from __future__ import annotations

import importlib
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


def _iso(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class SslDedupTests(unittest.TestCase):
    """Exercises route_handlers helpers against a throwaway SQLite database."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self._prepare_db(self.db)
        self._load()

    def tearDown(self) -> None:
        self.db = None
        try:
            self.tmp.cleanup()
        except PermissionError:
            # Windows keeps the file handle until GC; the temp dir is harmless.
            pass

    def _prepare_db(self, path: Path) -> None:
        c = sqlite3.connect(str(path))
        c.executescript(
            """
            CREATE TABLE ssl_certificates (
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
              autoRenew INTEGER NOT NULL DEFAULT 0,
              lastRenewedAt TEXT,
              renewError TEXT,
              acmeCa TEXT NOT NULL DEFAULT '',
              UNIQUE(userId, provider, remoteCertId)
            );
            CREATE TABLE ssl_acme_jobs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              userId INTEGER NOT NULL,
              certificateId INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'queued'
            );
            CREATE TABLE ssl_deployment_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              userId INTEGER NOT NULL,
              provider TEXT,
              remoteCertId TEXT
            );
            CREATE TABLE acceleration_cert_bindings (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              userId INTEGER NOT NULL,
              remoteCertId TEXT,
              certRemoteId TEXT
            );
            CREATE TABLE dns_credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              userId INTEGER NOT NULL,
              name TEXT,
              provider TEXT,
              secrets TEXT
            );
            CREATE TABLE ssl_task_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              userId INTEGER,
              taskType TEXT,
              taskId INTEGER,
              domain TEXT,
              source TEXT,
              status TEXT,
              attempt INTEGER,
              targetName TEXT,
              message TEXT,
              createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        c.commit()
        c.close()

    def _load(self):
        import modules.route_handlers as rh
        # Patch instead of reload(): reloading rebinds globals that the other
        # test modules keep references to (app.py normally injects them).
        self._saved = {
            "conn": getattr(rh, "conn", None),
            "cache_delete_pattern": getattr(rh, "cache_delete_pattern", None),
            "_cleanup_edgeone_cert_for_cert": getattr(rh, "_cleanup_edgeone_cert_for_cert", None),
        }
        rh.conn = lambda: self._conn()
        rh.cache_delete_pattern = lambda *a, **k: None
        rh._cleanup_edgeone_cert_for_cert = lambda *a, **k: {"removedEdgeCerts": [], "errors": []}
        self.addCleanup(self._restore)
        self.rh = rh

    def _restore(self) -> None:
        for name, value in (self._saved or {}).items():
            if value is not None:
                setattr(self.rh, name, value)

    def _conn(self):
        c = sqlite3.connect(str(self.db))
        c.row_factory = sqlite3.Row
        return c

    def _insert(self, domain, san, not_before, not_after, remote_id, status="issued", provider="tencent_ssl"):
        with self._conn() as c:
            c.execute(
                """INSERT INTO ssl_certificates
                     (userId, credentialId, provider, remoteCertId, domain, san, status,
                      notBefore, notAfter, isUploaded)
                   VALUES (1, 7, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (provider, remote_id, domain, json.dumps(san), status, not_before, not_after),
            )
            c.commit()

    def test_effective_cert_prefers_root_domain_over_wildcard(self):
        self._insert("x.shifuf.com", ["x.shifuf.com"], _iso(-30), _iso(60), "exact")
        self._insert("*.shifuf.com", ["*.shifuf.com"], _iso(-30), _iso(200), "wildcard")
        best = self.rh._effective_cert_for_host(1, "x.shifuf.com")
        self.assertIsNotNone(best)
        self.assertEqual(best["remoteCertId"], "exact")

    def test_effective_cert_falls_back_to_wildcard(self):
        self._insert("*.shifuf.com", ["*.shifuf.com"], _iso(-30), _iso(200), "wildcard")
        best = self.rh._effective_cert_for_host(1, "x.shifuf.com")
        self.assertIsNotNone(best)
        self.assertEqual(best["remoteCertId"], "wildcard")

    def test_expired_cert_never_shadows_valid_wildcard(self):
        self._insert("x.shifuf.com", ["x.shifuf.com"], _iso(-400), _iso(-5), "expired-exact")
        self._insert("*.shifuf.com", ["*.shifuf.com"], _iso(-30), _iso(200), "wildcard")
        best = self.rh._effective_cert_for_host(1, "x.shifuf.com")
        self.assertEqual(best["remoteCertId"], "wildcard")

    def test_upload_rejects_identical_duplicate(self):
        self._insert("*.shifuf.com", ["*.shifuf.com"], "2026-10-17T00:00:00Z", _iso(80), "dup-1")
        verdict = self.rh._needs_replacement_upload(1, {
            "names": ["*.shifuf.com"],
            "notBefore": "2026-10-17T00:00:00Z",
            "notAfter": _iso(80),
        })
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["mode"], "duplicate")

    def test_upload_rejected_outside_seven_day_window(self):
        self._insert("x.shifuf.com", ["x.shifuf.com"], _iso(-10), _iso(60), "current")
        verdict = self.rh._needs_replacement_upload(1, {
            "names": ["x.shifuf.com"],
            "notBefore": _iso(0),
            "notAfter": _iso(150),
        })
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["mode"], "too_early")

    def test_upload_allowed_inside_window_when_newly_issued(self):
        self._insert("x.shifuf.com", ["x.shifuf.com"], _iso(-80), _iso(5), "current")
        verdict = self.rh._needs_replacement_upload(1, {
            "names": ["x.shifuf.com"],
            "notBefore": _iso(0),
            "notAfter": _iso(150),
        })
        self.assertTrue(verdict["allowed"])
        self.assertEqual(verdict["mode"], "renewal")

    def test_upload_rejected_when_not_newly_issued(self):
        self._insert("x.shifuf.com", ["x.shifuf.com"], _iso(-5), _iso(5), "current")
        verdict = self.rh._needs_replacement_upload(1, {
            "names": ["x.shifuf.com"],
            "notBefore": _iso(-100),
            "notAfter": _iso(150),
        })
        self.assertFalse(verdict["allowed"])
        self.assertEqual(verdict["mode"], "stale")

    def test_dedup_keeps_one_copy_per_domain(self):
        self._insert("*.shifuf.com", ["*.shifuf.com"], "2026-10-17T00:00:00Z", _iso(90), "keep-me", status="issued")
        self._insert("*.shifuf.com", ["*.shifuf.com"], "2026-10-17T00:00:00Z", _iso(90), "dup-a", status="issued")
        self._insert("*.shifuf.com", ["*.shifuf.com"], "2026-10-17T00:00:00Z", _iso(90), "dup-b", status="issued")
        summary = self.rh._dedup_certificates(1, delete_cloud=False)
        self.assertEqual(summary["removedCount"], 2)
        with self._conn() as c:
            remaining = [row["remoteCertId"] for row in c.execute("SELECT remoteCertId FROM ssl_certificates")]
        self.assertEqual(len(remaining), 1)

    def test_dedup_keeps_unrelated_certificates(self):
        self._insert("a.shifuf.com", ["a.shifuf.com"], _iso(-5), _iso(90), "a-cert")
        self._insert("b.shifuf.com", ["b.shifuf.com"], _iso(-5), _iso(90), "b-cert")
        summary = self.rh._dedup_certificates(1, delete_cloud=False)
        self.assertEqual(summary["removedCount"], 0)

    def test_dedup_replaces_older_cert_with_renewal(self):
        old_san = ["*.shifuf.com"]
        new_san = ["*.shifuf.com", "_dnsauth.shifuf.com"]
        with self._conn() as c:
            c.execute(
                """INSERT INTO ssl_certificates
                     (userId, credentialId, provider, remoteCertId, domain, san, status, notBefore, notAfter)
                   VALUES (1, 7, 'tencent_ssl', 'old', '*.shifuf.com', ?, 'issued', ?, ?)""",
                (json.dumps(old_san), _iso(-360), _iso(6)),
            )
            c.execute(
                """INSERT INTO ssl_certificates
                     (userId, credentialId, provider, remoteCertId, domain, san, status, notBefore, notAfter)
                   VALUES (1, 7, 'tencent_ssl', 'new', '*.shifuf.com', ?, 'issued', ?, ?)""",
                (json.dumps(new_san), _iso(0), _iso(90)),
            )
            c.commit()
        summary = self.rh._dedup_certificates(1, delete_cloud=False)
        self.assertEqual(summary["removedCount"], 1)
        with self._conn() as c:
            remaining = [row["remoteCertId"] for row in c.execute("SELECT remoteCertId FROM ssl_certificates")]
        self.assertEqual(remaining, ["new"])


if __name__ == "__main__":
    unittest.main()
