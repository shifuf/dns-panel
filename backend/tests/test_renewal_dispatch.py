"""Exercise the renewal endpoint with SQLite and an isolated Tencent transport."""
from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # Installs the shared route dependencies used by the HTTP server.
from modules import route_handlers as routes


class RenewalDispatchTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE dns_credentials (id INTEGER PRIMARY KEY, userId INTEGER, name TEXT, provider TEXT, secrets TEXT);
            INSERT INTO dns_credentials VALUES (7, 1, 'Tencent fixture', 'tencent_ssl', '{}');
            CREATE TABLE ssl_certificates (userId INTEGER, provider TEXT, status TEXT, domain TEXT, san TEXT, notAfter TEXT);
        """)
        self.days = 3
        self.other_certs = []
        self.applications = []
        owner = self

        class TencentTransport:
            def __init__(self, sid, skey):
                pass

            def list_certificates(self, **kwargs):
                certs = [{"domain": "api.example.com", "status": "issued", "remoteCertId": "old-cert", "notAfter": owner.expiry(owner.days)}] + owner.other_certs
                return {"certificates": certs, "totalCount": len(certs)}

            def apply_certificate(self, domain, method, old_certificate_id=None):
                owner.applications.append((domain, method, old_certificate_id))
                return {"CertificateId": "replacement-cert"}

        @contextmanager
        def connection():
            yield self.db

        for target, replacement in (
            ("conn", connection), ("TencentSslApi", TencentTransport),
            ("_write_ssl_task_log", lambda *args, **kwargs: None),
            ("_push_ssl_success_event", lambda *args, **kwargs: None),
            ("_send_ssl_failure_notifications", lambda *args, **kwargs: None),
        ):
            patcher = patch.object(routes, target, replacement, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(routes.acme_api, "acme_available", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def expiry(days):
        return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()

    def run_renewal(self):
        class Handler:
            command = "POST"

            def _auth(self): return {"id": 1}
            def _json_body(self, value): return json.loads(value)
            def _credential_secrets(self, row): return {"secretId": "fixture-id", "secretKey": "fixture-key"}
            def _ok(self, data, message="", code=200): self.result = (code, data)
            def _err(self, message, code=400): self.result = (code, {"error": message})

        handler = Handler()
        routes._ssl_routes(handler, "/api/ssl/certificates/renew-expired", {}, b'{"renewDays":7}')
        self.assertEqual(handler.result[0], 200, handler.result)
        return handler.result[1]

    def test_expiring_tencent_certificate_reaches_renewal_application(self):
        result = self.run_renewal()
        self.assertEqual(result["failed"], [])
        self.assertEqual([item["newCertId"] for item in result["renewed"]], ["replacement-cert"])
        self.assertEqual(self.applications, [("api.example.com", "DNS", "old-cert")])

    def test_healthy_acme_coverage_still_prevents_duplicate_application(self):
        self.db.execute("INSERT INTO ssl_certificates VALUES (1, 'acme', 'issued', '*.example.com', '[\"*.example.com\"]', ?)", (self.expiry(60),))
        result = self.run_renewal()
        self.assertEqual(result["failed"], [])
        self.assertEqual(result["renewed"], [])
        self.assertEqual(self.applications, [])
        self.assertEqual(len(result["skipped"]), 1)

    def test_healthy_tencent_wildcard_prevents_duplicate_application(self):
        self.other_certs = [{"domain": "*.example.com", "status": "issued", "remoteCertId": "healthy", "notAfter": self.expiry(60)}]
        result = self.run_renewal()
        self.assertEqual(result["failed"], [])
        self.assertEqual(result["renewed"], [])
        self.assertEqual(self.applications, [])


if __name__ == "__main__":
    unittest.main()
