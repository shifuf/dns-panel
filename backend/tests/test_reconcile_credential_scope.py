"""Whole-account reconciliation ignores credentials with no Tencent capability."""
from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from modules import route_handlers as routes


class ReconcileCredentialScopeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE dns_credentials (id INTEGER PRIMARY KEY, userId INTEGER, name TEXT, provider TEXT, secrets TEXT);
            CREATE TABLE ssl_certificates (userId INTEGER, credentialId INTEGER, provider TEXT);
        """)

        @contextmanager
        def connection():
            yield self.db

        class TencentTransport:
            def __init__(self, sid, key): pass
            def list_certificates(self, **kwargs): return {"certificates": [], "totalCount": 0}

        for name, replacement in (("conn", connection), ("TencentSslApi", TencentTransport)):
            patcher = patch.object(routes, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def credential(self, cid, provider, secrets=None):
        self.db.execute("INSERT INTO dns_credentials VALUES (?, 1, ?, ?, ?)", (cid, f"credential-{cid}", provider, json.dumps(secrets or {})))

    def reconcile(self, selected=None):
        db = self.db

        class Handler:
            command = "POST"
            def _auth(self): return {"id": 1}
            def _json_body(self, body): return json.loads(body)
            def _credential_secrets(self, row): return json.loads(row["secrets"])
            def _get_credential_row(self, uid, cid):
                return db.execute("SELECT * FROM dns_credentials WHERE userId = ? AND id = ?", (uid, cid)).fetchone()
            def _ok(self, data, message="", code=200): self.result = (code, data)
            def _err(self, message, code=400): self.result = (code, {"error": message})

        handler = Handler()
        body = {"credentialId": selected} if selected is not None else {}
        routes._ssl_routes(handler, "/api/ssl/certificates/reconcile", {}, json.dumps(body).encode())
        return handler.result

    def test_all_accounts_skip_other_provider_credentials_without_tencent_keys(self):
        self.credential(1, "cloudflare", {"apiToken": "token"})
        self.credential(2, "qiniu", {"accessKey": "ak", "secretKey": "sk"})
        self.credential(3, "upyun", {"username": "user", "password": "password"})
        self.credential(7, "tencent_ssl", {"secretId": "sid", "secretKey": "key"})
        status, result = self.reconcile()
        self.assertEqual(status, 200)
        self.assertEqual(result["failed"], 0)
        self.assertEqual([row["credentialId"] for row in result["results"]], [7])

    def test_explicit_non_tencent_credential_reports_missing_keys(self):
        self.credential(1, "qiniu", {"accessKey": "ak", "secretKey": "sk"})
        status, result = self.reconcile(1)
        self.assertEqual(status, 200)
        self.assertEqual(result["failed"], 1)
        self.assertIn("SecretId", result["results"][0]["error"])

    def test_missing_explicit_credential_is_an_error(self):
        status, _ = self.reconcile(999)
        self.assertEqual(status, 404)

    def test_tencent_provider_with_missing_keys_still_reports_error(self):
        self.credential(1, "tencent_ssl")
        self.credential(2, "dnspod", {"secretId": "sid"})
        status, result = self.reconcile("all")
        self.assertEqual(status, 200)
        self.assertEqual(result["failed"], 2)

    def test_other_provider_with_both_tencent_keys_remains_eligible(self):
        self.credential(1, "custom", {"secretId": "sid", "secretKey": "key"})
        status, result = self.reconcile()
        self.assertEqual(status, 200)
        self.assertEqual(result["failed"], 0)
        self.assertEqual([row["credentialId"] for row in result["results"]], [1])


if __name__ == "__main__":
    unittest.main()
