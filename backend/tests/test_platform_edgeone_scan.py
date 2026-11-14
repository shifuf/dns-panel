"""Platform list/check routes must scan each Tencent account and zone once."""
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


class PlatformEdgeOneScanTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE dns_credentials (id INTEGER PRIMARY KEY, userId INTEGER, name TEXT, provider TEXT, secrets TEXT, createdAt TEXT);
            CREATE INDEX credential_scan_desc ON dns_credentials(userId, id DESC);
            CREATE TABLE ssl_certificates (id INTEGER PRIMARY KEY, userId INTEGER, remoteCertId TEXT, domain TEXT, san TEXT, status TEXT, notAfter TEXT);
            CREATE TABLE ssl_platform_deployments (id INTEGER PRIMARY KEY, userId INTEGER, credentialId INTEGER, certRowId INTEGER, provider TEXT, domain TEXT, updatedAt TEXT);
            CREATE TABLE acceleration_cert_bindings (id INTEGER PRIMARY KEY, userId INTEGER, provider TEXT, accelerationCredentialId INTEGER,
                siteId TEXT, domainName TEXT, edgeCertId TEXT, certRemoteId TEXT, notAfter TEXT, status TEXT, lastError TEXT, syncedAt TEXT, updatedAt TEXT);
        """)
        self.account_a = ("test-id-a", "test-key-a")
        self.account_b = ("test-id-b", "test-key-b")
        self.add_credential(2, self.account_a, "alias credential")
        self.add_credential(1, self.account_a, "canonical credential")
        self.snapshots = {self.account_a: {"zone-a": [self.entry("cdn.example.com")]}}
        self.calls = []
        self.patchers = [
            patch("modules.route_handlers.conn", new=self.connection),
            patch("modules.tencent_edgeone_api.TencentEdgeOneApi", new=self.api),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def add_credential(self, identifier, account, name):
        self.db.execute("INSERT INTO dns_credentials VALUES (?,1,?,'tencent',?,'2026-01-01')", (
            identifier, name, json.dumps({"secretId": account[0], "secretKey": account[1]}),
        ))
        self.db.commit()

    @staticmethod
    def entry(domain, cert_id="edge-cert"):
        return {"domainName": domain, "certificateId": cert_id, "certificateMode": "sslcert",
                "certificateStatus": "deployed", "certificateExpireTime": "2099-01-01T00:00:00Z",
                "domainStatus": "online", "cnameStatus": "finished"}

    def add_binding(self, credential, site, domain):
        self.db.execute("""INSERT INTO acceleration_cert_bindings
            VALUES (99,1,'edgeone',?,?,?,'recorded-cert','panel-cert','2099-01-01T00:00:00Z','synced','','2026-01-01','2026-01-01')""", (credential, site, domain))
        self.db.commit()

    @contextmanager
    def connection(self):
        with self.db:
            yield self.db

    def api(self, secret_id, secret_key):
        account = (secret_id, secret_key)
        owner = self

        class Api:
            def list_zones(self, offset=0, limit=100):
                owner.calls.append((account, "zones"))
                return {"zones": [{"zoneId": site} for site in owner.snapshots.get(account, {})]}

            def list_acceleration_domains(self, site_id):
                owner.calls.append((account, site_id))
                return {"items": owner.snapshots.get(account, {}).get(site_id, [])}

        return Api()

    def route(self, method):
        self.calls.clear()
        handler = app.H.__new__(app.H)
        handler.command = method
        handler._auth = lambda: {"id": 1}
        handler._credential_secrets = lambda row: json.loads(row["secrets"])

        def acceleration_auth(uid, credential):
            row = self.db.execute("SELECT * FROM dns_credentials WHERE id=?", (credential,)).fetchone()
            secrets = json.loads(row["secrets"])
            return {"api": self.api(secrets["secretId"], secrets["secretKey"])}

        handler._acceleration_auth = acceleration_auth
        handler._ok = lambda data, message="", code=200: setattr(handler, "result", (code, data))
        handler._err = lambda message, code=400: setattr(handler, "result", (code, {"error": message}))
        path = "/api/ssl/platform-deployments" + ("/check" if method == "POST" else "")
        routes._ssl_routes(handler, path, {}, b"{}")
        code, data = handler.result
        self.assertEqual(code, 200, data)
        return data["deployments" if method == "GET" else "checks"]

    def identities(self, items):
        return sorted((item.get("credentialId"), item.get("siteId", ""), item["domain"]) for item in items)

    def test_duplicate_credentials_scan_once_with_same_list_and_check_identity(self):
        results = []
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                items = self.route(method)
                results.append(self.identities(items))
                self.assertEqual(self.calls, [(self.account_a, "zones"), (self.account_a, "zone-a")])
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]["credentialId"], 1)
                self.assertEqual(items[0]["credentialName"], "canonical credential")
        self.assertEqual(results[0], results[1])

    def test_same_domain_on_different_accounts_is_not_merged(self):
        self.add_credential(3, self.account_b, "other account")
        self.snapshots[self.account_b] = {"zone-a": [self.entry("cdn.example.com")]}
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                items = self.route(method)
                self.assertEqual(len(items), 2)
                self.assertEqual(self.identities(items), [(1, "zone-a", "cdn.example.com"), (3, "zone-a", "cdn.example.com")])
                self.assertEqual(len(self.calls), 4)

    def test_same_account_domain_in_different_zones_is_not_merged(self):
        self.snapshots[self.account_a]["zone-b"] = [self.entry("cdn.example.com", "second-cert")]
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                items = self.route(method)
                self.assertEqual(len(items), 2)
                self.assertEqual(self.identities(items), [(1, "zone-a", "cdn.example.com"), (1, "zone-b", "cdn.example.com")])
                self.assertEqual(len(self.calls), 3)

    def test_record_under_credential_alias_does_not_duplicate_live_domain(self):
        self.add_binding(2, "zone-a", "cdn.example.com")
        for method in ("GET", "POST"):
            with self.subTest(method=method):
                items = self.route(method)
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]["credentialId"], 1)
                self.assertEqual(len(self.calls), 2)

    def test_unbound_record_reuses_already_scanned_zone(self):
        self.snapshots[self.account_a]["zone-a"] = [self.entry("cdn.example.com", "")]
        self.add_binding(2, "zone-a", "cdn.example.com")
        listed = self.route("GET")
        checked = self.route("POST")
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(self.identities(listed), self.identities(checked))
        self.assertFalse(checked[0]["live"]["bound"])

    def test_fallback_domains_are_normalized_consistently(self):
        self.snapshots[self.account_a]["zone-a"] = [self.entry("cdn.example.com", "")]
        self.add_binding(2, "zone-a", " CDN.Example.COM. ")
        listed = self.route("GET")
        checked = self.route("POST")
        self.assertEqual(self.identities(listed), [(1, "zone-a", "cdn.example.com")])
        self.assertEqual(self.identities(checked), self.identities(listed))
        self.assertFalse(checked[0]["live"]["bound"])

    def test_other_account_record_is_not_hidden_by_same_live_domain(self):
        self.add_credential(3, self.account_b, "other account")
        self.snapshots[self.account_b] = {}
        self.add_binding(3, "zone-b", "cdn.example.com")
        listed = self.route("GET")
        checked = self.route("POST")
        self.assertEqual(len(listed), 2)
        self.assertEqual(len(checked), 2)
        self.assertEqual(self.identities(listed), self.identities(checked))


if __name__ == "__main__":
    unittest.main()
