"""Renewal dispatch uses real stored bindings and replaces only covered hosts."""
from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules import route_handlers as routes


class PlatformRenewalCoverageTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE dns_credentials (id INTEGER PRIMARY KEY, name TEXT);
            CREATE TABLE ssl_platform_deployments (
                userId INTEGER, provider TEXT, credentialId INTEGER, domain TEXT,
                platformCertId TEXT, platformCertName TEXT, fingerprint TEXT,
                notBefore TEXT, notAfter TEXT
            );
            INSERT INTO dns_credentials VALUES (7, 'CDN account');
        """)
        self.cert = {"id": 15, "remoteCertId": "*.example.com", "domain": "*.example.com", "san": '["*.example.com"]'}
        self.handler = type("Handler", (), {
            "_get_credential_row": lambda _self, uid, cid: {"id": cid, "name": "CDN account"},
            "_credential_secrets": lambda _self, row: {},
        })()

        @contextmanager
        def connection():
            yield self.db

        def deploy(handler, uid, provider, credential, secrets, cert, pem, domains):
            return {"platformCertName": "renewed", "results": [{"domain": domain, "ok": True} for domain in domains]}

        for target, replacement in (
            ("conn", connection), ("_panel_cert_pem", lambda *args: {"publicKey": "fixture", "privateKey": "fixture"}),
            ("_deploy_pem_to_platform", deploy), ("_write_ssl_task_log", lambda *args, **kwargs: None),
        ):
            patcher = patch.object(routes, target, replacement, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def binding(self, domain, user=1):
        self.db.execute("INSERT INTO ssl_platform_deployments VALUES (?, 'qiniu', 7, ?, 'old', 'old', '', '', '')", (user, domain))

    def test_wildcard_renewal_reuploads_tracked_cdn_subdomain(self):
        self.binding("cdn.example.com")
        result = routes._sync_cert_to_platforms(self.handler, 1, self.cert)
        self.assertEqual(result["synced"], 1)
        self.assertEqual([row["domain"] for row in result["results"]], ["cdn.example.com"])

    def test_wildcard_renewal_excludes_apex_deeper_hosts_and_other_users(self):
        for domain in ("example.com", "cdn.oss.example.com", "unrelated.net"):
            self.binding(domain)
        self.binding("other.example.com", user=2)
        result = routes._sync_cert_to_platforms(self.handler, 1, self.cert)
        self.assertEqual(result["synced"], 0)

    def test_san_matches_are_case_insensitive_and_keep_exact_names(self):
        self.cert["san"] = json.dumps(["*.example.com", "EXAMPLE.NET"])
        self.binding("example.net")
        result = routes._sync_cert_to_platforms(self.handler, 1, self.cert)
        self.assertEqual(result["synced"], 1)

    def test_qiniu_wildcard_target_keeps_leading_dot_during_renewal(self):
        self.binding(".example.com")
        result = routes._sync_cert_to_platforms(self.handler, 1, self.cert)
        self.assertEqual(result["synced"], 1)
        self.assertEqual(result["results"][0]["domain"], ".example.com")

    def test_exact_certificate_does_not_replace_qiniu_wildcard_target(self):
        self.cert.update(domain="cdn.example.com", san='["cdn.example.com"]')
        self.binding(".example.com")
        self.assertEqual(routes._sync_cert_to_platforms(self.handler, 1, self.cert)["synced"], 0)


if __name__ == "__main__":
    unittest.main()
