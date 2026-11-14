"""Renewal discovers existing EdgeOne HTTPS hosts without panel binding rows."""
from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app  # Installs the HTTP server's shared route dependencies.
from modules import route_handlers as routes
from modules.tencent_edgeone_api import TencentEdgeOneApi


class NativeEdgeOneRenewalTargetTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE dns_credentials (
                id INTEGER PRIMARY KEY, userId INTEGER, name TEXT, provider TEXT, secrets TEXT
            );
            CREATE INDEX credentials_desc ON dns_credentials(userId, id DESC);
            CREATE TABLE dns_record_acceleration_states (
                userId INTEGER, enabled INTEGER, accelerationDomain TEXT, recordName TEXT,
                accelerationCredentialId INTEGER, accelerationSiteId TEXT, accelerationProvider TEXT
            );
            CREATE TABLE acceleration_cert_bindings (
                userId INTEGER, provider TEXT, accelerationCredentialId INTEGER, siteId TEXT, domainName TEXT,
                source TEXT, certRemoteId TEXT, edgeCertId TEXT, fingerprint TEXT, notAfter TEXT,
                status TEXT, lastError TEXT, syncedAt TEXT, createdAt TEXT, updatedAt TEXT,
                UNIQUE(userId, accelerationCredentialId, siteId, domainName)
            );
            CREATE TABLE ssl_certificates (
                id INTEGER PRIMARY KEY, userId INTEGER, credentialId INTEGER, provider TEXT,
                remoteCertId TEXT, domain TEXT, san TEXT, status TEXT, notAfter TEXT
            );
        """)
        self.add_credential(1, "account-a", provider="dnspod")
        self.add_credential(3, "account-a")
        self.accounts = {"account-a": {"zone-a": [self.host("cdn.example.com")]}}
        self.failed_accounts = set()
        self.failed_zones = set()
        self.calls = []
        self.cache = {}
        owner = self

        def transport(api, action, payload):
            account = api._secret_id
            owner.calls.append((account, action, dict(payload)))
            if account in owner.failed_accounts:
                raise ValueError("credential unavailable")
            zones = owner.accounts.get(account, {})
            offset, limit = payload["Offset"], payload["Limit"]
            if action == "DescribeZones":
                items = [{"ZoneId": zone, "ZoneName": "example.com", "Status": "active"} for zone in zones]
                return {"Zones": items[offset:offset + limit], "TotalCount": len(items)}
            if action == "DescribeAccelerationDomains":
                zone = payload["ZoneId"]
                if (account, zone) in owner.failed_zones:
                    raise ValueError("zone unavailable")
                items = zones[zone]
                return {"AccelerationDomains": items[offset:offset + limit], "TotalCount": len(items)}
            raise AssertionError(f"Unexpected cloud action: {action}")

        for patcher in (
            patch.object(routes, "conn", self.connection),
            patch.object(routes, "decrypt_text", lambda value: value),
            patch.object(routes, "cache_get", lambda key: self.cache.get(key)),
            patch.object(routes, "cache_set", lambda key, value, ttl: self.cache.__setitem__(key, value)),
            patch.object(TencentEdgeOneApi, "_tc3_request", transport),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    @contextmanager
    def connection(self):
        with self.db:
            yield self.db

    def add_credential(self, identifier, account, provider="edgeone", user=1):
        self.db.execute("INSERT INTO dns_credentials VALUES (?, ?, ?, ?, ?)", (
            identifier, user, f"credential-{identifier}", provider,
            json.dumps({"secretId": account, "secretKey": f"key-{account}"}),
        ))

    @staticmethod
    def host(domain, mode="sslcert", cert_id="old-cert"):
        return {"DomainName": domain, "DomainStatus": "online", "CnameStatus": "finished",
                "Certificate": {"Mode": mode, "List": ([{"CertId": cert_id, "Status": "deployed"}]
                                                        if cert_id else [])}}

    @staticmethod
    def identities(targets):
        return sorted((target["accelerationCredentialId"], target["siteId"], target["domainName"])
                      for target in targets)

    def test_renewal_preview_finds_native_https_hosts_with_no_panel_state(self):
        self.accounts["account-a"]["zone-a"] = [self.host(f"{name}.example.com") for name in ("account", "ai", "cpa", "dns")]
        cert = {"domain": "*.example.com", "san": '["*.example.com"]'}
        result = routes._sync_cert_to_edgeone(object(), 1, cert, dry_run=True)
        self.assertEqual(result["synced"], 4)
        self.assertEqual(sorted(row["domain"] for row in result["results"]),
                         ["account.example.com", "ai.example.com", "cpa.example.com", "dns.example.com"])
        self.assertTrue(all(row["dryRun"] for row in result["results"]))

    def test_coverage_and_disabled_https_filter_only_eligible_hosts(self):
        self.accounts["account-a"]["zone-a"] = [
            self.host(" CDN.Example.COM. "), self.host("EXAMPLE.NET."),
            self.host("example.com"), self.host("deep.cdn.example.com"), self.host("unrelated.net"),
            self.host("disabled.example.com", mode="disable"),
            self.host("unknown.example.com", mode="", cert_id=""),
        ]
        targets = routes._accel_targets_for_cert_names(1, ["*.EXAMPLE.COM", "example.net"])
        self.assertEqual(self.identities(targets),
                         [(3, "zone-a", "cdn.example.com"), (3, "zone-a", "example.net")])
        self.assertTrue(all(target["provider"] == "edgeone" for target in targets))

    def test_duplicate_accounts_keep_an_edgeone_credential_and_distinct_sites(self):
        self.add_credential(9, "account-a")
        self.add_credential(4, "account-b")
        self.add_credential(5, "account-other-user", user=2)
        self.accounts["account-a"]["zone-b"] = [self.host("cdn.example.com")]
        self.accounts["account-b"] = {"zone-a": [self.host("cdn.example.com")]}
        self.accounts["account-other-user"] = {"zone-a": [self.host("cdn.example.com")]}
        targets = routes._accel_targets_for_cert_names(1, ["*.example.com"])
        self.assertEqual(self.identities(targets), [
            (3, "zone-a", "cdn.example.com"), (3, "zone-b", "cdn.example.com"),
            (4, "zone-a", "cdn.example.com"),
        ])
        self.assertEqual([(account, action) for account, action, _ in self.calls].count(
            ("account-a", "DescribeZones")), 1)

    def test_zone_and_host_pagination_include_later_pages(self):
        self.accounts["account-a"] = {f"zone-{index}": [] for index in range(101)}
        self.accounts["account-a"]["zone-100"] = [self.host(f"host{index}.example.com") for index in range(101)]
        targets = routes._accel_targets_for_cert_names(1, ["host100.example.com"])
        self.assertEqual(self.identities(targets), [(3, "zone-100", "host100.example.com")])

    def test_unreadable_credentials_and_failed_accounts_or_zones_do_not_stop_discovery(self):
        self.add_credential(2, "unavailable")
        self.db.execute("INSERT INTO dns_credentials VALUES (6, 1, 'broken', 'edgeone', 'not-json')")
        self.failed_accounts.add("unavailable")
        self.accounts["account-a"] = {"failed-zone": [], "zone-a": [self.host("cdn.example.com")]}
        self.failed_zones.add(("account-a", "failed-zone"))
        targets = routes._accel_targets_for_cert_names(1, ["*.example.com"])
        self.assertEqual(self.identities(targets), [(3, "zone-a", "cdn.example.com")])

    def test_cached_discovery_is_filtered_for_each_certificate(self):
        self.accounts["account-a"]["zone-a"].append(self.host("www.example.net"))
        first = routes._accel_targets_for_cert_names(1, ["*.example.com"])
        self.assertEqual(self.identities(first), [(3, "zone-a", "cdn.example.com")])
        self.failed_accounts.add("account-a")
        second = routes._accel_targets_for_cert_names(1, ["www.example.net"])
        self.assertEqual(self.identities(second), [(3, "zone-a", "www.example.net")])
        self.assertEqual(len(self.calls), 2)

    def test_panel_and_native_targets_for_same_site_are_not_duplicated(self):
        self.db.execute("INSERT INTO dns_record_acceleration_states VALUES (1, 1, 'cdn.example.com', 'cdn', 3, 'zone-a', 'edgeone')")
        self.accounts["account-a"]["zone-a"].append(self.host("api.example.com"))
        targets = routes._accel_targets_for_cert_names(1, ["*.example.com"])
        self.assertEqual(self.identities(targets),
                         [(3, "zone-a", "api.example.com"), (3, "zone-a", "cdn.example.com")])

    def capture_cloud_binds(self):
        self.binds = []
        self.retired = []

        def binder(handler, uid, credential, site, cert, domain, dry_run):
            self.binds.append((domain, cert["remoteCertId"]))
            return "edge-" + cert["remoteCertId"]

        patcher = patch.dict(routes._ACCEL_CERT_BINDERS, {"edgeone": binder})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(routes.TencentSslApi, "delete_certificate",
                               lambda api, cert_id: self.retired.append(cert_id))
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def cert(identifier, expiry, domain="cdn.example.com"):
        return {"provider": "acme", "remoteCertId": identifier, "domain": domain,
                "san": json.dumps([domain]), "notAfter": expiry}

    def binding(self):
        return self.db.execute("SELECT * FROM acceleration_cert_bindings WHERE domainName='cdn.example.com'").fetchone()

    def test_all_sync_does_not_downgrade_a_newer_wildcard_binding_to_older_exact(self):
        self.capture_cloud_binds()
        self.db.execute("INSERT INTO ssl_certificates VALUES (1,1,3,'acme','new-wildcard','*.example.com','[]','issued','2099-02-12T00:00:00Z')")
        self.db.execute("INSERT INTO ssl_certificates VALUES (2,1,3,'acme','old-exact','cdn.example.com','[]','issued','2099-01-05T00:00:00Z')")
        handler = app.H.__new__(app.H)
        handler.command = "POST"
        handler._auth = lambda: {"id": 1}
        handler._acceleration_auth = lambda uid, cid: {
            "credential": self.db.execute("SELECT * FROM dns_credentials WHERE id=?", (cid,)).fetchone(),
        }
        handler._credential_secrets = lambda row: json.loads(row["secrets"])
        handler._ok = lambda data, message="", code=200: setattr(handler, "result", data)
        routes._ssl_routes(handler, "/api/ssl/certificates/sync-edgeone", {}, b"{}")
        self.assertEqual(self.binding()["certRemoteId"], "new-wildcard")
        self.assertEqual(self.binds, [("cdn.example.com", "new-wildcard")])
        self.assertEqual(self.retired, [])
        self.assertEqual(handler.result["totalSynced"], 1)
        skipped = handler.result["results"][1]["results"][0]
        self.assertTrue(skipped["skipped"])
        self.assertFalse(skipped.get("ok"))

    def test_equal_or_later_expiry_can_replace_an_existing_successful_binding(self):
        self.capture_cloud_binds()
        for expiry in ("2099-01-01T00:00:00Z", "2099-02-01T00:00:00Z"):
            with self.subTest(expiry=expiry):
                self.db.execute("DELETE FROM acceleration_cert_bindings")
                routes._sync_cert_to_edgeone(object(), 1, self.cert("old", "2099-01-01T00:00:00Z"))
                result = routes._sync_cert_to_edgeone(object(), 1, self.cert("incoming", expiry))
                self.assertEqual(result["synced"], 1)
                self.assertEqual(self.binding()["certRemoteId"], "incoming")

    def test_failed_expired_or_unreadable_bindings_do_not_prevent_recovery(self):
        self.capture_cloud_binds()
        cases = [("failed", "2099-02-01T00:00:00Z"), ("synced", "2000-01-01T00:00:00Z"),
                 ("synced", "unreadable")]
        for status, expiry in cases:
            with self.subTest(status=status, expiry=expiry):
                self.db.execute("DELETE FROM acceleration_cert_bindings")
                routes._upsert_accel_cert_binding(1, 3, "zone-a", "cdn.example.com", "acme", "old",
                                                 "old-edge", "", expiry, status, "")
                result = routes._sync_cert_to_edgeone(object(), 1, self.cert("incoming", "2099-01-01T00:00:00Z"))
                self.assertEqual(result["synced"], 1)
                self.assertEqual(self.binding()["certRemoteId"], "incoming")

    def test_preview_reports_newer_binding_as_skipped_without_claiming_sync(self):
        self.capture_cloud_binds()
        routes._upsert_accel_cert_binding(1, 3, "zone-a", "cdn.example.com", "acme", "newer",
                                         "newer-edge", "", "2099-02-01T00:00:00Z", "synced", "")
        result = routes._sync_cert_to_edgeone(object(), 1, self.cert("older", "2099-01-01T00:00:00Z"), dry_run=True)
        self.assertEqual(result["synced"], 0)
        self.assertTrue(result["results"][0]["skipped"])
        self.assertEqual(self.binds, [])


if __name__ == "__main__":
    unittest.main()
