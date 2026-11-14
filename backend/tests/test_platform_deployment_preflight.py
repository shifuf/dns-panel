"""Exercise deployment routes, provider requests and stored outcomes locally."""
from __future__ import annotations

import io
import json
import sqlite3
import sys
import unittest
import urllib.error
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from modules import route_handlers as routes
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class PlatformDeploymentPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.com")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime(2099, 1, 1, tzinfo=timezone.utc))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.example.com"), x509.DNSName("api.other.net")]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.pem = {
            "publicKey": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "privateKey": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
        }

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE ssl_certificates (id INTEGER PRIMARY KEY, userId INTEGER, remoteCertId TEXT, provider TEXT,
                domain TEXT, san TEXT, status TEXT, notAfter TEXT);
            INSERT INTO ssl_certificates VALUES (1, 1, 'panel-cert', 'acme', '*.example.com', '["*.example.com","api.other.net"]', 'issued', '2099-01-01T00:00:00Z');
            CREATE TABLE dns_credentials (id INTEGER PRIMARY KEY, userId INTEGER, provider TEXT, name TEXT, secrets TEXT);
            INSERT INTO dns_credentials VALUES (3, 1, 'qiniu', 'Qiniu test account', '{}');
            CREATE TABLE ssl_platform_deployments (id INTEGER PRIMARY KEY, userId INTEGER, provider TEXT,
                credentialId INTEGER, certRowId INTEGER, certRemoteId TEXT, fingerprint TEXT, domain TEXT,
                platformCertId TEXT, platformCertName TEXT, notBefore TEXT, notAfter TEXT, status TEXT, lastError TEXT,
                uploadedAt TEXT, syncedAt TEXT, createdAt TEXT, updatedAt TEXT,
                UNIQUE(userId, provider, credentialId, domain));
        """)
        self.calls = []
        self.existing_domains = {"cdn.example.com", "api.other.net"}
        self.binding_fails = False
        self.read_error = None
        for target, kwargs in (
            ("modules.route_handlers.conn", {"new": self.connection}),
            ("modules.route_handlers._platform_credential_row", {"return_value": ({"id": 3}, "qiniu", {"accessKey": "ak", "secretKey": "sk"})}),
            ("modules.route_handlers._panel_cert_pem", {"return_value": self.pem}),
            ("modules.qiniu_cdn_api.urllib.request.urlopen", {"side_effect": self.transport}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)

    @contextmanager
    def connection(self):
        with self.db:
            yield self.db

    def transport(self, request, timeout=20):
        path = urllib.parse.unquote(urllib.parse.urlsplit(request.full_url).path)
        self.calls.append((request.method, path))
        if request.method == "GET" and path.startswith("/domain/"):
            if self.read_error:
                status, code, detail = self.read_error
                self.raise_http(request.full_url, status, code, detail)
            domain = path.removeprefix("/domain/")
            if domain not in self.existing_domains:
                self.raise_http(request.full_url, 404, 404001, "无此域名")
            response = {"name": domain, "protocol": "https", "https": {"certId": "old-cert", "forceHttps": True}}
        elif request.method == "POST" and path == "/sslcert":
            response = {"certID": "uploaded-cert"}
        elif request.method == "PUT" and path.endswith("/httpsconf"):
            if self.binding_fails:
                self.raise_http(request.full_url, 400, 400030, "域名正在处理中")
            response = {"code": 200}
        else:
            raise AssertionError(f"Unexpected request: {request.method} {path}")
        return io.BytesIO(json.dumps(response).encode())

    def raise_http(self, url, status, code, detail):
        error = urllib.error.HTTPError(url, status, detail, {}, io.BytesIO(json.dumps({"code": code, "error": detail}).encode()))
        self.addCleanup(error.close)
        raise error

    def deploy(self, domains):
        handler = app.H.__new__(app.H)
        handler.command = "POST"
        handler._auth = lambda: {"id": 1}
        handler._ok = lambda data, message="", code=200: setattr(handler, "result", (code, data, message))
        handler._err = lambda message, code=400: setattr(handler, "result", (code, {}, message))
        body = {"provider": "qiniu", "credentialId": 3, "certRowId": 1, "domains": domains}
        routes._ssl_routes(handler, "/api/ssl/platform-deployments", {}, json.dumps(body).encode())
        return handler.result

    def check(self):
        handler = app.H.__new__(app.H)
        handler.command = "POST"
        handler._auth = lambda: {"id": 1}
        handler._get_credential_row = lambda *args: {"id": 3, "provider": "qiniu"}
        handler._credential_secrets = lambda row: {"accessKey": "ak", "secretKey": "sk"}
        handler._ok = lambda data, message="", code=200: setattr(handler, "result", (code, data, message))
        handler._err = lambda message, code=400: setattr(handler, "result", (code, {}, message))
        routes._ssl_routes(handler, "/api/ssl/platform-deployments/check", {}, b"{}")
        return handler.result

    def record_failed_deployment(self, domain):
        self.db.execute("""INSERT INTO ssl_platform_deployments
            (userId,provider,credentialId,domain,platformCertId,status,lastError)
            VALUES (1,'qiniu',3,?,'uploaded-cert','failed','bad token')""", (domain,))
        self.db.commit()

    def test_wildcard_certificate_can_deploy_to_existing_single_level_host(self):
        status, result, _ = self.deploy(["cdn.example.com"])
        self.assertEqual(status, 201)
        self.assertEqual(result["results"], [{"domain": "cdn.example.com", "ok": True}])
        self.assertEqual(self.calls[0], ("GET", "/domain/cdn.example.com"))
        row = self.db.execute("SELECT * FROM ssl_platform_deployments").fetchone()
        self.assertEqual(row["status"], "synced")

    def test_exact_san_can_deploy(self):
        self.assertEqual(self.deploy(["api.other.net"])[0], 201)

    def test_wildcard_does_not_cover_apex_or_multiple_labels(self):
        for domain in ("example.com", "cdn.oss.example.com"):
            with self.subTest(domain=domain):
                self.assertEqual(self.deploy([domain])[0], 400)
        self.assertEqual(self.calls, [])

    def test_invalid_domain_is_rejected_before_provider_calls(self):
        for domain in ("https://cdn.example.com", "cdn.example.com/path", "cdn.example.com:443", "bad_label.example.com", "*.*.example.com"):
            with self.subTest(domain=domain):
                self.assertEqual(self.deploy([domain])[0], 400)
        self.assertEqual(self.calls, [])

    def test_missing_wildcard_target_fails_before_certificate_upload(self):
        status, _, message = self.deploy(["*.example.com"])
        self.assertEqual(status, 404)
        self.assertIn("未接入", message)
        self.assertEqual(self.calls, [("GET", "/domain/*.example.com")])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM ssl_platform_deployments").fetchone()[0], 0)

    def test_all_targets_are_preflighted_before_upload(self):
        status, _, _ = self.deploy(["api.other.net", "*.example.com"])
        self.assertEqual(status, 404)
        self.assertTrue(self.calls)
        self.assertTrue(all(method == "GET" for method, _ in self.calls))

    def test_existing_wildcard_target_is_allowed(self):
        self.existing_domains.add("*.example.com")
        status, result, _ = self.deploy(["*.example.com"])
        self.assertEqual(status, 201)
        self.assertTrue(result["results"][0]["ok"])
        self.assertEqual(self.calls[0], ("GET", "/domain/*.example.com"))

    def test_existing_provider_dot_wildcard_target_is_preserved(self):
        self.existing_domains.add(".example.com")
        self.assertEqual(self.deploy([".example.com"])[0], 201)
        self.assertEqual(self.calls[0], ("GET", "/domain/.example.com"))
        self.calls.clear()
        status, result, _ = self.check()
        self.assertEqual(status, 200)
        self.assertTrue(result["checks"][0]["live"]["bound"])
        self.assertEqual(self.calls, [("GET", "/domain/.example.com")])

    def test_real_time_check_explains_missing_target_without_cloud_writes(self):
        self.record_failed_deployment("*.example.com")
        status, result, _ = self.check()
        self.assertEqual(status, 200)
        check = result["checks"][0]
        self.assertTrue(check["checked"])
        self.assertFalse(check["live"]["bound"])
        self.assertFalse(check["live"]["domainExists"])
        self.assertIn("未接入", check["live"]["error"])
        self.assertEqual(self.calls, [("GET", "/domain/*.example.com")])

    def test_real_time_auth_error_remains_a_failed_check(self):
        self.record_failed_deployment("api.other.net")
        self.read_error = (401, 401001, "bad token")
        status, result, _ = self.check()
        self.assertEqual(status, 200)
        self.assertFalse(result["checks"][0]["checked"])
        self.assertIn("bad token", result["checks"][0]["error"])
        self.assertEqual(self.calls, [("GET", "/domain/api.other.net")])

    def test_auth_failure_does_not_upload_or_claim_unbound(self):
        self.read_error = (401, 401001, "bad token")
        status, _, message = self.deploy(["api.other.net"])
        self.assertEqual(status, 401)
        self.assertIn("bad token", message)
        self.assertTrue(all(method == "GET" for method, _ in self.calls))

    def test_uploaded_certificate_and_failed_binding_remain_distinguishable(self):
        self.binding_fails = True
        status, result, message = self.deploy(["api.other.net"])
        self.assertEqual(status, 201)
        self.assertEqual(result["platformCertId"], "uploaded-cert")
        self.assertFalse(result["results"][0]["ok"])
        self.assertIn("0/1", message)
        row = self.db.execute("SELECT * FROM ssl_platform_deployments").fetchone()
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["platformCertId"], "uploaded-cert")
        self.assertTrue(row["uploadedAt"])
        self.assertIsNone(row["syncedAt"])
        _, current, _ = self.check()
        self.assertTrue(current["checks"][0]["live"]["bound"])
        self.assertTrue(current["checks"][0]["drift"])


if __name__ == "__main__":
    unittest.main()
