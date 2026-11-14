"""Upyun renewal regressions; console HTTP requests stay local."""
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.upyun_console_api import UpyunConsoleApi, UpyunConsoleError  # noqa: E402


DOMAIN = "cdn.example.com"
SUCCESS = {"data": {"status": True}, "msg": {"errors": [], "messages": []}}
CONFLICT = {"data": {
    "type": "YouHaveBindThisDomainsToACertificate", "error_code": 21713,
    "message": "domain already bound",
}, "msg": {"errors": [], "messages": []}, "user": {"email": "private@example.com"}}


def certificate_list(*cert_ids: str) -> dict:
    return {"data": {"status": 0, "result": [
        {"certificate_id": cert_id, "commonName": "*.example.com", "crt_type": "custom",
         "payment_type": "free", "brand": "", "domain_type": "", "crt_type_pay": "",
         "pro": False, "organization": "", "gm": False,
         "validity": {"start": 1766660462000, "end": 1800000000000 if cert_id == "new" else 1790000000000}}
        for cert_id in cert_ids
    ]}, "msg": {"errors": [], "messages": []}}


def certificate_detail(*domains: dict) -> dict:
    return {"data": {"authenticate_num": 1, "authenticate_domain": ["*.example.com"],
                     "domains": list(domains)}, "msg": {"errors": [], "messages": []}}


def domain_config(name: str = DOMAIN, **config) -> dict:
    return {"name": name, "type": "file", "bucket_id": 123, "bucket_name": "example", **config}


def active_certificate_list(force_https: bool = False) -> dict:
    payload = certificate_list("old")
    payload["data"]["result"][0].update(https=True, force_https=force_https)
    return payload


class UpyunBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "*.example.com")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime.fromtimestamp(1800000000, tz=timezone.utc))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("*.example.com")]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.pem = {
            "publicKey": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "privateKey": key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
            ).decode(),
        }

    def setUp(self) -> None:
        self.api = UpyunConsoleApi("user", "password", auto_login=False)
        self.api._logged_in = True
        self.old_detail = certificate_detail(domain_config(https=True, force_https=False, source_https=False))
        self.new_detail = certificate_detail(domain_config())

    def responses(self, *payloads: dict):
        return patch.object(self.api._opener, "open", side_effect=[
            io.BytesIO(json.dumps(payload).encode()) for payload in payloads
        ])

    def test_status_selects_active_certificate_instead_of_newest_candidate(self) -> None:
        with self.responses(certificate_list("new", "old"), self.new_detail, self.old_detail):
            status = self.api.get_binding_status(DOMAIN)
        self.assertTrue(status["bound"])
        self.assertTrue(status["https"])
        self.assertEqual(status["certificateId"], "old")
        self.assertEqual(status["notAfter"], "2026-09-21T14:13:20Z")

    def test_candidate_without_enabled_https_is_unbound(self) -> None:
        with self.responses(certificate_list("new"), self.new_detail):
            status = self.api.get_binding_status(DOMAIN)
        self.assertFalse(status["bound"])
        self.assertFalse(status["https"])

    def test_https_enabled_for_another_domain_is_not_current_domain_binding(self) -> None:
        detail = certificate_detail(domain_config(), domain_config("other.example.com", https=True))
        with self.responses(certificate_list("new"), detail):
            status = self.api.get_binding_status(DOMAIN)
        self.assertFalse(status["bound"])

    def test_explicit_active_flag_avoids_rate_limited_detail_requests(self) -> None:
        payload = certificate_list("new", "old")
        payload["data"]["result"][0].update(https=False, force_https=False)
        payload["data"]["result"][1].update(https=True, force_https=True)
        with self.responses(payload, self.new_detail, self.old_detail) as send:
            status = self.api.get_binding_status(DOMAIN)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(status["certificateId"], "old")
        self.assertTrue(status["forceHttps"])

    def test_explicit_disabled_flag_does_not_query_certificate_detail(self) -> None:
        payload = certificate_list("new")
        payload["data"]["result"][0]["https"] = False
        with self.responses(payload, self.new_detail) as send:
            status = self.api.get_binding_status(DOMAIN)
        self.assertEqual(send.call_count, 1)
        self.assertFalse(status["bound"])

    def test_single_domain_renewal_migrates_old_certificate(self) -> None:
        with self.responses(active_certificate_list(), self.old_detail, SUCCESS) as send:
            result = self.api.bind_domain(DOMAIN, "new")
        self.assertEqual(send.call_count, 3)
        request = send.call_args.args[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.full_url, "https://console.upyun.com/api/https/migrate/certificate")
        self.assertEqual(json.loads(request.data), {"old_crt_id": "old", "new_crt_id": "new"})
        self.assertTrue(self.api._ok(result))

    def test_renewal_preserves_existing_force_https_configuration(self) -> None:
        detail = certificate_detail(domain_config(https=True, force_https=True, source_https=True))
        with self.responses(active_certificate_list(force_https=True), detail, SUCCESS) as send:
            result = self.api.bind_domain(DOMAIN, "new")
        writes = [call.args[0] for call in send.call_args_list if call.args[0].method == "POST"]
        self.assertEqual([json.loads(request.data) for request in writes], [
            {"old_crt_id": "old", "new_crt_id": "new"},
        ])
        self.assertTrue(self.api._ok(result))

    def test_renewal_refuses_to_migrate_another_bound_domain(self) -> None:
        detail = certificate_detail(
            domain_config(https=True, force_https=False),
            domain_config("other.example.com", https=True, force_https=True),
        )
        with self.responses(active_certificate_list(), detail) as send:
            with self.assertRaises(UpyunConsoleError) as raised:
                self.api.bind_domain(DOMAIN, "new")
        self.assertIn("批量", str(raised.exception))
        self.assertTrue(raised.exception.need_manual)
        self.assertTrue(all(call.args[0].method == "GET" for call in send.call_args_list))

    def test_missing_old_domain_inventory_refuses_migration(self) -> None:
        with self.responses(active_certificate_list(), {"data": {}}) as send:
            with self.assertRaises(UpyunConsoleError):
                self.api.bind_domain(DOMAIN, "new")
        self.assertTrue(all(call.args[0].method == "GET" for call in send.call_args_list))

    def test_migration_failure_is_reported_without_account_data(self) -> None:
        failure = {"data": {"type": "MigrationFailed", "error_code": 21799, "message": "migration failed"},
                   "msg": {"errors": []}, "user": {"email": "private@example.com"}}
        with self.responses(active_certificate_list(), self.old_detail, failure):
            with self.assertRaises(UpyunConsoleError) as raised:
                self.api.bind_domain(DOMAIN, "new")
        self.assertIn("MigrationFailed", str(raised.exception))
        self.assertNotIn("private@example.com", str(raised.exception))

    def test_binding_current_certificate_is_idempotent(self) -> None:
        with self.responses(active_certificate_list()) as send:
            result = self.api.bind_domain(DOMAIN, "old")
        self.assertTrue(self.api._ok(result))
        self.assertTrue(all(call.args[0].method == "GET" for call in send.call_args_list))

    def test_first_binding_keeps_original_request(self) -> None:
        with self.responses(certificate_list("new"), self.new_detail, SUCCESS) as send:
            result = self.api.bind_domain(DOMAIN, "new", force_https=True)
        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://console.upyun.com/api/https/certificate/manager")
        self.assertEqual(json.loads(request.data), {
            "certificate_id": "new", "domain": DOMAIN, "https": True, "force_https": True,
        })
        self.assertTrue(self.api._ok(result))

    def test_conflict_refreshes_binding_before_safe_migration(self) -> None:
        with self.responses(
            certificate_list(), CONFLICT, active_certificate_list(), self.old_detail, SUCCESS,
        ) as send:
            result = self.api.bind_domain(DOMAIN, "new")
        writes = [call.args[0] for call in send.call_args_list if call.args[0].method == "POST"]
        self.assertEqual([request.full_url for request in writes], [
            "https://console.upyun.com/api/https/certificate/manager",
            "https://console.upyun.com/api/https/migrate/certificate",
        ])
        self.assertTrue(self.api._ok(result))

    def test_upload_id_fallback_and_bind_share_one_list_request_then_read_new_binding(self) -> None:
        from modules import route_handlers as routes

        calls = []
        migrated = False
        listing_reads = 0

        def transport(request, timeout=20):
            nonlocal migrated, listing_reads
            path = urllib.parse.urlsplit(request.full_url).path
            calls.append((request.method, path))
            if request.method == "POST" and path == "/api/https/certificate/":
                # Successful console upload may return metadata without a certificate ID.
                response = {"data": {"status": 0, "result": {
                    "commonName": "*.example.com", "san": {"dns": ["*.example.com"]},
                    "validity": {"start": 1767225600000, "end": 1800000000000},
                }}, "msg": {"errors": [], "messages": []}}
            elif request.method == "GET" and path == "/api/https/services/manager":
                listing_reads += 1
                if listing_reads > 1 and not migrated:
                    response = {"data": {"type": "RepeatCallInterface", "error_code": 21000,
                                         "message": "request repeated too quickly"}, "msg": {"errors": []}}
                else:
                    response = certificate_list("old", "new")
                    response["data"]["result"][0].update(https=not migrated, force_https=False)
                    response["data"]["result"][1].update(https=migrated, force_https=False)
            elif request.method == "GET" and path == "/api/https/certificate/manager":
                response = self.old_detail
            elif request.method == "POST" and path == "/api/https/migrate/certificate":
                self.assertEqual(json.loads(request.data), {"old_crt_id": "old", "new_crt_id": "new"})
                migrated = True
                response = SUCCESS
            else:
                raise AssertionError(f"Unexpected request: {request.method} {path}")
            return io.BytesIO(json.dumps(response).encode())

        with patch.object(self.api._opener, "open", side_effect=transport), \
                patch.object(routes, "_build_platform_api", return_value=self.api), \
                patch.object(routes, "_upsert_platform_deployment"), \
                patch("modules.upyun_console_api.time.monotonic", return_value=100):
            result = routes._deploy_pem_to_platform(
                object(), 1, "upyun", {"id": 3}, {},
                {"id": 1, "remoteCertId": "panel-cert", "domain": "*.example.com", "san": "[]"},
                self.pem, [DOMAIN],
            )
            self.assertEqual(result["results"], [{"domain": DOMAIN, "ok": True}])
            self.assertEqual(result["platformCertId"], "new")
            self.assertEqual(listing_reads, 1)
            self.assertTrue(migrated)
            status = self.api.get_binding_status(DOMAIN)
        self.assertEqual(status["certificateId"], "new")
        self.assertEqual(listing_reads, 2)

    def test_domain_list_cache_expires_after_two_seconds(self) -> None:
        new = certificate_list("new")
        new["data"]["result"][0]["https"] = True
        with self.responses(active_certificate_list(), new) as send, \
                patch("modules.upyun_console_api.time.monotonic", return_value=100) as clock:
            self.assertEqual(self.api.get_binding_status(DOMAIN)["certificateId"], "old")
            clock.return_value = 101.9
            self.assertEqual(self.api.get_binding_status(DOMAIN)["certificateId"], "old")
            self.assertEqual(send.call_count, 1)
            clock.return_value = 102
            self.assertEqual(self.api.get_binding_status(DOMAIN)["certificateId"], "new")
        self.assertEqual(send.call_count, 2)

    def test_every_certificate_write_invalidates_cached_domain_state(self) -> None:
        for operation in ("upload", "bind", "migrate", "unbind"):
            with self.subTest(operation=operation):
                self.api = UpyunConsoleApi("user", "password", auto_login=False)
                self.api._logged_in = True
                before = certificate_list() if operation == "bind" else active_certificate_list()
                after = certificate_list() if operation == "unbind" else certificate_list("new")
                with self.responses(before, SUCCESS, after) as send, \
                        patch("modules.upyun_console_api.time.monotonic", return_value=100):
                    self.api.get_domain_cert(DOMAIN)
                    if operation == "upload":
                        self.api.upload_cert(self.pem["publicKey"], self.pem["privateKey"])
                    elif operation == "bind":
                        self.api.bind_domain(DOMAIN, "new")
                    elif operation == "migrate":
                        self.api.migrate_cert("old", "new")
                    else:
                        self.api.unbind_domain(DOMAIN)
                    current = self.api.get_domain_cert(DOMAIN)
                self.assertEqual(current["data"]["result"], after["data"]["result"])
                self.assertEqual([call.args[0].method for call in send.call_args_list], ["GET", "POST", "GET"])

    def test_failed_write_also_invalidates_cache_before_followup_check(self) -> None:
        failure = {"data": {"type": "MigrationFailed", "error_code": 21799}, "msg": {"errors": []}}
        after = certificate_list("new")
        with self.responses(active_certificate_list(), failure, after) as send, \
                patch("modules.upyun_console_api.time.monotonic", return_value=100):
            self.api.get_domain_cert(DOMAIN)
            migrated, _ = self.api.migrate_cert("old", "new")
            current = self.api.get_domain_cert(DOMAIN)
        self.assertFalse(migrated)
        self.assertEqual(current["data"]["result"][0]["certificate_id"], "new")
        self.assertEqual(send.call_count, 3)

    def test_failed_domain_query_is_not_cached(self) -> None:
        failure = {"data": {"type": "RepeatCallInterface", "error_code": 21000}, "msg": {"errors": []}}
        with self.responses(failure, active_certificate_list()) as send, \
                patch("modules.upyun_console_api.time.monotonic", return_value=100):
            self.assertFalse(self.api._ok(self.api.get_domain_cert(DOMAIN)))
            current = self.api.get_binding_status(DOMAIN)
        self.assertEqual(current["certificateId"], "old")
        self.assertEqual(send.call_count, 2)

    def test_cache_separates_domains_and_normalizes_equivalent_domain_names(self) -> None:
        with self.responses(active_certificate_list(), certificate_list()) as send, \
                patch("modules.upyun_console_api.time.monotonic", return_value=100):
            self.api.get_domain_cert(DOMAIN)
            other = self.api.get_binding_status("other.example.com")
            current = self.api.get_binding_status(" CDN.EXAMPLE.COM. ")
        self.assertFalse(other["bound"])
        self.assertEqual(current["certificateId"], "old")
        self.assertEqual(send.call_count, 2)

    def test_cache_is_not_shared_between_account_clients(self) -> None:
        other_api = UpyunConsoleApi("other-user", "other-password", auto_login=False)
        other_api._logged_in = True
        with self.responses(active_certificate_list()), \
                patch.object(other_api._opener, "open", return_value=io.BytesIO(json.dumps(certificate_list()).encode())) as send, \
                patch("modules.upyun_console_api.time.monotonic", return_value=100):
            self.api.get_domain_cert(DOMAIN)
            current = other_api.get_binding_status(DOMAIN)
        self.assertFalse(current["bound"])
        self.assertEqual(send.call_count, 1)


if __name__ == "__main__":
    unittest.main()
