"""Qiniu wire-protocol regressions; all HTTP calls are intercepted locally."""
from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.qiniu_cdn_api import QiniuApiError, QiniuCdnApi  # noqa: E402


class QiniuRequestProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = QiniuCdnApi("ak", "sk")

    def test_upload_json_uses_qbox_path_signature_and_sends_pems(self) -> None:
        # Auth.token_of_request in the official Python SDK excludes JSON bodies.
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(b'{"certID":"new-cert"}')) as send:
            result = self.api.upload_cert("example", "CERTIFICATE", "PRIVATE KEY", "example.com")

        request = send.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "QBox ak:yYkziIwMbCQ4EXTzx2KJf-YV7to=")
        self.assertEqual(request.full_url, "https://fusion.qiniuapi.com/sslcert")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(request.data), {
            "name": "example", "ca": "CERTIFICATE", "pri": "PRIVATE KEY", "common_name": "example.com",
        })
        self.assertEqual(result["certID"], "new-cert")

    def test_binding_json_uses_qiniu_content_signature(self) -> None:
        responses = [io.BytesIO(b'{"protocol":"https","https":{"certId":"old-cert"}}'), io.BytesIO(b'{"code":200}')]
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=responses) as send, patch("modules.qiniu_cdn_api.datetime", create=True) as clock:
            clock.now.return_value = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)
            self.api.bind_domain("cdn.example.com", "new-cert", force_https=True)

        request = send.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Qiniu ak:KielWpxN8W-8zQlPQpCUUGT3LN8=")
        self.assertEqual(request.get_header("X-qiniu-date"), "20261114T120000Z")
        self.assertEqual(request.full_url, "https://api.qiniu.com/domain/cdn.example.com/httpsconf")
        self.assertEqual(request.method, "PUT")
        self.assertEqual(request.data, b'{"certId":"new-cert","forceHttps":true}')

    def test_domain_get_signs_qiniu_host_date_and_encoded_query(self) -> None:
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(b'{"domains":[]}')) as send, patch("modules.qiniu_cdn_api.datetime", create=True) as clock:
            clock.now.return_value = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)
            self.api._request(self.api.cdn_host, "GET", "/domain", query={"limit": 2, "marker": "a+b/="})

        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.qiniu.com/domain?limit=2&marker=a%2Bb%2F%3D")
        self.assertEqual(request.get_header("Authorization"), "Qiniu ak:G1oP0nbuj5A7Z8_yEYYsY9GdwD0=")
        self.assertIsNone(request.get_header("Content-type"))
        self.assertIsNone(request.data)

    def test_query_string_is_signed_as_transmitted(self) -> None:
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(b'{"certs":[]}')) as send:
            self.api._request(self.api.cert_host, "GET", "/sslcert", query={"limit": 2, "marker": "a+b/=", "unused": None})

        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://fusion.qiniuapi.com/sslcert?limit=2&marker=a%2Bb%2F%3D")
        self.assertEqual(request.get_header("Authorization"), "QBox ak:zLmiy0diS-2nwVg3jNHQamYoUWY=")
        self.assertIsNone(request.data)

    def test_plain_text_http_error_preserves_provider_detail(self) -> None:
        error = urllib.error.HTTPError("https://fusion.qiniuapi.com/sslcert", 401, "Unauthorized", {}, io.BytesIO(b"bad token: invalid signature"))
        self.addCleanup(error.close)
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=error):
            with self.assertRaises(QiniuApiError) as raised:
                self.api.list_certs()

        self.assertEqual(raised.exception.status, 401)
        self.assertIn("bad token: invalid signature", str(raised.exception))


class QiniuDomainProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = QiniuCdnApi("ak", "sk")

    def test_binding_status_reads_domain_detail_endpoint(self) -> None:
        payload = {"name": "cdn.example.com", "protocol": "https", "https": {"certId": "active-cert", "forceHttps": True}}
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())) as send:
            status = self.api.get_binding_status("cdn.example.com")

        self.assertEqual(send.call_args.args[0].full_url, "https://api.qiniu.com/domain/cdn.example.com")
        self.assertTrue(status["bound"])
        self.assertEqual(status["certificateId"], "active-cert")
        self.assertTrue(status["forceHttps"])

    def test_wildcard_status_keeps_literal_star_in_signed_request_path(self) -> None:
        error = urllib.error.HTTPError("https://api.qiniu.com/domain/*.example.com", 404, "Not Found", {}, io.BytesIO(json.dumps({"code": 404001, "error": "无此域名"}).encode()))
        self.addCleanup(error.close)
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=error) as send, patch("modules.qiniu_cdn_api.datetime") as clock:
            clock.now.return_value = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)
            status = self.api.get_binding_status("*.example.com")

        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.qiniu.com/domain/*.example.com")
        self.assertEqual(request.get_header("Authorization"), "Qiniu ak:RAFqBOy_kgKMO_y1-F63CVWEXGs=")
        self.assertFalse(status["bound"])
        self.assertFalse(status["domainExists"])
        self.assertIn("CDN", status["error"])
        self.assertIn("未接入", status["error"])

    def test_provider_wildcard_name_keeps_leading_dot(self) -> None:
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(b'{"name":".example.com","protocol":"https","https":{"certId":"active-cert"}}')) as send:
            status = self.api.get_binding_status(".example.com")
        self.assertEqual(send.call_args.args[0].full_url, "https://api.qiniu.com/domain/.example.com")
        self.assertTrue(status["bound"])

    def test_http_domain_with_old_certificate_config_is_not_bound(self) -> None:
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(b'{"protocol":"http","https":{"certId":"old-cert"}}')):
            status = self.api.get_binding_status("cdn.example.com")
        self.assertFalse(status["bound"])

    def test_http3_does_not_imply_force_https(self) -> None:
        payload = {"protocol": "https", "https": {"certId": "active-cert", "forceHttps": False, "http3Enabled": True}}
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
            status = self.api.get_binding_status("cdn.example.com")
        self.assertFalse(status["forceHttps"])

    def test_domains_follow_server_marker_even_with_short_page(self) -> None:
        pages = [
            {"domains": [{"name": "one.example.com"}], "marker": "next+/="},
            {"domains": [{"name": "two.example.com"}], "marker": ""},
        ]
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=[io.BytesIO(json.dumps(page).encode()) for page in pages]) as send:
            domains = self.api.list_domains(limit=2)

        self.assertEqual([item["name"] for item in domains], ["one.example.com", "two.example.com"])
        self.assertEqual([call.args[0].full_url for call in send.call_args_list], [
            "https://api.qiniu.com/domain?limit=2",
            "https://api.qiniu.com/domain?limit=2&marker=next%2B%2F%3D",
        ])

    def test_http_domain_is_upgraded_when_binding_first_certificate(self) -> None:
        responses = [io.BytesIO(b'{"protocol":"http","https":{}}'), io.BytesIO(b'{"code":200}')]
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=responses) as send:
            result = self.api.bind_domain("cdn.example.com", "new-cert")

        self.assertEqual([call.args[0].method for call in send.call_args_list], ["GET", "PUT"])
        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.qiniu.com/domain/cdn.example.com/sslize")
        self.assertEqual(json.loads(request.data), {"certId": "new-cert", "forceHttps": False, "http2Enable": False})
        self.assertEqual(result, {"code": 200})

    def test_certificate_renewal_preserves_force_https_without_overwriting_other_settings(self) -> None:
        config = {"protocol": "https", "https": {
            "certId": "old-cert", "forceHttps": True, "http2Enable": True, "tlsVersions": "TLSv1.2/TLSv1.3",
        }}
        responses = [io.BytesIO(json.dumps(config).encode()), io.BytesIO(b'{"code":200}')]
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=responses) as send:
            self.api.bind_domain("cdn.example.com", "renewed-cert")

        request = send.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.qiniu.com/domain/cdn.example.com/httpsconf")
        self.assertEqual(json.loads(request.data), {"certId": "renewed-cert", "forceHttps": True})

    def test_explicit_false_can_disable_existing_force_https(self) -> None:
        responses = [io.BytesIO(b'{"protocol":"https","https":{"forceHttps":true,"http2Enable":true}}'), io.BytesIO(b'{"code":200}')]
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=responses) as send:
            self.api.bind_domain("cdn.example.com", "renewed-cert", force_https=False)

        self.assertEqual(json.loads(send.call_args.args[0].data), {"certId": "renewed-cert", "forceHttps": False})

    def test_forbidden_status_query_is_reported_as_error(self) -> None:
        error = urllib.error.HTTPError("https://api.qiniu.com/domain/cdn.example.com", 403, "Forbidden", {}, io.BytesIO(b'{"error":"forbidden","code":403024}'))
        self.addCleanup(error.close)
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=error):
            with self.assertRaises(QiniuApiError) as raised:
                self.api.get_binding_status("cdn.example.com")
        self.assertEqual(raised.exception.code, 403024)

    def test_missing_access_key_is_not_mistaken_for_missing_domain(self) -> None:
        error = urllib.error.HTTPError("https://api.qiniu.com/domain/cdn.example.com", 401, "Unauthorized", {}, io.BytesIO(b'{"error":"access key not found","code":401001}'))
        self.addCleanup(error.close)
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=error):
            with self.assertRaises(QiniuApiError) as raised:
                self.api.get_binding_status("cdn.example.com")
        self.assertEqual(raised.exception.status, 401)

    def test_domain_not_found_code_returns_unbound(self) -> None:
        error = urllib.error.HTTPError("https://api.qiniu.com/domain/cdn.example.com", 404, "Not Found", {}, io.BytesIO(json.dumps({"error": "域名不存在", "code": 404001}).encode()))
        self.addCleanup(error.close)
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", side_effect=error):
            status = self.api.get_binding_status("cdn.example.com")
        self.assertFalse(status["bound"])


if __name__ == "__main__":
    unittest.main()
