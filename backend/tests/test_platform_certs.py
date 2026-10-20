"""Tests for the third-party platform (七牛云 / 又拍云) certificate upload."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.qiniu_cdn_api import QiniuCdnApi, QiniuApiError, _qbox_sign  # noqa: E402
from modules.upyun_console_api import (  # noqa: E402
    UpyunConsoleApi, UpyunConsoleError, upyun_validity_ms_to_iso,
)
from modules import route_handlers  # noqa: E402


class QiniuSignTests(unittest.TestCase):
    def test_sign_matches_hmac_sha1_urlsafe(self) -> None:
        data = b"/sslcert\n{\"name\":\"x\"}"
        expected = base64.urlsafe_b64encode(
            hmac.new(b"secret", data, hashlib.sha1).digest()
        ).decode()
        self.assertEqual(_qbox_sign("secret", data), expected)

    def test_missing_keys_raise(self) -> None:
        with self.assertRaises(QiniuApiError):
            QiniuCdnApi("", "")


class QiniuRequestTests(unittest.TestCase):
    def _run(self, payload: dict, status: int = 200) -> dict:
        api = QiniuCdnApi("ak", "sk")
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps(payload).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        with patch("modules.qiniu_cdn_api.urllib.request.urlopen", return_value=fake_resp) as m:
            result = api._request("fusion.qiniuapi.com", "POST", "/sslcert", {"name": "x"})
            req = m.call_args[0][0]
            self.assertEqual(req.get_header("Authorization").startswith("QBox ak:"), True)
            self.assertEqual(req.method, "POST")
        return result

    def test_upload_response(self) -> None:
        out = self._run({"certID": "abc123"})
        self.assertEqual(out["certID"], "abc123")

    def test_business_error_code_raises(self) -> None:
        with self.assertRaises(QiniuApiError):
            self._run({"code": 400325, "error": "https证书解析失败"})

    def test_upload_cert_requires_pems(self) -> None:
        api = QiniuCdnApi("ak", "sk")
        with self.assertRaises(QiniuApiError):
            api.upload_cert("n", "", "")


class UpyunConsoleTests(unittest.TestCase):
    def test_extract_cert_id_shapes(self) -> None:
        self.assertEqual(UpyunConsoleApi._extract_cert_id({"data": {"certificate_id": "a"}}), "a")
        self.assertEqual(UpyunConsoleApi._extract_cert_id({"certificateId": "b"}), "b")
        self.assertEqual(UpyunConsoleApi._extract_cert_id({"data": {"id": "c"}}), "c")
        self.assertEqual(UpyunConsoleApi._extract_cert_id({"data": {}}), "")

    def test_ok_error_detection(self) -> None:
        self.assertFalse(UpyunConsoleApi._ok({"data": {"status": False}}))
        self.assertFalse(UpyunConsoleApi._ok({"msg": {"errors": ["bad"]}}))
        self.assertTrue(UpyunConsoleApi._ok({"data": {"status": True}}))
        self.assertTrue(UpyunConsoleApi._ok({}))

    def test_validity_ms(self) -> None:
        self.assertEqual(upyun_validity_ms_to_iso(0), "")
        self.assertEqual(upyun_validity_ms_to_iso(1766660462000), "2025-12-25T11:01:02Z")

    def test_login_requires_cookies(self) -> None:
        api = UpyunConsoleApi.__new__(UpyunConsoleApi)
        api.username = "u"
        api.password = "p"
        api.timeout = 5
        import http.cookiejar
        api._jar = http.cookiejar.CookieJar()
        api._opener = MagicMock()
        api._logged_in = False
        fake_resp = MagicMock()
        fake_resp.read.return_value = json.dumps({"msg": {"errors": []}}).encode()
        fake_resp.__enter__ = MagicMock(return_value=fake_resp)
        fake_resp.__exit__ = MagicMock(return_value=False)
        api._opener.open.return_value = fake_resp
        with self.assertRaises(UpyunConsoleError):
            api.login()

    def test_upload_failure_raises(self) -> None:
        api = UpyunConsoleApi.__new__(UpyunConsoleApi)
        api.username = "u"
        api.password = "p"
        api._logged_in = True
        with patch.object(UpyunConsoleApi, "_request", return_value={"data": {"status": False}, "msg": {"errors": ["格式错误"]}}):
            with self.assertRaises(UpyunConsoleError):
                api.upload_cert("CERT", "KEY")


class PlatformRouteSourceTests(unittest.TestCase):
    """The auto-renew hook and endpoints must be wired into the SSL routes."""

    def setUp(self) -> None:
        self.source = Path(BACKEND_DIR / "modules" / "route_handlers.py").read_text(encoding="utf-8-sig")

    def test_acme_success_hook_calls_platform_sync(self) -> None:
        self.assertIn("_sync_cert_to_platforms(self, uid, fresh)", self.source)

    def test_upload_endpoint_hook(self) -> None:
        self.assertIn("手动上传替换的新证书同步到已部署过的第三方平台", self.source)

    def test_endpoints_registered(self) -> None:
        for needle in (
            'sub in ("/platform-credentials", "/platform-credentials/")',
            'sub in ("/platform-deployments", "/platform-deployments/")',
            'r"/platform-deployments/(\\d+)"',
        ):
            self.assertIn(needle, self.source)

    def test_provider_catalog_has_cert_upload(self) -> None:
        from modules.provider_catalog import get_supported_provider_types_by_category
        self.assertEqual(get_supported_provider_types_by_category("cert_upload"), ("qiniu", "upyun"))

    def test_migration_creates_platform_table(self) -> None:
        import sqlite3
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "t.db")
            import migrate as db_migrate
            db_migrate.migrate(db_migrate.normalize_db_path(db))
            conn = sqlite3.connect(db)
            names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ssl_platform_deployments'")]
            conn.close()
            self.assertEqual(names, ["ssl_platform_deployments"])


if __name__ == "__main__":
    unittest.main()
