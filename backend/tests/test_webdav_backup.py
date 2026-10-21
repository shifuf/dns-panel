"""Tests for WebDAV backup settings, helpers, and route wiring."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

APP = Path(BACKEND_DIR / "app.py").read_text(encoding="utf-8-sig")
ROUTES = Path(BACKEND_DIR / "modules" / "route_handlers.py").read_text(encoding="utf-8-sig")


class WebdavSourceTests(unittest.TestCase):
    def test_helpers_exist(self) -> None:
        for fn in (
            "def get_backup_webdav_settings",
            "def upload_backup_to_webdav",
            "def list_webdav_backups",
            "def fetch_webdav_backup",
            "def run_webdav_full_backup",
            "def _backup_webdav_worker",
        ):
            self.assertIn(fn, APP)

    def test_worker_started(self) -> None:
        self.assertIn("target=_backup_webdav_worker", APP)

    def test_settings_payload_exposes_webdav(self) -> None:
        self.assertIn("backupWebdavEnabled", APP)
        self.assertIn("backupWebdavAutoHour", APP)
        self.assertIn("backupWebdavLastResult", APP)
        # password is never included in the payload (only hasPassword)
        self.assertNotIn('"backupWebdavPassword":', APP.split("def system_settings_payload")[1].split("def ")[1])

    def test_routes_exist(self) -> None:
        for route in (
            '"/backup/webdav/test"',
            '"/backup/webdav/sync"',
            '"/backup/webdav/list"',
            '"/backup/webdav/restore"',
            '"/backup/webdav/status"',
        ):
            self.assertIn(route, ROUTES)

    def test_settings_put_accepts_webdav_fields(self) -> None:
        self.assertIn('"backupWebdavEnabled" in body', ROUTES)
        self.assertIn('"backupWebdavPassword"', ROUTES)
        # password stored encrypted
        self.assertIn('encrypt_text(str(body.get("backupWebdavPassword")))', ROUTES)

    def test_admin_guard_on_webdav_routes(self) -> None:
        for marker in ('sub == "/backup/webdav/test"', 'sub == "/backup/webdav/sync"'):
            idx = ROUTES.index(marker)
            block = ROUTES[idx:idx + 400]
            self.assertIn("is_admin_user_id", block)

    def test_export_uploads_to_webdav_when_enabled(self) -> None:
        self.assertIn('upload_backup_to_webdav(backup, filename)', ROUTES)

    def test_full_backup_covers_both_scopes(self) -> None:
        self.assertIn('export_backup_payload(uid, ["dns", "ssl"])', APP)

    def test_webdav_filename_validated(self) -> None:
        self.assertIn("A-Za-z0-9._-", APP)


class UpyunDomainFixTests(unittest.TestCase):
    def test_upyun_cred_from_dns_credentials(self) -> None:
        # 修复：凭证必须从 dns_credentials 查询，而不是部署行（否则新保存的
        # 账号没有部署记录时域名列表永远为空）
        self.assertIn("provider = 'upyun' ORDER BY createdAt ASC LIMIT 1", ROUTES)

    def test_upyun_error_surfaced(self) -> None:
        self.assertIn('"upyunError": upyun_error', ROUTES)


if __name__ == "__main__":
    unittest.main()
