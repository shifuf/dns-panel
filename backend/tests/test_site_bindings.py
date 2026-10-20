"""Tests for BaoTa site-binding reporting and platform credential secrets."""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

PLUGIN_MAIN = ROOT_DIR / "baota-ssl-plugin" / "dnspanel_ssl_main.py"


class SiteBindingsSourceTests(unittest.TestCase):
    """Route wiring checks for the plugin-reported site bindings."""

    def setUp(self) -> None:
        self.source = Path(BACKEND_DIR / "modules" / "route_handlers.py").read_text(encoding="utf-8-sig")
        self.plugin = PLUGIN_MAIN.read_text(encoding="utf-8-sig")

    def test_report_endpoint_exists(self) -> None:
        self.assertIn('/site-bindings/report', self.source)
        self.assertIn('ssl_site_bindings', self.source)

    def test_list_endpoint_exists(self) -> None:
        self.assertIn('"/site-bindings"', self.source)

    def test_api_token_scope_allows_report(self) -> None:
        self.assertIn('sub == "/site-bindings/report"', self.source)

    def test_table_in_migrations(self) -> None:
        self.assertIn('CREATE TABLE IF NOT EXISTS ssl_site_bindings', Path(BACKEND_DIR / "migrate.py").read_text(encoding="utf-8-sig"))

    def test_plugin_reports_on_sync(self) -> None:
        self.assertIn('_report_site_bindings()', self.plugin)
        self.assertIn('def report_bindings', self.plugin)

    def test_plugin_parses_proxy_pass(self) -> None:
        self.assertIn('proxy_pass', self.plugin)
        self.assertIn('ProxyPass', self.plugin)

    def test_plugin_and_panel_versions_match(self) -> None:
        import re
        panel = re.search(r'PLUGIN_EXPECTED_VERSION = "([^"]+)"', self.source)
        plugin = re.search(r'PLUGIN_VERSION = "([^"]+)"', self.plugin)
        self.assertIsNotNone(panel)
        self.assertIsNotNone(plugin)
        self.assertEqual(panel.group(1), plugin.group(1))


class SecretsEndpointSourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = Path(BACKEND_DIR / "modules" / "route_handlers.py").read_text(encoding="utf-8-sig")

    def test_secrets_endpoint_exists(self) -> None:
        self.assertIn('/platform-credentials/(\\d+)/secrets', self.source.replace("\\\\", "\\"))

    def test_tencent_not_exposed(self) -> None:
        self.assertIn('腾讯云凭证请在 SSL 凭证管理中查看', self.source)


class SiteBindingsMigrationTests(unittest.TestCase):
    def test_migrate_creates_site_bindings_table(self) -> None:
        import migrate as db_migrate
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "t.db")
            db_migrate.migrate(db_migrate.normalize_db_path(db))
            conn = sqlite3.connect(db)
            names = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='ssl_site_bindings'"
            )]
            conn.close()
            self.assertEqual(names, ["ssl_site_bindings"])


if __name__ == "__main__":
    unittest.main()
