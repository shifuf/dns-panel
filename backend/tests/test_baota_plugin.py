from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path


PLUGIN_PATH = Path(__file__).resolve().parents[2] / "baota-ssl-plugin" / "dnspanel_ssl_main.py"


def _load_plugin_module():
    """Import the BaoTa plugin module with a stubbed `public` runtime.

    The plugin begins with os.chdir("/www/server/panel") + import public, which
    cannot run off a BaoTa host. We inject a minimal fake `public` module and
    neutralize the chdir so the pure helper functions stay testable here.
    """
    fake_public = types.ModuleType("public")

    def _read_file(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return fh.read()
        except Exception:
            return None

    fake_public.ReadFile = _read_file
    fake_public.WriteLog = lambda *a, **k: None
    fake_public.GetWebServer = lambda: "nginx"
    fake_public.ReturnMsg = lambda status, msg: {"status": bool(status), "msg": str(msg)}
    fake_public.M = lambda *a, **k: None
    sys.modules.setdefault("public", fake_public)

    spec = importlib.util.spec_from_file_location("dnspanel_ssl_main_test", PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    # Neutralize the hard-coded chdir by pre-empting os.chdir during exec.
    original_chdir = __import__("os").chdir
    try:
        __import__("os").chdir = lambda *_a, **_k: None
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    finally:
        __import__("os").chdir = original_chdir
    return module


class PluginLoadedOnce:
    module = None

    @classmethod
    def get(cls):
        if cls.module is None:
            cls.module = _load_plugin_module()
        return cls.module


class NameCoverageTests(unittest.TestCase):
    """TLS wildcard semantics for the per-site certificate analysis."""

    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    def test_exact_name(self) -> None:
        self.assertTrue(self.mod._name_covers("api.example.com", "api.example.com"))

    def test_wildcard_covers_one_label_only(self) -> None:
        self.assertTrue(self.mod._name_covers("*.example.com", "account.example.com"))
        # never the apex, never two labels down
        self.assertFalse(self.mod._name_covers("*.example.com", "example.com"))
        self.assertFalse(self.mod._name_covers("*.example.com", "a.b.example.com"))

    def test_literal_wildcard_host_requires_identical_wildcard_name(self) -> None:
        self.assertTrue(self.mod._name_covers("*.example.com", "*.example.com"))
        self.assertFalse(self.mod._name_covers("api.example.com", "*.example.com"))

    def test_coverage_score_counts_hosts(self) -> None:
        names = ["*.example.com", "www.example.com"]
        hosts = ["example.com", "www.example.com", "account.example.com"]
        self.assertEqual(self.mod._names_coverage_score(names, hosts), 2)


class PanelCertNameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    def test_san_count_ignored_and_primary_used(self) -> None:
        # Tencent list API reports san as a COUNT — must not be treated as names.
        self.assertEqual(
            self.mod._cert_names_from_panel_cert({"domain": "Example.com", "san": 3}),
            ["example.com"],
        )

    def test_acme_json_san_list_is_parsed(self) -> None:
        cert = {"domain": "*.example.com", "san": '["*.example.com", "example.com"]'}
        self.assertEqual(
            self.mod._cert_names_from_panel_cert(cert),
            ["*.example.com", "example.com"],
        )


class CertificateHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    def test_expired_and_expiring_states(self) -> None:
        expired = {"notAfter": "2020-01-01T00:00:00Z", "status": "expired"}
        self.assertEqual(self.mod._certificate_health(expired)["state"], "expired")
        soon = {"notAfter": "2999-01-01T00:00:00Z", "status": "issued"}
        self.assertEqual(self.mod._certificate_health(soon, renew_days=30)["state"], "valid")
        unparsable = {"notAfter": "", "status": "issued"}
        self.assertEqual(self.mod._certificate_health(unparsable)["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
