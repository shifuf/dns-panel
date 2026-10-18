from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


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


class EdgeOneBindingStatusTests(unittest.TestCase):
    """The plugin surface must flag when the CDN edge serves a stale cert."""

    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    def test_none_when_no_bindings(self) -> None:
        cert = {"domain": "api.example.com", "remoteCertId": "c1"}
        self.assertEqual(self.mod._edgeone_binding_status(cert, {})["state"], "none")

    def test_synced_when_same_cert(self) -> None:
        cert = {"domain": "api.example.com", "remoteCertId": "c1", "san": ""}
        bindings = {"api.example.com": {"status": "synced", "certRemoteId": "c1", "upToDate": True}}
        out = self.mod._edgeone_binding_status(cert, bindings)
        self.assertEqual(out["state"], "synced")
        self.assertIn("api.example.com", out["domains"])

    def test_stale_when_binding_has_older_cert(self) -> None:
        cert = {"domain": "api.example.com", "remoteCertId": "c2", "san": ""}
        bindings = {"api.example.com": {"status": "synced", "certRemoteId": "c1", "upToDate": False}}
        self.assertEqual(self.mod._edgeone_binding_status(cert, bindings)["state"], "stale")

    def test_failed_takes_priority(self) -> None:
        cert = {"domain": "api.example.com", "remoteCertId": "c1", "san": ""}
        bindings = {"api.example.com": {"status": "failed", "certRemoteId": "c1"}}
        self.assertEqual(self.mod._edgeone_binding_status(cert, bindings)["state"], "failed")

    def test_wildcard_cert_matches_edge_subdomain(self) -> None:
        cert = {"domain": "*.example.com", "remoteCertId": "c1", "san": "[\"*.example.com\"]"}
        bindings = {"cdn.example.com": {"status": "synced", "certRemoteId": "c1", "upToDate": True}}
        self.assertEqual(self.mod._edgeone_binding_status(cert, bindings)["state"], "synced")


class NginxDirectiveRewriteTests(unittest.TestCase):
    """The deploy path used to die with "local variable 'lines' referenced
    before assignment" on every site that already had SSL configured."""

    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    SSL_CONF = (
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name files.shifuf.com;\n"
        "    ssl_certificate    /www/server/panel/vhost/cert/files.shifuf.com/fullchain.pem;\n"
        "    ssl_certificate_key    /www/server/panel/vhost/cert/files.shifuf.com/privkey.pem;\n"
        "}\n"
    )

    def test_directive_replacement_keeps_indentation_and_spares_key(self) -> None:
        out = self.mod._replace_nginx_directive(
            self.SSL_CONF, "ssl_certificate", "/new/cert/fullchain.pem"
        )
        self.assertIn("    ssl_certificate    /new/cert/fullchain.pem;", out)
        # The *_key* directive must not be swallowed by the *_certificate* pass.
        self.assertIn(
            "ssl_certificate_key    /www/server/panel/vhost/cert/files.shifuf.com/privkey.pem;",
            out,
        )
        out = self.mod._replace_nginx_directive(out, "ssl_certificate_key", "/new/cert/privkey.pem")
        self.assertIn("    ssl_certificate_key    /new/cert/privkey.pem;", out)

    def test_directive_replacement_is_noop_when_absent(self) -> None:
        conf = "server {\n    listen 80;\n    server_name example.com;\n}\n"
        self.assertEqual(
            self.mod._replace_nginx_directive(conf, "ssl_certificate", "/x.pem"), conf
        )

    def test_443_without_inline_cert_does_not_append_duplicate_block(self) -> None:
        mod = self.mod
        site = "files.shifuf.com"
        conf = (
            "server {\n"
            "    listen 443 ssl;\n"
            "    server_name files.shifuf.com;\n"
            "    include /www/server/panel/vhost/nginx/ssl/" + site + ".conf;\n"
            "}\n"
        )
        conf_path = "/www/server/panel/vhost/nginx/" + site + ".conf"
        writes: dict = {}
        with patch.object(mod.os.path, "exists", lambda p: str(p) == conf_path), \
        patch.object(mod.os.path, "getsize", lambda p: len(self.SSL_CONF)), \
             patch.object(mod.public, "ReadFile", lambda p: conf if str(p) == conf_path else None), \
             patch.object(mod, "_atomic_write", lambda p, c, mode=0o600: writes.__setitem__(str(p), c)):
            mod.dnspanel_ssl_main()._enable_nginx_ssl_for_proxy(
                site,
                "/www/server/panel/vhost/cert/" + site + "/fullchain.pem",
                "/www/server/panel/vhost/cert/" + site + "/privkey.pem",
            )
        # Config gets backed up and written back byte-identical — no second server block.
        self.assertEqual(writes[conf_path], conf)

    def test_ssl_enabled_site_is_rewritten_without_crashing(self) -> None:
        mod = self.mod
        site = "files.shifuf.com"
        conf_path = "/www/server/panel/vhost/nginx/" + site + ".conf"
        backup_path = conf_path + ".dnspanel.bak"
        writes: dict = {}

        with patch.object(mod.os.path, "exists", lambda p: str(p) == conf_path), \
        patch.object(mod.os.path, "getsize", lambda p: len(self.SSL_CONF)), \
             patch.object(mod.public, "ReadFile", lambda p: self.SSL_CONF if str(p) == conf_path else None), \
             patch.object(mod, "_atomic_write", lambda p, c, mode=0o600: writes.__setitem__(str(p), c)):
            backups = mod.dnspanel_ssl_main()._enable_nginx_ssl_for_proxy(
                site,
                "/www/server/panel/vhost/cert/" + site + "/fullchain.pem",
                "/www/server/panel/vhost/cert/" + site + "/privkey.pem",
            )

        self.assertIn(backup_path, backups)
        self.assertEqual(writes[backup_path], self.SSL_CONF)
        written = writes[conf_path]
        self.assertIn(
            "ssl_certificate    /www/server/panel/vhost/cert/" + site + "/fullchain.pem;",
            written,
        )
        self.assertIn(
            "ssl_certificate_key    /www/server/panel/vhost/cert/" + site + "/privkey.pem;",
            written,
        )


def _summary(days: int, names):
    return {
        "names": list(names),
        "expiry": datetime.now(timezone.utc) + timedelta(days=days),
        "fingerprint": "fp-" + str(days),
        "path": "/cert/" + ",".join(names) + ".pem",
    }


def _panel_cert(cert_id: str, domain: str, days: int, source: str = "letsencrypt"):
    return {
        "remoteCertId": cert_id,
        "credentialId": 7,
        "domain": domain,
        "provider": "acme" if source == "letsencrypt" else "tencent_ssl",
        "source": source,
        "status": "issued",
        "notAfter": (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(),
        "san": [domain],
    }


class SiteCertificateCheckTests(unittest.TestCase):
    """Per-site update detection must respect a certificate the site already
    serves instead of nagging to deploy an unrelated panel certificate."""

    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    def _check(self, installed, panel_certs, site="files.shifuf.com", renew_days=30):
        return self._check_with_domains(installed, panel_certs, [site], site=site, renew_days=renew_days)

    def _check_with_domains(self, installed, panel_certs, domains, site=None, renew_days=30):
        mod = self.mod
        site = site or domains[0]
        cfg = {
            "serverUrl": "https://panel.example.com",
            "apiToken": "token",
            "renewDays": renew_days,
            "allowedSites": [],
            "allowedSources": ["tencent", "letsencrypt"],
        }
        sites = [{"id": 1, "name": site, "domains": list(domains)}]
        with patch.object(mod, "_get_config", lambda *a, **k: cfg), \
             patch.object(mod, "_set_config", lambda *a, **k: True), \
             patch.object(mod, "_list_bt_sites", lambda: sites), \
             patch.object(mod, "_installed_cert_summaries", lambda name: list(installed)), \
             patch.object(mod, "_panel_get", lambda path, timeout=30: {"success": True, "data": list(panel_certs)}):
            result = mod.dnspanel_ssl_main().check_site_certificates(None)
        self.assertTrue(result.get("success"), result)
        return result["data"]["items"][0]

    def test_valid_self_deployed_cert_is_not_flagged_for_wildcard_update(self) -> None:
        item = self._check(
            installed=[_summary(200, ["files.shifuf.com"])],
            panel_certs=[_panel_cert("le-1", "*.shifuf.com", 89)],
        )
        self.assertEqual(item["state"], "ok")
        self.assertIn(item["installedDaysRemaining"], (199, 200))
        # The candidate is still offered for a manual choice.
        self.assertEqual([c["id"] for c in item["panelCerts"]], ["le-1"])

    def test_expired_deployed_cert_recommends_candidate(self) -> None:
        item = self._check(
            installed=[_summary(-86, ["files.shifuf.com"])],
            panel_certs=[_panel_cert("le-1", "*.shifuf.com", 89)],
        )
        self.assertEqual(item["state"], "update")
        self.assertIn("已过期", item["action"])
        self.assertIn(item["installedDaysRemaining"], (-87, -86))

    def test_multiple_non_expired_panel_certs_are_exposed(self) -> None:
        item = self._check(
            installed=[],
            panel_certs=[
                _panel_cert("le-1", "*.shifuf.com", 89),
                _panel_cert("t-1", "files.shifuf.com", 300, source="tencent"),
            ],
        )
        self.assertEqual(item["state"], "missing")
        self.assertEqual(sorted(c["id"] for c in item["panelCerts"]), ["le-1", "t-1"])
        # Longest validity wins the default slot when coverage ties.
        self.assertEqual(item["bestCertId"], "t-1")

    def test_coverage_gap_is_still_reported(self) -> None:
        # Site serves two hosts but the deployed cert only covers one of them:
        # that is a real gap, so the wider wildcard candidate is recommended.
        item = self._check_with_domains(
            installed=[_summary(200, ["files.shifuf.com"])],
            panel_certs=[_panel_cert("le-1", "*.shifuf.com", 89)],
            domains=["files.shifuf.com", "cdn.shifuf.com"],
        )
        self.assertEqual(item["state"], "update")
        self.assertIn("cdn.shifuf.com", item["action"])

    def test_valid_self_deployed_cert_covers_all_hosts_quietly(self) -> None:
        item = self._check_with_domains(
            installed=[_summary(200, ["files.shifuf.com", "cdn.shifuf.com"])],
            panel_certs=[_panel_cert("le-1", "*.shifuf.com", 89)],
            domains=["files.shifuf.com", "cdn.shifuf.com"],
        )
        self.assertEqual(item["state"], "ok")



class AccelCheckTests(unittest.TestCase):
    """The 加速证书 tab — previously a dead tab (index.html called a
    non-existent show_accel_check). Its backend action classifies each
    acceleration certificate binding by drift / expiry / failure."""

    def setUp(self) -> None:
        self.mod = PluginLoadedOnce.get()

    def _run(self, bindings):
        mod = self.mod
        cfg = {"serverUrl": "https://panel.example.com", "apiToken": "token"}
        with patch.object(mod, "_get_config", lambda *a, **k: cfg), \
             patch.object(mod, "_set_config", lambda *a, **k: True), \
             patch.object(mod, "_panel_get", lambda path, timeout=60: {"success": True, "data": list(bindings)}):
            return mod.dnspanel_ssl_main().accel_check(None)

    def test_classifies_state_by_drift_and_expiry(self) -> None:
        import datetime as _dt
        future = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        soon = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        past = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = self._run([
            {"domainName": "ok.example.com", "source": "acme", "certRemoteId": "c1",
             "upToDate": True, "status": "synced", "notAfter": future},
            {"domainName": "drift.example.com", "source": "tencent", "certRemoteId": "old",
             "upToDate": False, "status": "synced", "notAfter": future},
            {"domainName": "failed.example.com", "source": "tencent", "certRemoteId": "x",
             "upToDate": False, "status": "failed", "lastError": "boom", "notAfter": future},
            {"domainName": "expired.example.com", "source": "tencent", "certRemoteId": "y",
             "upToDate": True, "status": "synced", "notAfter": past},
            {"domainName": "expiring.example.com", "source": "acme", "certRemoteId": "z",
             "upToDate": True, "status": "synced", "notAfter": soon},
        ])
        self.assertTrue(result.get("success"), result)
        states = {it["domainName"]: it["state"] for it in result["data"]["items"]}
        self.assertEqual(states["ok.example.com"], "synced")
        self.assertEqual(states["drift.example.com"], "stale")
        self.assertEqual(states["failed.example.com"], "failed")
        self.assertEqual(states["expired.example.com"], "expired")
        self.assertEqual(states["expiring.example.com"], "expiring")
        summary = result["data"]["summary"]
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["synced"], 1)
        self.assertEqual(summary["failed"], 1)

    def test_worst_state_sorted_first(self) -> None:
        import datetime as _dt
        future = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        result = self._run([
            {"domainName": "good.example.com", "source": "acme", "certRemoteId": "c1",
             "upToDate": True, "status": "synced", "notAfter": future},
            {"domainName": "bad.example.com", "source": "tencent", "certRemoteId": "x",
             "upToDate": False, "status": "failed", "notAfter": future},
        ])
        self.assertEqual(result["data"]["items"][0]["domainName"], "bad.example.com")


if __name__ == "__main__":
    unittest.main()
