"""A multi-file nginx deployment must either commit or restore every file."""
from __future__ import annotations

import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from test_baota_plugin import _load_plugin_module


class NginxDeploymentRollbackTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load_plugin_module()
        self.plugin = self.mod.dnspanel_ssl_main()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cert_dir = self.root / "cert" / "example.com"
        self.cert_dir.mkdir(parents=True)
        self.cert = self.cert_dir / "fullchain.pem"
        self.key = self.cert_dir / "privkey.pem"
        self.cert.write_text("old certificate", encoding="utf-8")
        self.key.write_text("old private key", encoding="utf-8")
        self.confs = [self.root / "site.conf", self.root / "ssl.conf"]
        self.original = {}
        for index, path in enumerate(self.confs):
            content = (
                "server {\n    listen 443 ssl;\n    server_name example.com;\n"
                "    ssl_certificate /old/cert%d.pem;\n"
                "    ssl_certificate_key /old/key%d.pem;\n}\n" % (index, index)
            )
            path.write_text(content, encoding="utf-8")
            self.original[path] = content
        self.cfg = {"serverUrl": "https://panel.example.com", "apiToken": "test-token"}
        self.args = types.SimpleNamespace(certId="new-cert", credentialId="7", siteName="example.com", force=True)
        realpath = os.path.realpath

        def map_cert_path(path, *args, **kwargs):
            normalized = str(path).replace("\\", "/")
            prefix = "/www/server/panel/vhost/cert"
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return str(self.root / "cert") + normalized[len(prefix):]
            return realpath(path, *args, **kwargs)

        patches = [
            patch.object(self.mod.os.path, "realpath", side_effect=map_cert_path),
            patch.object(self.mod, "_get_config", side_effect=lambda key=None, **kw: self.cfg.get(key) if key else self.cfg),
            patch.object(self.mod, "_set_config", side_effect=lambda key, value: self.cfg.__setitem__(key, value)),
            patch.object(self.mod, "_list_bt_sites", return_value=[{"name": "example.com", "domains": []}]),
            patch.object(self.mod, "_site_vhost_conf_paths", return_value=[str(p) for p in self.confs]),
            patch.object(self.mod, "_http_request", side_effect=lambda url, **kw: json.dumps({"success": True, "data": {"publicKey": "new certificate", "privateKey": "new private key", "status": "issued", "notAfter": "2999-01-01T00:00:00Z"}})),
            patch.object(self.mod, "_complete_certificate_chain", side_effect=lambda pem, *args: (pem, 0, "")),
            patch.object(self.mod, "_validate_pem_pair", return_value=(True, "")),
            patch.object(self.mod, "_find_executable", return_value="nginx-test-binary"),
            patch.object(self.mod.public, "GetWebServer", return_value="nginx"),
            patch.object(self.mod.public, "ReadFile", side_effect=lambda p: Path(p).read_text(encoding="utf-8")),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def assert_restored(self):
        self.assertEqual(self.cert.read_text(encoding="utf-8"), "old certificate")
        self.assertEqual(self.key.read_text(encoding="utf-8"), "old private key")
        for path, content in self.original.items():
            self.assertEqual(path.read_text(encoding="utf-8"), content)
        self.assertNotIn("deployedFingerprints", self.cfg)

    def test_success_removes_every_config_and_certificate_backup(self):
        with patch.object(self.mod, "_run_checked", return_value=(True, "configuration is valid")) as check, \
             patch.object(self.mod.subprocess, "call", return_value=0) as reload:
            result = self.plugin.deploy(self.args)
        self.assertTrue(result["status"], result)
        self.assertEqual(self.cert.read_text(encoding="utf-8"), "new certificate")
        self.assertEqual(self.key.read_text(encoding="utf-8"), "new private key")
        for path in self.confs:
            self.assertIn(self.cert.as_posix(), path.read_text(encoding="utf-8").replace("\\", "/"))
        self.assertEqual(list(self.root.rglob("*.dnspanel.bak")), [])
        check.assert_called_once_with(["nginx-test-binary", "-t"])
        reload.assert_called_once_with(["nginx-test-binary", "-s", "reload"])

    def test_failed_nginx_check_restores_configs_in_reverse_order_then_checks_again(self):
        replacements = []
        real_replace = os.replace

        def replace(source, target):
            if str(source).endswith(".conf.dnspanel.bak"):
                replacements.append(str(target))
            return real_replace(source, target)

        checks = []

        def check(command):
            checks.append(command)
            if len(checks) == 1:
                return False, "invalid new configuration"
            self.assert_restored()
            return True, "restored configuration is valid"

        with patch.object(self.mod.os, "replace", side_effect=replace), \
             patch.object(self.mod, "_run_checked", side_effect=check), \
             patch.object(self.mod.subprocess, "call", return_value=0) as reload:
            result = self.plugin.deploy(self.args)
        self.assertFalse(result["status"])
        self.assert_restored()
        self.assertEqual(replacements, [str(self.confs[1]), str(self.confs[0])])
        self.assertEqual(checks, [["nginx-test-binary", "-t"], ["nginx-test-binary", "-t"]])
        reload.assert_not_called()

    def test_partial_config_write_failure_restores_backups_already_created(self):
        atomic_write = self.mod._atomic_write

        def fail_second_config(path, content, mode=0o600):
            if str(path) == str(self.confs[1]):
                raise OSError("simulated second-config failure")
            return atomic_write(path, content, mode)

        with patch.object(self.mod, "_atomic_write", side_effect=fail_second_config), \
             patch.object(self.mod, "_run_checked", return_value=(True, "restored configuration is valid")) as check, \
             patch.object(self.mod.subprocess, "call", return_value=0) as reload:
            result = self.plugin.deploy(self.args)
        self.assertFalse(result["status"])
        self.assert_restored()
        check.assert_called_once_with(["nginx-test-binary", "-t"])
        reload.assert_not_called()

    def test_reload_failure_restores_certificates_and_every_config(self):
        with patch.object(self.mod, "_run_checked", return_value=(True, "configuration is valid")) as check, \
             patch.object(self.mod.subprocess, "call", return_value=1) as reload:
            result = self.plugin.deploy(self.args)
        self.assertFalse(result["status"])
        self.assert_restored()
        self.assertEqual(check.call_count, 2)
        reload.assert_called_once_with(["nginx-test-binary", "-s", "reload"])

    def test_failed_restore_is_reported_instead_of_claiming_successful_rollback(self):
        real_replace = os.replace

        def fail_restore(source, target):
            if str(source) == str(self.confs[1]) + ".dnspanel.bak":
                raise OSError("simulated restore failure")
            return real_replace(source, target)

        with patch.object(self.mod.os, "replace", side_effect=fail_restore), \
             patch.object(self.mod, "_run_checked", return_value=(False, "invalid configuration")), \
             patch.object(self.mod.subprocess, "call", return_value=0) as reload:
            result = self.plugin.deploy(self.args)
        self.assertFalse(result["status"])
        self.assertIn("回滚未完成", result["msg"])
        self.assertEqual(self.confs[0].read_text(encoding="utf-8"), self.original[self.confs[0]])
        self.assertTrue(Path(str(self.confs[1]) + ".dnspanel.bak").exists())
        reload.assert_not_called()


if __name__ == "__main__":
    unittest.main()
