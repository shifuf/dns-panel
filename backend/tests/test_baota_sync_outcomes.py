"""Automatic sync must expose renewal and deployment failures to the operator."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from test_baota_plugin import _load_plugin_module


class AutoSyncOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.mod = _load_plugin_module()
        self.plugin = self.mod.dnspanel_ssl_main()
        self.cfg = {"serverUrl": "https://panel.example.com", "apiToken": "fixture-token", "autoSync": True, "renewDays": 7}
        patcher = patch.object(self.mod, "_get_config", lambda key=None, **kwargs: self.cfg.get(key) if key else self.cfg)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_auto(self, renewal):
        completed = []
        with patch.object(self.mod, "_http_request", return_value=json.dumps(renewal)), \
             patch.object(self.plugin, "sync_now", side_effect=lambda args: completed.append("deployed") or {"status": True, "msg": "同步完成"}), \
             patch.object(self.plugin, "check_site_certificates", return_value={}):
            result = self.plugin.auto_sync(object())
        self.assertEqual(completed, ["deployed"], "Renewal failure must not prevent deployment of already issued certificates")
        return result

    def test_renewal_http_error_is_not_reported_as_successful_sync(self):
        result = self.run_auto({"success": False, "message": "renew authorization denied"})
        self.assertFalse(result["status"])
        self.assertIn("renew authorization denied", result["msg"])

    def test_failed_certificate_in_success_envelope_is_reported(self):
        result = self.run_auto({"success": True, "data": {"failed": [{"domain": "api.example.com", "error": "DNS credential missing"}]}})
        self.assertFalse(result["status"])
        self.assertIn("api.example.com", result["msg"])
        self.assertIn("DNS credential missing", result["msg"])

    def test_queued_renewal_does_not_turn_sync_into_failure(self):
        result = self.run_auto({"success": True, "data": {"renewed": [{"domain": "api.example.com", "status": "queued"}], "failed": []}})
        self.assertTrue(result["status"])

    def event_sync(self, deploy_result, report_success=True):
        claimed = False
        event = {"id": 1, "domain": "api.example.com", "source": "letsencrypt", "remoteCertId": "api.example.com", "credentialId": 7}

        def panel_post(path, payload=None, **kwargs):
            nonlocal claimed
            if path.endswith("/claim"):
                result = {"success": True, "data": None if claimed else event}
                claimed = True
                return result
            return {"success": report_success, "message": "result submission failed"}

        with patch.object(self.mod, "_panel_post", side_effect=panel_post), \
             patch.object(self.mod, "_panel_get", return_value={"success": True, "data": {"status": "issued", "notAfter": "2999-01-01T00:00:00Z"}}), \
             patch.object(self.mod, "_list_bt_sites", return_value=[{"name": "api.example.com", "domains": ["api.example.com"]}]), \
             patch.object(self.mod, "_report_site_bindings", return_value={}), \
             patch.object(self.mod, "_set_config", return_value=True), \
             patch.object(self.plugin, "deploy", return_value=deploy_result):
            return self.plugin.sync_now(object())

    def test_failed_site_deployment_makes_sync_fail(self):
        result = self.event_sync({"status": False, "msg": "nginx configuration test failed"})
        self.assertFalse(result["status"])
        self.assertIn("失败 1", result["msg"])

    def test_unacknowledged_deployment_result_is_not_success(self):
        result = self.event_sync({"status": True, "msg": "deployed"}, report_success=False)
        self.assertFalse(result["status"])
        self.assertIn("回传", result["msg"])


if __name__ == "__main__":
    unittest.main()
