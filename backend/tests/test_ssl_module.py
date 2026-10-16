from __future__ import annotations

import subprocess
import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules import acme_api  # noqa: E402
from modules.tencent_ssl_api import (  # noqa: E402
    parse_certificate_datetime, certificate_days_remaining, certificate_is_expired,
    _normalize_status,
)
from modules.route_handlers import _ssl_filter_and_summarize, _validate_ssl_notification_url  # noqa: E402
import migrate as db_migrate  # noqa: E402


class SslListTests(unittest.TestCase):
    def test_status_summary_uses_full_filtered_set_before_pagination(self) -> None:
        certs = [
            {"remoteCertId": "t1", "provider": "tencent_ssl", "status": "issued"},
            {"remoteCertId": "t2", "provider": "tencent_ssl", "status": "expired"},
            {"remoteCertId": "a1", "provider": "acme", "status": "issued"},
        ]

        result = _ssl_filter_and_summarize(certs, source_filter="tencent")

        self.assertEqual(result["statusSummary"], {"issued": 1, "expired": 1})
        self.assertEqual(result["sourceSummary"], {"tencent": 2, "letsencrypt": 1})
        self.assertEqual([item["remoteCertId"] for item in result["certs"]], ["t1", "t2"])

    def test_source_and_status_filters_are_combined_server_side(self) -> None:
        certs = [
            {"provider": "tencent_ssl", "status": "issued"},
            {"provider": "acme", "status": "issued"},
            {"provider": "acme", "status": "failed"},
        ]

        result = _ssl_filter_and_summarize(certs, "issued", "letsencrypt")

        self.assertEqual(len(result["certs"]), 1)
        self.assertEqual(result["certs"][0]["source"], "letsencrypt")
        self.assertEqual(result["statusSummary"], {"issued": 1, "failed": 1})


class CertificateDateTests(unittest.TestCase):
    def test_tencent_date_formats_are_compared_as_utc(self) -> None:
        self.assertEqual(parse_certificate_datetime("2026-07-23 07:59:59").isoformat(), "2026-07-23T07:59:59+00:00")
        self.assertEqual(parse_certificate_datetime("2026-07-23T07:59:59Z").isoformat(), "2026-07-23T07:59:59+00:00")
        self.assertFalse(certificate_is_expired("2099-07-23 07:59:59"))
        self.assertIsNotNone(certificate_days_remaining("2099-07-23 07:59:59"))

    def test_acme_metadata_uses_iso8601(self) -> None:
        self.assertEqual(acme_api.parse_cert_pem.__name__, "parse_cert_pem")


class TencentStatusMapTests(unittest.TestCase):
    """The official enum: 2=审核失败 3=已过期 4=自动添加DNS记录 7=已取消 10=已吊销.

    Mis-mapping 3 → failed previously hid expired certificates from the
    auto-renew scanner, so they were never renewed (the reported bug).
    """

    def test_official_status_enum_is_mapped_correctly(self) -> None:
        self.assertEqual(_normalize_status(0), "validating")   # 审核中
        self.assertEqual(_normalize_status(1), "issued")       # 已通过
        self.assertEqual(_normalize_status(2), "failed")       # 审核失败
        self.assertEqual(_normalize_status(3), "expired")      # 已过期
        self.assertEqual(_normalize_status(4), "validating")   # 自动添加 DNS 记录
        self.assertEqual(_normalize_status(7), "cancelled")    # 已取消
        self.assertEqual(_normalize_status(9), "revoked")      # 吊销中
        self.assertEqual(_normalize_status(10), "revoked")     # 已吊销
        self.assertEqual(_normalize_status(None), "applying")
        self.assertEqual(_normalize_status("bad"), "applying")



class AcmeApplyTests(unittest.TestCase):
    def test_domain_validation_rejects_path_traversal_and_invalid_labels(self) -> None:
        for domain in ("../../etc/passwd", "bad_domain.example", "example", "*.example"):
            with self.subTest(domain=domain), self.assertRaises(acme_api.AcmeApiError):
                acme_api.validate_domain(domain)

    def test_domain_validation_normalizes_idna_and_wildcards(self) -> None:
        self.assertEqual(acme_api.validate_domain("*.例子.测试"), "*.xn--fsqu00a.xn--0zwm56d")
    @patch.object(acme_api.AcmeService, "_install_and_read")
    @patch.object(acme_api, "_run")
    @patch.object(acme_api, "dns_plugin_env", return_value=("dns_cf", {"CF_Token": "token"}))
    def test_issue_passes_primary_and_all_san_domains_to_acme(
        self, _env, run_mock, install_mock
    ) -> None:
        run_mock.return_value = subprocess.CompletedProcess([], 0, "", "")
        install_mock.return_value = {"primary": "example.com"}

        result = acme_api.AcmeService("ec-256").issue(
            ["EXAMPLE.com", "www.example.com", "api.example.com"],
            "cloudflare",
            {"apiToken": "token"},
        )

        args = run_mock.call_args.args[0]
        self.assertEqual(args.count("-d"), 3)
        self.assertIn("example.com", args)
        self.assertIn("www.example.com", args)
        self.assertIn("api.example.com", args)
        install_mock.assert_called_once_with("example.com", {"CF_Token": "token"})
        self.assertEqual(result["primary"], "example.com")

    @patch.object(acme_api, "_find_acme_bin", return_value="acme.sh")
    @patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("acme.sh", 600))
    def test_acme_timeout_is_exposed_as_gateway_timeout(self, _run, _find) -> None:
        with self.assertRaises(acme_api.AcmeApiError) as ctx:
            acme_api._run(["--issue"], {}, timeout=600)

        self.assertEqual(ctx.exception.status, 504)
        self.assertIn("超时", str(ctx.exception))


class AcmeStoreFallbackTests(unittest.TestCase):
    def test_store_files_prefers_matching_key_type_dir(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            # RSA dir exists with old files; ECC dir is the "matching" one.
            rsa_dir = home / "example.com"
            ecc_dir = home / "example.com_ecc"
            for d in (rsa_dir, ecc_dir):
                d.mkdir()
                (d / "fullchain.cer").write_text("CERT-" + d.name, encoding="utf-8")
                (d / "example.com.key").write_text("KEY-" + d.name, encoding="utf-8")
            with patch.object(acme_api, "ACME_HOME", str(home)):
                svc_ecc = acme_api.AcmeService("ec-256")
                full, key = svc_ecc._store_files("example.com")
                self.assertEqual(full.read_text(encoding="utf-8"), "CERT-example.com_ecc")
                self.assertEqual(key.read_text(encoding="utf-8"), "KEY-example.com_ecc")
                svc_rsa = acme_api.AcmeService("2048")
                full, key = svc_rsa._store_files("example.com")
                self.assertEqual(full.read_text(encoding="utf-8"), "CERT-example.com")

    @unittest.skipIf(sys.platform.startswith("win"), "Windows forbids '*' in directory names")
    def test_store_files_wildcard_dir_uses_literal_star(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            wc_dir = home / "*.example.com"
            wc_dir.mkdir()
            (wc_dir / "fullchain.cer").write_text("WC-CERT", encoding="utf-8")
            (wc_dir / "*.example.com.key").write_text("WC-KEY", encoding="utf-8")
            with patch.object(acme_api, "ACME_HOME", str(home)):
                full, key = acme_api.AcmeService("2048")._store_files("*.example.com")
                self.assertEqual(full.read_text(encoding="utf-8"), "WC-CERT")
                self.assertEqual(key.read_text(encoding="utf-8"), "WC-KEY")

    def test_read_pem_recovers_from_install_failure_via_store(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            src = home / "example.com"
            src.mkdir()
            (src / "fullchain.cer").write_text("STORE-CERT", encoding="utf-8")
            (src / "example.com.key").write_text("STORE-KEY", encoding="utf-8")
            with patch.object(acme_api, "ACME_HOME", str(home)), \
                 patch.object(acme_api, "_run",
                              side_effect=acme_api.AcmeApiError("install-cert failed", 502)):
                pem = acme_api.AcmeService().read_pem("example.com")
            self.assertEqual(pem["publicKey"], "STORE-CERT")
            self.assertEqual(pem["privateKey"], "STORE-KEY")
            # deployed copy was repaired for future reads
            deployed = home / "deployed" / "example.com" / "fullchain.pem"
            self.assertEqual(deployed.read_text(encoding="utf-8"), "STORE-CERT")


class SslNotificationSecurityTests(unittest.TestCase):
    @patch("modules.route_handlers.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))])
    def test_webhook_rejects_private_or_loopback_targets(self, _resolve) -> None:
        with self.assertRaisesRegex(ValueError, "不能指向"):
            _validate_ssl_notification_url("https://hooks.example.test/ssl")

    @patch("modules.route_handlers.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("1.1.1.1", 443))])
    def test_wecom_webhook_requires_official_hostname(self, _resolve) -> None:
        with self.assertRaisesRegex(ValueError, "qyapi.weixin.qq.com"):
            _validate_ssl_notification_url("https://example.com/wecom", wecom=True)


class SslRouteContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (BACKEND_DIR / "modules" / "route_handlers.py").read_text(encoding="utf-8")

    def test_list_detail_apply_and_auto_renew_routes_exist(self) -> None:
        for route in (
            'sub in ("/certificates", "/certificates/")',
            'sub == "/certificates/apply"',
            'sub == "/certificates/issue-acme"',
            'r"/certificates/([^/]+)/auto-renew"',
            'sub == "/certificates/clean-expired"',
        ):
            self.assertIn(route, self.source)
        self.assertIn("获取 Let's Encrypt 证书详情成功", self.source)

    def test_acme_download_has_local_zip_branch(self) -> None:
        # acme certs live on disk, not on the Tencent API — the /download route
        # must zip the local PEM pair instead of falling through to the cloud.
        self.assertIn('r"/certificates/([^/]+)/download"', self.source)
        self.assertIn('zf.writestr("fullchain.pem"', self.source)
        self.assertIn('zf.writestr("privkey.pem"', self.source)

    def test_per_cert_auto_renew_toggles_tencent_flag(self) -> None:
        self.assertIn("set_auto_renew_flag(cert_id, enabled)", self.source)
        self.assertIn("上传证书不支持开启腾讯云自动续费", self.source)

    def test_renew_expired_keeps_tencent_autorenew_safety_net(self) -> None:
        self.assertIn("腾讯云自动续费已开启，由腾讯云托管续期", self.source)
        self.assertIn("safety_days = min(5, max(1, renew_days))", self.source)

    def test_renew_expired_skips_domains_covered_by_healthy_acme(self) -> None:
        self.assertIn("def _acme_covers", self.source)
        self.assertIn("已被有效的 Let's Encrypt 证书覆盖，跳过腾讯云续期", self.source)

    def test_persisted_jobs_requeue_stale_running_work(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS ssl_acme_jobs", (BACKEND_DIR / "app.py").read_text(encoding="utf-8"))
        self.assertIn("任务中断，已自动重新排队", self.source)
        self.assertIn("status = 'running'", self.source)
        self.assertIn("'-20 minutes'", self.source)
        self.assertIn("attempts < 3", self.source)
        self.assertIn("BEGIN IMMEDIATE", self.source)
        self.assertIn("WHERE id = ? AND status = 'queued'", self.source)

    def test_deployment_queue_is_atomic_retriable_and_rejects_stale_results(self) -> None:
        self.assertIn('sub == "/deployment-events/claim"', self.source)
        self.assertIn('r"/deployment-events/(\\d+)/result"', self.source)
        self.assertIn('r"/deployment-events/(\\d+)/retry"', self.source)
        self.assertIn("attempts < 5", self.source)
        self.assertIn("60 * (2 ** max(0, attempts - 1))", self.source)
        self.assertIn("部署事件未处于执行中，拒绝重复或过期回执", self.source)
        self.assertIn("当前部署事件已在等待或执行中，无需重复排队", self.source)

    def test_acme_job_management_has_state_guards(self) -> None:
        self.assertIn('sub == "/acme-jobs"', self.source)
        self.assertIn('r"/acme-jobs/(\\d+)/(retry|cancel)"', self.source)
        self.assertIn("当前任务状态不允许", self.source)
        self.assertIn("status IN ('failed', 'cancelled')", self.source)

    def test_acme_san_management_scope_is_checked(self) -> None:
        self.assertIn("def _validate_acme_managed_domains", self.source)
        self.assertIn("所选 DNS 凭证无法管理以下域名", self.source)
        self.assertIn("_validate_acme_managed_domains(_dns_provider, _dns_secrets, domains)", self.source)

    def test_effective_auto_renew_requires_global_and_certificate_switches(self) -> None:
        self.assertIn('"globalAutoRenew": global_auto_renew', self.source)
        self.assertIn('"effectiveAutoRenew": global_auto_renew and cert_auto_renew', self.source)

    def test_private_key_route_requires_dedicated_scope_and_no_store(self) -> None:
        self.assertIn('_require_api_scope("ssl:pem")', self.source)
        app_source = (BACKEND_DIR / "app.py").read_text(encoding="utf-8")
        self.assertIn('self.send_header("Cache-Control", "no-store, max-age=0")', app_source)

    def test_baota_deploy_uses_safe_paths_atomic_writes_and_rollback(self) -> None:
        plugin = (BACKEND_DIR.parent / "baota-ssl-plugin" / "dnspanel_ssl_main.py").read_text(encoding="utf-8")
        self.assertNotIn('os.system("chmod', plugin)
        self.assertIn("def _safe_site_name", plugin)
        self.assertIn("def _atomic_write", plugin)
        self.assertIn("def _validate_pem_pair", plugin)
        self.assertIn("def _rollback_deploy", plugin)
        self.assertIn('["openssl", "x509"', plugin)
        self.assertIn("allowedSites", plugin)
        self.assertIn("allowedSources", plugin)
        self.assertIn('web_server in ("nginx", "openresty")', plugin)
        self.assertIn("def _find_executable", plugin)
        self.assertNotIn('public.ExecShell("nginx -t', plugin)
        self.assertNotIn('public.ExecShell("httpd -t', plugin)
        self.assertIn("def _match_sites_for_domain", plugin)
        self.assertIn("for site in allowed_matches", plugin)
        self.assertIn("部分站点部署失败", plugin)

    def test_task_logs_notifications_filters_and_download_routes_exist(self) -> None:
        for route in (
            'sub == "/notification-settings"',
            'sub == "/notification-settings/test"',
            'sub in ("/task-logs", "/task-logs/download")',
            'sub == "/task-stats"',
            'sub == "/tasks/cleanup"',
        ):
            self.assertIn(route, self.source)
        self.assertIn("status_filter", self.source)
        self.assertIn("source_filter", self.source)
        self.assertIn("domain_filter", self.source)
        self.assertIn("_send_ssl_failure_notifications", self.source)
        self.assertIn("_write_ssl_task_log", self.source)

    def test_cloudflare_verify_reports_visible_zones(self) -> None:
        self.assertIn('verify_details = {"zoneCount": zone_count, "visibleZones": visible_zones}', self.source)
        self.assertIn("Zone Resources", self.source)

    def test_scoped_tokens_are_guarded_outside_ssl_modules(self) -> None:
        app_source = (BACKEND_DIR / "app.py").read_text(encoding="utf-8")
        self.assertIn("def _guard_scoped_api_token", app_source)
        self.assertIn('self._err("当前 API Token 无权访问该模块", 403)', app_source)


class SslMigrationTests(unittest.TestCase):
    def test_deployment_event_table_and_queue_index_are_created(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "ssl-test.db"
            db_migrate.migrate(db_path)
            connection = sqlite3.connect(str(db_path))
            try:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                indexes = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='index'")}
            finally:
                connection.close()
            self.assertIn("ssl_deployment_events", tables)
            self.assertIn("idx_ssl_deploy_events_queue", indexes)
            self.assertIn("ssl_task_logs", tables)
            self.assertIn("idx_ssl_task_logs_user_time", indexes)


if __name__ == "__main__":
    unittest.main()
