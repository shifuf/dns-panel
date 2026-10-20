from __future__ import annotations

import subprocess
import sys
import sqlite3
import shutil
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
from modules.route_handlers import (  # noqa: E402
    _ssl_filter_and_summarize, _validate_ssl_notification_url,
    _wildcard_covers, _norm_host,
)
import migrate as db_migrate  # noqa: E402


class WildcardCoverTests(unittest.TestCase):
    """TLS semantics for the acceleration-cert domain matching."""

    def test_exact_and_wildcard(self) -> None:
        self.assertTrue(_wildcard_covers("api.example.com", "api.example.com"))
        self.assertTrue(_wildcard_covers("*.example.com", "account.example.com"))
        self.assertFalse(_wildcard_covers("*.example.com", "example.com"))
        self.assertFalse(_wildcard_covers("*.example.com", "a.b.example.com"))

    def test_literal_wildcard_host_only_matches_itself(self) -> None:
        self.assertTrue(_wildcard_covers("*.example.com", "*.example.com"))
        self.assertFalse(_wildcard_covers("api.example.com", "*.example.com"))

    def test_norm_host_strips_dots_and_lowercases(self) -> None:
        self.assertEqual(_norm_host("Example.COM."), "example.com")
        self.assertEqual(_norm_host(None), "")
        self.assertEqual(_norm_host("  *.Foo.com "), "*.foo.com")


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

    def test_expiry_notification_scan_targets_30_7_1_days(self) -> None:
        self.assertIn("def _check_ssl_expiry_notifications", self.source)
        self.assertIn("thresholds = (30, 7, 1)", self.source)
        self.assertIn('"event": "ssl_expiry_warning"', self.source)
        # dedup marker keyed by band + exact expiry so a renewed cert re-alerts
        self.assertIn('marker = f"expiry:{band}"', self.source)

    def test_batch_routes_exist_and_are_scoped(self) -> None:
        self.assertIn('sub == "/certificates/batch-deploy"', self.source)
        self.assertIn('sub == "/certificates/batch-auto-renew"', self.source)
        self.assertIn('"/certificates/batch-deploy", "/certificates/batch-auto-renew"', self.source)
        self.assertIn('sub == "/certificates/check-expiry"', self.source)
        self.assertIn('sub == "/deployments/by-site"', self.source)
        self.assertIn('sub == "/acme-cas"', self.source)
        self.assertIn('sub == "/plugin-version"', self.source)

    def test_acme_multi_ca_and_eab_are_supported(self) -> None:
        acme_source = (BACKEND_DIR / "modules" / "acme_api.py").read_text(encoding="utf-8")
        self.assertIn("ACME_SUPPORTED_CAS", acme_source)
        self.assertIn('"zerossl"', acme_source)
        self.assertIn("def resolve_ca_server", acme_source)
        self.assertIn("--eab-kid", acme_source)
        self.assertIn("--eab-hmac-key", acme_source)
        # jobs carry the CA/EAB choice through to the worker
        self.assertIn("ca, eabKid, eabHmac, operation", self.source)

    def test_acme_private_key_stored_encrypted(self) -> None:
        acme_source = (BACKEND_DIR / "modules" / "acme_api.py").read_text(encoding="utf-8")
        self.assertIn("def _encrypt_pem_text", acme_source)
        self.assertIn("def _read_private_key", acme_source)
        self.assertIn("_write_private_key(privkey, raw_key)", acme_source)

    def test_edgeone_cert_sync_routes_and_helpers_exist(self) -> None:
        for probe in (
            'sub == "/certificates/sync-edgeone"',
            'sub == "/edgeone-bindings"',
            "acceleration_cert_bindings",
            "def _sync_cert_to_edgeone",
            "def _accel_targets_for_domain",
            "def _edge_cert_id_for_ssl_cert",
            "def _best_cert_for_domain",
            "def _download_tencent_cert_pem",
        ):
            self.assertIn(probe, self.source)
        # deploy result + acme job success + accel enable all trigger the sync
        self.assertIn("_sync_cert_to_edgeone(self, uid, cert_row)", self.source)
        self.assertIn("_sync_cert_to_edgeone(self, uid, fresh)", self.source)
        self.assertIn("edgeoneCertSync", self.source)
        # cross-account certs must be re-uploaded, not reused by id
        self.assertIn("same_account", self.source)
        # "all" sync must only bind the freshest cert per domain
        self.assertIn("seen_domains.add(domain_key)", self.source)

    def test_multi_cdn_binders_are_registered(self) -> None:
        # All three CDN providers have a real cert binder — none fall back to
        # the unsupported-reason stub.
        self.assertIn("def _bind_cert_to_cloudflare_provider", self.source)
        self.assertIn("def _bind_cert_to_esa_provider", self.source)
        self.assertIn('"cloudflare": _bind_cert_to_cloudflare_provider', self.source)
        self.assertIn('"aliyun_esa": _bind_cert_to_esa_provider', self.source)
        self.assertNotIn('_ACCEL_CERT_UNSUPPORTED_REASON: Dict[str, str] = {\n    "aliyun_esa":', self.source)
        # CF pushes the panel PEM onto the custom hostname (type=custom)
        cf_source = (BACKEND_DIR / "modules" / "cloudflare_api.py").read_text(encoding="utf-8")
        self.assertIn("def update_custom_hostname_custom_certificate", cf_source)
        self.assertIn('"custom_certificate"', cf_source)
        # Native target discovery for panel-external CF/ESA resources
        self.assertIn("def _native_cdn_targets", self.source)
        self.assertIn("def _discover_cf_hostname_targets", self.source)
        self.assertIn("def _discover_esa_record_targets", self.source)
        self.assertIn("ssl:cdn-targets:user:", self.source)

    def test_cert_delete_paths_clean_up_uploaded_accel_temp_certs(self) -> None:
        # Panel-uploaded temp certs in acceleration accounts must be removed
        # wherever a cert dies: single delete (acme + tencent), sync prune,
        # clean-expired, prune-superseded and credential deletion.
        self.assertIn("def _cleanup_edgeone_cert_for_cert", self.source)
        self.assertGreaterEqual(self.source.count("_cleanup_edgeone_cert_for_cert("), 6)

    def test_accel_binding_drift_view_is_wildcard_aware(self) -> None:
        self.assertIn("def _accel_binding_drift_view", self.source)
        self.assertIn("_wildcard_covers(n, domain)", self.source)
        # the endpoint must use the shared drift view helper (with the
        # preloaded issued-cert rows to avoid a query per binding)
        self.assertIn("_accel_binding_drift_view(uid, dict(row), issued_rows)", self.source)

    def test_success_event_webhook_opt_in_is_persisted_and_sent(self) -> None:
        self.assertIn("def _push_ssl_success_event", self.source)
        # the settings save endpoint must round-trip the opt-in flag
        self.assertIn('"notifySuccessWebhook": bool(body.get("notifySuccessWebhook"', self.source)
        # renew (tencent inline), issue (acme job) and deploy success all push
        for event in ('"ssl_renewal_succeeded"', '"ssl_issue_succeeded"', '"ssl_deployment_succeeded"'):
            self.assertIn(event, self.source)

    def test_persisted_jobs_requeue_stale_running_work(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS ssl_acme_jobs", (BACKEND_DIR / "app.py").read_text(encoding="utf-8"))
        self.assertIn("任务中断，已自动重新排队", self.source)
        self.assertIn("status = 'running'", self.source)
        self.assertIn("'-20 minutes'", self.source)
        self.assertIn("attempts < 3", self.source)
        self.assertIn("BEGIN IMMEDIATE", self.source)
        self.assertIn("WHERE id = ? AND status = 'queued'", self.source)

    def test_expired_certificates_are_blocked_from_deploy_paths(self) -> None:
        self.assertIn('证书已过期，禁止部署（请先续期）', self.source)
        self.assertIn('证书已过期，禁止部署（请续期或删除）', self.source)
        self.assertIn('reason": "证书已过期"', self.source)
        self.assertIn('"证书已过期，禁止部署（请续期或删除）"', self.source)

    def test_upload_accepts_unique_ssl_credential_when_credential_missing(self) -> None:
        self.assertIn('if not cred_id_raw:', self.source)
        self.assertIn("provider IN ('tencent_ssl', 'dnspod')", self.source)
        self.assertIn('ORDER BY isDefault DESC, createdAt ASC', self.source)

    def test_ssl_backup_includes_acme_and_edgeone_runtime_state(self) -> None:
        app_source = (BACKEND_DIR / "app.py").read_text(encoding="utf-8")
        for probe in (
            '"acmeCertificates"',
            '"acmeJobs"',
            '"accelerationStates"',
            '"accelerationBindings"',
            '"accelerationRequests"',
            '"acmeRuntime"',
            'def _export_acme_runtime_files',
            'def _restore_acme_runtime_files',
            'Path("deployed") / safe / name',
        ):
            self.assertIn(probe, app_source)
        self.assertIn('certificate_id_map', app_source)
        self.assertIn('acmeRuntimeFiles', app_source)

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

    def test_acceleration_cert_tables_and_columns_are_created(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "ssl-test.db"
            db_migrate.migrate(db_path)
            connection = sqlite3.connect(str(db_path))
            try:
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                cert_cols = {row[1] for row in connection.execute("PRAGMA table_info(ssl_certificates)")}
                job_cols = {row[1] for row in connection.execute("PRAGMA table_info(ssl_acme_jobs)")}
            finally:
                connection.close()
            self.assertIn("acceleration_cert_requests", tables)
            self.assertIn("acceleration_cert_bindings", tables)
            self.assertIn("acmeCa", cert_cols)
            for col in ("ca", "eabKid", "eabHmac"):
                self.assertIn(col, job_cols)


class EdgeOneSyncFlowTests(unittest.TestCase):
    """End-to-end (mocked) test of the cert→EdgeOne binding flow."""

    def _build(self):
        d = tempfile.mkdtemp()
        db = Path(d) / "t.db"
        db_migrate.migrate(db)
        raw = sqlite3.connect(str(db))
        raw.row_factory = sqlite3.Row
        raw.execute(
            """INSERT INTO dns_record_acceleration_states
               (userId, dnsCredentialId, zoneId, zoneName, recordId, recordName,
                accelerationProvider, accelerationCredentialId, accelerationSiteId,
                accelerationDomain, accelerationTarget, originalRecord, enabled)
               VALUES (1,1,'z','example.com','r1','cdn','edgeone',5,'site1',
                       'cdn.example.com','tgt.dnse.com','{}',1)"""
        )
        raw.execute(
            """INSERT INTO ssl_certificates
               (userId, credentialId, provider, remoteCertId, domain, status, notAfter, autoRenew)
               VALUES (1, 9, 'tencent_ssl', 'SSLCERT-1', 'cdn.example.com', 'issued', '2027-01-01T00:00:00Z', 0)"""
        )
        raw.commit()
        self.addCleanup(lambda: (raw.close(), shutil.rmtree(d, ignore_errors=True)))
        return rh if False else None, raw, db

    def test_same_account_tencent_cert_reuses_cert_id(self) -> None:
        import modules.route_handlers as rh
        _, raw, db = self._build()
        orig = (rh.conn, rh.now_iso, rh.cache_delete_pattern)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-17T00:00:00Z"
        rh.cache_delete_pattern = lambda *a, **k: None

        calls = []

        class FakeAccelApi:
            def modify_hosts_certificate(self, site, hosts, mode, cert_id):
                calls.append((site, hosts, mode, cert_id))
                return {}

        class FakeHandler:
            def _acceleration_auth(self, uid, cid):
                return {"api": FakeAccelApi(), "credential": {"secrets": "x"}, "provider": "edgeone"}

            def _credential_secrets(self, row):
                return {"secretId": "AKID-SAME", "secretKey": "SK"}

            def _get_credential_row(self, uid, cid):
                return {"secrets": "x"}

        try:
            cert = raw.execute("SELECT * FROM ssl_certificates WHERE remoteCertId='SSLCERT-1'").fetchone()
            out = rh._sync_cert_to_edgeone(FakeHandler(), 1, cert)
        finally:
            rh.conn, rh.now_iso, rh.cache_delete_pattern = orig
        self.assertEqual(out["synced"], 1)
        self.assertEqual(calls, [("site1", ["cdn.example.com"], "sslcert", "SSLCERT-1")])

    def test_dry_run_does_not_upload_or_bind(self) -> None:
        import modules.route_handlers as rh
        _, raw, db = self._build()
        orig = (rh.conn, rh.now_iso, rh.cache_delete_pattern)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-17T00:00:00Z"
        rh.cache_delete_pattern = lambda *a, **k: None

        calls = []

        class FakeAccelApi:
            def modify_hosts_certificate(self, *a):
                calls.append(a)
                return {}

        class FakeHandler:
            def _acceleration_auth(self, uid, cid):
                return {"api": FakeAccelApi(), "credential": {"secrets": "x"}, "provider": "edgeone"}

            def _credential_secrets(self, row):
                return {"secretId": "AKID", "secretKey": "SK"}

            def _get_credential_row(self, uid, cid):
                return {"secrets": "x"}

        try:
            cert = raw.execute("SELECT * FROM ssl_certificates WHERE remoteCertId='SSLCERT-1'").fetchone()
            out = rh._sync_cert_to_edgeone(FakeHandler(), 1, cert, dry_run=True)
        finally:
            rh.conn, rh.now_iso, rh.cache_delete_pattern = orig
        # preview reports the target but performs NO cloud bind
        self.assertEqual(calls, [])
        self.assertTrue(all(r.get("dryRun") for r in out["results"]))

    def test_no_acceleration_returns_skipped(self) -> None:
        import modules.route_handlers as rh
        d = tempfile.mkdtemp()
        db = Path(d) / "t.db"
        db_migrate.migrate(db)
        raw = sqlite3.connect(str(db))
        raw.row_factory = sqlite3.Row
        raw.execute(
            """INSERT INTO ssl_certificates
               (userId, credentialId, provider, remoteCertId, domain, status, notAfter, autoRenew)
               VALUES (1, 9, 'tencent_ssl', 'SSLCERT-2', 'plain.example.com', 'issued', '2027-01-01T00:00:00Z', 0)"""
        )
        raw.commit()
        self.addCleanup(lambda: (raw.close(), shutil.rmtree(d, ignore_errors=True)))
        orig = (rh.conn, rh.now_iso, rh.cache_delete_pattern)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-17T00:00:00Z"
        rh.cache_delete_pattern = lambda *a, **k: None
        try:
            cert = raw.execute("SELECT * FROM ssl_certificates WHERE remoteCertId='SSLCERT-2'").fetchone()
            out = rh._sync_cert_to_edgeone(object(), 1, cert)
        finally:
            rh.conn, rh.now_iso, rh.cache_delete_pattern = orig
        self.assertEqual(out["synced"], 0)
        self.assertIn("没有已启用", out.get("skipped", ""))


class AccelTempCertCleanupTests(unittest.TestCase):
    """Deleting a panel cert must remove the temp certs the panel uploaded into
    acceleration accounts for it (and its binding rows)."""

    def _build(self):
        d = tempfile.mkdtemp()
        db = Path(d) / "t.db"
        db_migrate.migrate(db)
        raw = sqlite3.connect(str(db))
        raw.row_factory = sqlite3.Row
        raw.execute(
            """INSERT INTO acceleration_cert_bindings
               (userId, provider, accelerationCredentialId, siteId, domainName,
                source, certRemoteId, edgeCertId, fingerprint, notAfter,
                status, syncedAt, createdAt, updatedAt)
               VALUES (1, 'edgeone', 5, 'site1', 'cdn.example.com',
                       'acme', 'example.com', 'UPLOADED-1', 'FP1', '2027-01-01T00:00:00Z',
                       'synced', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z')"""
        )
        raw.commit()
        self.addCleanup(lambda: (raw.close(), shutil.rmtree(d, ignore_errors=True)))
        return raw, db

    def test_uploaded_temp_cert_is_deleted_and_bindings_dropped(self) -> None:
        import modules.route_handlers as rh
        raw, _ = self._build()
        orig = (rh.conn, rh.now_iso, rh.TencentSslApi)
        deleted = []

        class FakeSslApi:
            def __init__(self, sid, skey):
                self.sid = sid

            def delete_certificate(self, cert_id):
                deleted.append(cert_id)
                return {}

        class FakeHandler:
            def _acceleration_auth(self, uid, cid):
                return {"credential": {"secrets": "x"}, "provider": "edgeone"}

            def _credential_secrets(self, row):
                return {"secretId": "AKID", "secretKey": "SK"}

        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-18T00:00:00Z"
        rh.TencentSslApi = FakeSslApi
        try:
            out = rh._cleanup_edgeone_cert_for_cert(FakeHandler(), 1, {"remoteCertId": "example.com", "provider": "acme"})
        finally:
            rh.conn, rh.now_iso, rh.TencentSslApi = orig
        self.assertEqual(deleted, ["UPLOADED-1"])
        self.assertEqual(out["removedEdgeCerts"], ["UPLOADED-1"])
        left = raw.execute("SELECT COUNT(*) c FROM acceleration_cert_bindings").fetchone()["c"]
        self.assertEqual(left, 0)

    def test_same_account_cert_id_is_never_deleted(self) -> None:
        # A same-account Tencent cert reuses the cert's own cloud id — that is
        # the user's real certificate, not a temp upload, and must survive.
        import modules.route_handlers as rh
        raw, _ = self._build()
        raw.execute(
            """UPDATE acceleration_cert_bindings SET source='tencent_ssl', certRemoteId='SSLCERT-9',
               edgeCertId='SSLCERT-9'"""
        )
        raw.commit()
        orig = (rh.conn, rh.now_iso, rh.TencentSslApi)
        deleted = []

        class FakeSslApi:
            def __init__(self, sid, skey):
                pass

            def delete_certificate(self, cert_id):
                deleted.append(cert_id)
                return {}

        class FakeHandler:
            def _acceleration_auth(self, uid, cid):
                return {"credential": {"secrets": "x"}, "provider": "edgeone"}

            def _credential_secrets(self, row):
                return {"secretId": "AKID", "secretKey": "SK"}

        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-18T00:00:00Z"
        rh.TencentSslApi = FakeSslApi
        try:
            rh._cleanup_edgeone_cert_for_cert(FakeHandler(), 1, {"remoteCertId": "SSLCERT-9", "provider": "tencent_ssl"})
        finally:
            rh.conn, rh.now_iso, rh.TencentSslApi = orig
        self.assertEqual(deleted, [])
        left = raw.execute("SELECT COUNT(*) c FROM acceleration_cert_bindings").fetchone()["c"]
        self.assertEqual(left, 0)


class AccelBindingDriftViewTests(unittest.TestCase):
    def _build(self):
        d = tempfile.mkdtemp()
        db = Path(d) / "t.db"
        db_migrate.migrate(db)
        raw = sqlite3.connect(str(db))
        raw.row_factory = sqlite3.Row
        raw.execute(
            """INSERT INTO ssl_certificates
               (userId, credentialId, provider, remoteCertId, domain, san, status, notAfter, autoRenew)
               VALUES (1, 9, 'acme', 'example.com', '*.example.com', '["*.example.com"]',
                       'issued', '2027-01-01T00:00:00Z', 1)"""
        )
        raw.commit()
        self.addCleanup(lambda: (raw.close(), shutil.rmtree(d, ignore_errors=True)))
        return raw

    def test_wildcard_cert_covers_edge_host(self) -> None:
        import modules.route_handlers as rh
        raw = self._build()
        orig = rh.conn
        rh.conn = lambda: raw
        try:
            # binding carries the wildcard cert's own remoteCertId → up to date
            item = rh._accel_binding_drift_view(1, {"domainName": "cdn.example.com", "source": "acme", "certRemoteId": "example.com"})
            self.assertTrue(item["upToDate"])
            self.assertEqual(item["currentCertRemoteId"], "example.com")
            # an older binding id → drift
            item2 = rh._accel_binding_drift_view(1, {"domainName": "cdn.example.com", "source": "acme", "certRemoteId": "old.example.com"})
            self.assertFalse(item2["upToDate"])
        finally:
            rh.conn = orig

    def test_no_matching_cert_reports_unknown(self) -> None:
        import modules.route_handlers as rh
        raw = self._build()
        orig = rh.conn
        rh.conn = lambda: raw
        try:
            item = rh._accel_binding_drift_view(1, {"domainName": "other.example.net", "source": "acme", "certRemoteId": "x"})
            self.assertIsNone(item["upToDate"])
        finally:
            rh.conn = orig


class MultiCdnBinderTests(unittest.TestCase):
    """Cloudflare / ESA binders: real cert linkage, provider-appropriate."""

    CERT_PEM = (
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    )
    KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"

    class FakeHandler:
        def __init__(self, secrets):
            self._secrets = secrets

        def _get_credential_row(self, uid, cid):
            if cid == 999:
                return None
            return {"id": cid, "provider": self._secrets.get("_provider", "cloudflare"), "secrets": "x"}

        def _credential_secrets(self, row):
            return {k: v for k, v in self._secrets.items() if not k.startswith("_")}

    def test_cloudflare_binder_pushes_pem_to_matching_hostname(self) -> None:
        import modules.route_handlers as rh
        pushed = []

        class FakeCf:
            def __init__(self, token):
                if token != "tok":
                    raise AssertionError("bad token")

            def list_zones(self, page, size):
                return {"zones": [{"id": "zone1", "name": "example.com"}], "total": 1}

            def list_all_custom_hostnames(self, zone_id, max_pages=10):
                return [{"id": "ch1", "hostname": "cdn.example.com"}]

            def update_custom_hostname_custom_certificate(self, zone_id, hostname_id, cert, key):
                pushed.append((zone_id, hostname_id, cert, key))
                return {}

        orig_cf, orig_pem = rh.CloudflareApi, rh._panel_cert_pem
        rh.CloudflareApi = FakeCf
        rh._panel_cert_pem = lambda handler, uid, cert_row: {"publicKey": self.CERT_PEM, "privateKey": self.KEY_PEM}
        try:
            handler = self.FakeHandler({"apiToken": "tok", "_provider": "cloudflare"})
            edge_id = rh._bind_cert_to_cloudflare_provider(
                handler, 1, 7, "zone1", {"provider": "acme", "remoteCertId": "example.com"}, "cdn.example.com", False,
            )
        finally:
            rh.CloudflareApi, rh._panel_cert_pem = orig_cf, orig_pem
        # zone_id is used as-is when provided; the PEM pair is pushed
        self.assertEqual(pushed, [("zone1", "ch1", self.CERT_PEM, self.KEY_PEM)])
        self.assertTrue(edge_id.startswith("cf-custom:"))

    def test_cloudflare_binder_requires_custom_hostname(self) -> None:
        import modules.route_handlers as rh

        class FakeCf:
            def __init__(self, token):
                pass

            def list_zones(self, page, size):
                return {"zones": [{"id": "zone1", "name": "example.com"}], "total": 1}

            def list_all_custom_hostnames(self, zone_id, max_pages=10):
                return []

            def update_custom_hostname_custom_certificate(self, *a):
                raise AssertionError("must not push without a custom hostname")

        orig_cf = rh.CloudflareApi
        rh.CloudflareApi = FakeCf
        try:
            handler = self.FakeHandler({"apiToken": "tok"})
            with self.assertRaises(ValueError) as cm:
                rh._bind_cert_to_cloudflare_provider(
                    handler, 1, 7, "zone1", {"provider": "acme", "remoteCertId": "x"}, "cdn.example.com", False,
                )
            self.assertIn("自定义主机名", str(cm.exception))
        finally:
            rh.CloudflareApi = orig_cf

    def test_esa_binder_reuses_valid_cert_without_applying(self) -> None:
        import modules.route_handlers as rh
        applied = []

        def fake_list_certs(ak, sk, region, site, names, valid_only, detail):
            return {"records": [{"recordName": "cdn.example.com", "certificates": [{"id": "ESA-CERT-1"}]}]}

        def fake_apply(*a, **k):
            applied.append(a)
            return {"results": []}

        orig_list, orig_apply = rh.esa_list_certificates_by_record, rh.esa_apply_certificate
        rh.esa_list_certificates_by_record = fake_list_certs
        rh.esa_apply_certificate = fake_apply
        try:
            handler = self.FakeHandler({"accessKeyId": "ak", "accessKeySecret": "sk", "_provider": "aliyun"})
            edge_id = rh._bind_cert_to_esa_provider(
                handler, 1, 7, "site1", {"provider": "acme", "remoteCertId": "x"}, "cdn.example.com", False,
            )
        finally:
            rh.esa_list_certificates_by_record, rh.esa_apply_certificate = orig_list, orig_apply
        self.assertEqual(edge_id, "esa-managed:ESA-CERT-1")
        self.assertEqual(applied, [])

    def test_esa_binder_applies_free_cert_when_missing(self) -> None:
        import modules.route_handlers as rh

        def fake_list_certs(*a, **k):
            return {"records": [{"recordName": "cdn.example.com", "certificates": None}]}

        def fake_apply(ak, sk, region, site, domains, cert_type):
            return {"results": [{"domain": "cdn.example.com", "certificateId": "NEW-1", "status": "applying"}]}

        orig_list, orig_apply = rh.esa_list_certificates_by_record, rh.esa_apply_certificate
        rh.esa_list_certificates_by_record = fake_list_certs
        rh.esa_apply_certificate = fake_apply
        try:
            handler = self.FakeHandler({"accessKeyId": "ak", "accessKeySecret": "sk", "_provider": "aliyun"})
            edge_id = rh._bind_cert_to_esa_provider(
                handler, 1, 7, "site1", {"provider": "acme", "remoteCertId": "x"}, "cdn.example.com", False,
            )
        finally:
            rh.esa_list_certificates_by_record, rh.esa_apply_certificate = orig_list, orig_apply
        self.assertEqual(edge_id, "esa-applied:NEW-1")

    def test_binder_credential_provider_mismatch_is_rejected(self) -> None:
        import modules.route_handlers as rh
        handler = self.FakeHandler({"apiToken": "tok", "_provider": "cloudflare"})
        with self.assertRaises(ValueError):
            rh._cdn_binding_credential(handler, 1, 7, "aliyun")


class PreExpiryDeployTests(unittest.TestCase):
    """The daily pre-expiry (≤7d) deploy guarantee."""

    def _build(self, not_after: str):
        d = tempfile.mkdtemp()
        db = Path(d) / "t.db"
        db_migrate.migrate(db)
        raw = sqlite3.connect(str(db))
        raw.row_factory = sqlite3.Row
        raw.execute(
            """INSERT INTO ssl_certificates
               (userId, credentialId, provider, remoteCertId, domain, status, notAfter, autoRenew)
               VALUES (1, 9, 'tencent_ssl', 'SSLCERT-1', 'cdn.example.com', 'issued', ?, 0)""",
            (not_after,),
        )
        raw.commit()
        self.addCleanup(lambda: (raw.close(), shutil.rmtree(d, ignore_errors=True)))
        return raw

    def test_soon_expiring_cert_is_queued(self) -> None:
        import modules.route_handlers as rh
        # ~3 days out → inside the 7-day pre-expiry window.
        from datetime import datetime, timedelta, timezone
        soon = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = self._build(soon)
        orig = (rh.conn, rh.now_iso)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-18T00:00:00Z"
        try:
            out = rh._ensure_pre_expiry_deployments(1)
        finally:
            rh.conn, rh.now_iso = orig
        self.assertEqual(out["queued"], 1)
        self.assertIn("cdn.example.com", out["domains"])
        row = raw.execute("SELECT status FROM ssl_deployment_events WHERE userId=1").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "queued")

    def test_far_expiring_cert_is_skipped(self) -> None:
        import modules.route_handlers as rh
        from datetime import datetime, timedelta, timezone
        far = (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = self._build(far)
        orig = (rh.conn, rh.now_iso)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-18T00:00:00Z"
        try:
            out = rh._ensure_pre_expiry_deployments(1)
        finally:
            rh.conn, rh.now_iso = orig
        self.assertEqual(out["queued"], 0)
        self.assertEqual(raw.execute("SELECT COUNT(*) c FROM ssl_deployment_events").fetchone()["c"], 0)

    def test_requeues_a_success_event_for_pre_expiry(self) -> None:
        import modules.route_handlers as rh
        from datetime import datetime, timedelta, timezone
        soon = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = self._build(soon)
        raw.execute(
            """INSERT INTO ssl_deployment_events
               (userId, provider, remoteCertId, credentialId, domain, source, status, attempts, createdAt, updatedAt)
               VALUES (1,'tencent_ssl','SSLCERT-1',9,'cdn.example.com','tencent','success',1,'x','x')"""
        )
        raw.commit()
        orig = (rh.conn, rh.now_iso)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-18T00:00:00Z"
        try:
            out = rh._ensure_pre_expiry_deployments(1)
        finally:
            rh.conn, rh.now_iso = orig
        self.assertEqual(out["queued"], 1)
        row = raw.execute("SELECT status, attempts FROM ssl_deployment_events WHERE userId=1").fetchone()
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["attempts"], 0)

    def test_queued_event_is_left_untouched(self) -> None:
        import modules.route_handlers as rh
        from datetime import datetime, timedelta, timezone
        soon = (datetime.now(timezone.utc) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        raw = self._build(soon)
        raw.execute(
            """INSERT INTO ssl_deployment_events
               (userId, provider, remoteCertId, credentialId, domain, source, status, attempts, createdAt, updatedAt)
               VALUES (1,'tencent_ssl','SSLCERT-1',9,'cdn.example.com','tencent','queued',2,'x','x')"""
        )
        raw.commit()
        orig = (rh.conn, rh.now_iso)
        rh.conn = lambda: raw
        rh.now_iso = lambda: "2026-10-18T00:00:00Z"
        try:
            out = rh._ensure_pre_expiry_deployments(1)
        finally:
            rh.conn, rh.now_iso = orig
        # Already queued → not counted as re-armed, attempts preserved.
        self.assertEqual(out["queued"], 0)
        row = raw.execute("SELECT status, attempts FROM ssl_deployment_events WHERE userId=1").fetchone()
        self.assertEqual(row["status"], "queued")
        self.assertEqual(row["attempts"], 2)


if __name__ == "__main__":
    unittest.main()
