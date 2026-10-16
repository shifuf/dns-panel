from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch


BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.tencent_edgeone_api import TencentEdgeOneApi, TencentEdgeOneApiError  # noqa: E402


class Ipv6StatusTests(unittest.TestCase):
    """Official enum: follow / on / off. The old mapping swapped on→follow and
    off→close (illegal value), so '关闭 IPv6' requests always failed."""

    def test_official_values_round_trip(self) -> None:
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("follow"), "follow")
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("on"), "on")
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("off"), "off")

    def test_legacy_and_alias_values(self) -> None:
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("close"), "off")
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("disabled"), "off")
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("enabled"), "on")

    def test_unknown_returns_empty(self) -> None:
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status(""), "")
        self.assertEqual(TencentEdgeOneApi._normalize_ipv6_status("bogus"), "")


class UiStateTests(unittest.TestCase):
    """DomainStatus enum: online / process / offline / forbidden / init."""

    def test_forbidden_maps_to_error_not_deploying(self) -> None:
        self.assertEqual(
            TencentEdgeOneApi._compute_ui_state(domain_status="forbidden"),
            "error",
        )

    def test_process_maps_to_deploying(self) -> None:
        self.assertEqual(
            TencentEdgeOneApi._compute_ui_state(domain_status="process"),
            "deploying",
        )
        self.assertEqual(
            TencentEdgeOneApi._compute_ui_state(domain_status="processing"),
            "deploying",
        )

    def test_online_with_cname_success_is_active(self) -> None:
        self.assertEqual(
            TencentEdgeOneApi._compute_ui_state(
                domain_status="online", identification_status="verified", cname_status="active",
            ),
            "active",
        )

    def test_online_without_cname_is_cname_pending_or_deploying(self) -> None:
        state = TencentEdgeOneApi._compute_ui_state(
            domain_status="online", identification_status="verified", cname_status="",
        )
        self.assertIn(state, {"active", "cname_pending"})

    def test_paused_flag_wins(self) -> None:
        self.assertEqual(
            TencentEdgeOneApi._compute_ui_state(domain_status="online", paused=True),
            "paused",
        )


class OriginPayloadTests(unittest.TestCase):
    """Transport params go TOP-LEVEL; OriginInfo holds only the origin block."""

    def test_origin_info_excludes_transport_params(self) -> None:
        info = TencentEdgeOneApi._build_origin_info({
            "originType": "IP_DOMAIN",
            "originValue": "1.2.3.4",
            "originProtocol": "HTTPS",
            "httpOriginPort": 8080,
            "httpsOriginPort": 8443,
            "ipv6Status": "on",
            "hostHeader": "example.com",
        })
        self.assertEqual(info["OriginType"], "IP_DOMAIN")
        self.assertEqual(info["Origin"], "1.2.3.4")
        self.assertEqual(info["HostHeader"], "example.com")
        for bad_key in ("OriginProtocol", "HttpOriginPort", "HttpsOriginPort", "IPv6Status", "Ipv6Status"):
            self.assertNotIn(bad_key, info)

    def test_transport_params_are_applied_top_level(self) -> None:
        payload: dict = {}
        TencentEdgeOneApi._apply_origin_transport_params(payload, {
            "originProtocol": "https",
            "httpOriginPort": 8080,
            "ipv6Status": "close",  # legacy UI value normalizes to off
        })
        self.assertEqual(payload["OriginProtocol"], "HTTPS")
        self.assertEqual(payload["HttpOriginPort"], 8080)
        self.assertEqual(payload["IPv6Status"], "off")
        self.assertNotIn("Ipv6Status", payload)

    def test_missing_origin_value_raises(self) -> None:
        with self.assertRaises(Exception):
            TencentEdgeOneApi._build_origin_info({"originType": "IP_DOMAIN", "originValue": ""})


class VerificationNormalizeTests(unittest.TestCase):
    """DnsVerification uses Subdomain; without reading it the record name came
    back empty and automatic TXT creation silently skipped."""

    def test_dns_verification_subdomain_is_composed(self) -> None:
        result = TencentEdgeOneApi._normalize_verification({
            "ZoneName": "example.com",
            "OwnershipVerification": {
                "DnsVerification": {
                    "Subdomain": "_edgeone-verify",
                    "RecordType": "TXT",
                    "RecordValue": "verify-value-123",
                },
            },
        })
        self.assertEqual(result["recordType"], "TXT")
        self.assertEqual(result["recordValue"], "verify-value-123")
        self.assertTrue(result["recordName"])
        self.assertIn("_edgeone-verify", result["recordName"])
        self.assertIn("example.com", result["recordName"])

    def test_ascription_branch_still_works(self) -> None:
        result = TencentEdgeOneApi._normalize_verification({
            "ZoneName": "example.com",
            "Ascription": {
                "Subdomain": "_verify",
                "RecordType": "TXT",
                "RecordValue": "abc",
            },
        })
        self.assertTrue(result["recordName"])
        self.assertEqual(result["recordValue"], "abc")


class EndpointGuardTests(unittest.TestCase):
    """TC3-signed requests must not be pointed at arbitrary hosts (SSRF)."""

    def test_official_endpoint_allowed(self) -> None:
        api = TencentEdgeOneApi("id", "key", endpoint="teo.tencentcloudapi.com")
        self.assertEqual(api._host, "teo.tencentcloudapi.com")

    def test_arbitrary_host_rejected(self) -> None:
        for bad in ("evil.example.com", "127.0.0.1", "localhost"):
            with self.subTest(host=bad), self.assertRaises(Exception):
                TencentEdgeOneApi("id", "key", endpoint=bad)

    def test_tencent_subdomain_allowed(self) -> None:
        api = TencentEdgeOneApi("id", "key", endpoint="teo.intl.tencentcloudapi.com")
        self.assertEqual(api._host, "teo.intl.tencentcloudapi.com")


class RetryBackoffTests(unittest.TestCase):
    """Transient errors (rate limit / 5xx / network) should retry with bounded
    backoff instead of failing immediately — the old TC3 layer had none."""

    def _api(self) -> TencentEdgeOneApi:
        return TencentEdgeOneApi("id", "key")

    def test_rate_limit_error_is_retried_then_surfaces(self) -> None:
        api = self._api()
        calls = {"n": 0}

        def flaky(action, payload, version=None):
            calls["n"] += 1
            err = TencentEdgeOneApiError("RequestLimitExceeded: too many", 400)
            err.code = "RequestLimitExceeded"
            raise err

        with patch.object(api, "_tc3_request_once", side_effect=flaky), \
             patch("modules.tencent_edgeone_api.time.sleep", return_value=None):
            with self.assertRaises(TencentEdgeOneApiError):
                api._tc3_request("DescribeZones", {})
        # initial attempt + _MAX_RETRIES retries
        self.assertEqual(calls["n"], api._MAX_RETRIES + 1)

    def test_transient_error_recovers_on_retry(self) -> None:
        api = self._api()
        calls = {"n": 0}

        def flaky(action, payload, version=None):
            calls["n"] += 1
            if calls["n"] == 1:
                err = TencentEdgeOneApiError("InternalError: oops", 500)
                err.code = "InternalError"
                raise err
            return {"RequestId": "r1", "Zones": []}

        with patch.object(api, "_tc3_request_once", side_effect=flaky), \
             patch("modules.tencent_edgeone_api.time.sleep", return_value=None):
            result = api._tc3_request("DescribeZones", {})
        self.assertEqual(result.get("RequestId"), "r1")
        self.assertEqual(calls["n"], 2)

    def test_non_retryable_error_raises_immediately(self) -> None:
        api = self._api()
        calls = {"n": 0}

        def hard_fail(action, payload, version=None):
            calls["n"] += 1
            err = TencentEdgeOneApiError("InvalidParameter: bad zone", 400)
            err.code = "InvalidParameter"
            raise err

        with patch.object(api, "_tc3_request_once", side_effect=hard_fail), \
             patch("modules.tencent_edgeone_api.time.sleep", return_value=None):
            with self.assertRaises(TencentEdgeOneApiError):
                api._tc3_request("DescribeZones", {})
        self.assertEqual(calls["n"], 1)


class ZoneCacheTests(unittest.TestCase):
    """Zone traversal must be memoized — find_zone_by_name could otherwise
    issue up to 20 DescribeZones calls per invocation."""

    def test_zone_pages_are_cached_between_calls(self) -> None:
        api = TencentEdgeOneApi("id", "key")
        calls = {"n": 0}

        def fake_list(offset=0, limit=100):
            calls["n"] += 1
            return {"zones": [{"siteId": "z1", "zoneName": "example.com"}], "totalCount": 1}

        with patch.object(api, "list_zones", side_effect=fake_list):
            first = api.find_zone_by_name("example.com")
            second = api.find_zone_by_name("example.com")
        self.assertEqual(first.get("siteId"), "z1")
        self.assertEqual(second.get("siteId"), "z1")
        self.assertEqual(calls["n"], 1)  # second lookup served from cache

    def test_zero_value_zone_page_lookup_is_cached(self) -> None:
        api = TencentEdgeOneApi("id", "key")
        calls = {"n": 0}

        def fake_list(offset=0, limit=100):
            calls["n"] += 1
            return {"zones": [], "totalCount": 0}

        with patch.object(api, "list_zones", side_effect=fake_list):
            self.assertIsNone(api.find_zone_by_name("missing.com"))
            self.assertIsNone(api.find_zone_by_name("missing.com"))
        self.assertEqual(calls["n"], 1)


if __name__ == "__main__":
    unittest.main()
