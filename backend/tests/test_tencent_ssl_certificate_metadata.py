"""Tencent detail metadata must describe the public certificate being reused."""
from __future__ import annotations

import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules import tencent_ssl_api
from modules.route_handlers import _find_uploaded_edge_cert
from modules.tencent_ssl_api import TencentSslApi


class TencentCertificateMetadataTests(unittest.TestCase):
    FINGERPRINT = "B1:C4:E8:E5:A6:16:4E:6C:BB:20:B0:B9:C9:6E:5B:EA:13:6E:92:E8:40:D4:23:DD:7C:02:C8:D8:1F:97:4D:56"

    def setUp(self):
        self.now = datetime(2026, 11, 14, tzinfo=timezone.utc)
        owner = self

        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return owner.now.astimezone(tz) if tz else owner.now.replace(tzinfo=None)

        patcher = patch.object(tencent_ssl_api, "datetime", Clock)
        patcher.start()
        self.addCleanup(patcher.stop)
        pem = (Path(__file__).parent / "data" / "chain-leaf.pem").read_text()
        self.response = {
            "CertificateId": "already-uploaded", "Domain": "*.shifuf.com", "Alias": "dnspanel-acme-wildcard",
            "CertificatePublicKey": pem, "CertificatePrivateKey": "PRIVATE-KEY-MUST-NOT-LEAK",
            "CertFingerprint": "provider-fingerprint-is-not-sha256", "SubjectAltName": [],
            "CertBeginTime": "2026-10-17 06:04:19", "CertEndTime": "2027-01-14 06:04:19",
            "CertificateType": "SVR", "ProductZhName": "uploaded certificate", "Status": 1,
            "IsUpload": True, "RequestId": "fixture-request",
        }

    def detail(self):
        api = TencentSslApi("fixture-id", "fixture-key")
        with patch.object(api, "_tc3_request", return_value=self.response):
            return api.get_certificate("already-uploaded")

    def test_public_pem_supplies_fingerprint_and_actual_certificate_names(self):
        result = self.detail()
        self.assertEqual(result.get("fingerprintSha256"), self.FINGERPRINT)
        self.assertEqual(result["san"], ["*.shifuf.com", "shifuf.com"])
        self.assertEqual(result["issuer"], "Let's Encrypt")
        self.assertEqual(result["remoteCertId"], "already-uploaded")
        self.assertTrue(result["isUploaded"])

    def test_public_pem_uses_true_utc_validity_instead_of_offsetless_cloud_times(self):
        result = self.detail()
        self.assertEqual(result["notBefore"], "2026-10-16T22:04:19Z")
        self.assertEqual(result["notAfter"], "2027-01-13T22:04:19Z")

    def test_expiry_status_and_remaining_days_use_corrected_validity(self):
        self.now = datetime(2027, 1, 14, 0, 0, tzinfo=timezone.utc)
        result = self.detail()
        self.assertEqual(result["status"], "expired")
        self.assertTrue(result["isExpired"])
        self.assertEqual(result["daysRemaining"], -1)

    def test_existing_uploaded_certificate_is_reused_by_alias_and_public_pem_fingerprint(self):
        api = TencentSslApi("fixture-id", "fixture-key")

        def transport(action, payload):
            if action == "DescribeCertificates":
                return {"Certificates": [self.response], "TotalCount": 1}
            if action == "DescribeCertificateDetail" and payload == {"CertificateId": "already-uploaded"}:
                return self.response
            raise AssertionError(f"Unexpected cloud action: {action}")

        with patch.object(api, "_tc3_request", side_effect=transport):
            result = _find_uploaded_edge_cert(api, "dnspanel-acme-wildcard", self.FINGERPRINT)
        self.assertEqual(result, "already-uploaded")

    def test_detail_never_returns_private_key_or_raw_response(self):
        result = self.detail()
        self.assertNotIn("CertificatePrivateKey", result)
        self.assertNotIn("privateKey", result)
        self.assertNotIn("PRIVATE-KEY-MUST-NOT-LEAK", json.dumps(result))

    def test_missing_or_invalid_public_pem_retains_cloud_metadata(self):
        for pem in (None, "invalid-public-certificate"):
            with self.subTest(pem=pem):
                self.response["CertificatePublicKey"] = pem
                result = self.detail()
                self.assertEqual(result["domain"], "*.shifuf.com")
                self.assertEqual(result["notAfter"], "2027-01-14T06:04:19Z")
                self.assertFalse(result.get("fingerprintSha256"))


if __name__ == "__main__":
    unittest.main()
