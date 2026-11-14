"""Successful Tencent SSL uploads must expose their certificate ID to binders."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from modules.tencent_ssl_api import TencentSslApi


class TencentSslUploadResponseTests(unittest.TestCase):
    def upload(self, response):
        api = TencentSslApi("fixture-id", "fixture-key")
        with patch.object(api, "_tc3_request", return_value=response):
            return api.upload_certificate("fixture-certificate", "fixture-private-key", alias="renewed")

    def test_upload_returns_official_certificate_id(self):
        result = self.upload({"CertificateId": "uploaded-certificate", "RepeatCertId": "", "RequestId": "request-1"})
        self.assertEqual(result, {"CertificateId": "uploaded-certificate"})

    def test_official_certificate_id_takes_precedence_over_fallbacks(self):
        result = self.upload({"CertificateId": "current", "CertId": "legacy", "RepeatCertId": "duplicate"})
        self.assertEqual(result, {"CertificateId": "current"})

    def test_legacy_cert_id_remains_compatible(self):
        for response in ({"CertId": "legacy"}, {"CertificateId": "", "CertId": "legacy"}):
            with self.subTest(response=response):
                self.assertEqual(self.upload(response), {"CertificateId": "legacy"})

    def test_duplicate_response_returns_existing_certificate_id(self):
        result = self.upload({"CertificateId": "", "RepeatCertId": "already-uploaded", "RequestId": "request-2"})
        self.assertEqual(result, {"CertificateId": "already-uploaded"})

    def test_response_without_any_id_does_not_invent_success(self):
        self.assertEqual(self.upload({"RequestId": "request-3"}), {"CertificateId": ""})


if __name__ == "__main__":
    unittest.main()
