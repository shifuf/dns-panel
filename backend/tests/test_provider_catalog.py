from __future__ import annotations

import sys
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.provider_catalog import (  # noqa: E402
    get_all_provider_capabilities,
    get_record_management_provider_types,
    provider_supports_record_management,
)


class ProviderCatalogTests(unittest.TestCase):
    def test_record_management_providers_match_python_dns_implementation(self) -> None:
        expected = {"cloudflare", "dnspod", "dnspod_token"}

        self.assertEqual(set(get_record_management_provider_types()), expected)
        for provider in expected:
            self.assertTrue(provider_supports_record_management(provider))

        for item in get_all_provider_capabilities():
            provider = str(item.get("provider") or "")
            if provider not in expected:
                self.assertFalse(item.get("supportsRecordManagement"), provider)


if __name__ == "__main__":
    unittest.main()
