from __future__ import annotations

from typing import Any, Dict

from modules.tencent_edgeone_api import TencentEdgeOneApi, TencentEdgeOneApiError


class AccelerationPluginError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = int(status)


class TencentEdgeOneAccelerationPlugin:
    provider = "tencent_edgeone"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self._secrets = dict(secrets or {})
        self.api = TencentEdgeOneApi(
            str(self._secrets.get("secretId") or "").strip(),
            str(self._secrets.get("secretKey") or "").strip(),
            str(self._secrets.get("planId") or "").strip() or None,
        )

    def ensure_site(self, zone_name: str) -> Dict[str, Any]:
        existing = self.api.find_zone_by_name(zone_name)
        if existing:
            return self.get_site(zone_name, existing.get("siteId"))
        created = self.api.create_zone(zone_name)
        site = self.get_site(zone_name, created.get("siteId"))
        verification = created.get("verification") or {}
        if verification.get("recordName") and not site.get("verifyRecordName"):
            site["verifyRecordName"] = verification.get("recordName")
            site["verifyRecordType"] = verification.get("recordType") or "TXT"
            site["verifyRecordValue"] = verification.get("recordValue") or ""
        if created.get("planId") and not site.get("planId"):
            site["planId"] = created.get("planId")
        return site

    def get_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        site = self.api.describe_zone(zone_name, zone_id=site_id)
        verify_name = ""
        verify_type = "TXT"
        verify_value = ""
        if not site.get("verified"):
            try:
                identification = self.api.identify_zone(zone_name)
                verification = identification.get("verification") or {}
                verify_name = str(verification.get("recordName") or "")
                verify_type = str(verification.get("recordType") or "TXT")
                verify_value = str(verification.get("recordValue") or "")
                zone = identification.get("zone")
                if isinstance(zone, dict):
                    site = zone
            except TencentEdgeOneApiError:
                pass
        return {
            "provider": self.provider,
            "remoteSiteId": str(site.get("siteId") or site_id or ""),
            "zoneName": str(site.get("zoneName") or zone_name),
            "siteStatus": str(site.get("status") or "unknown"),
            "verifyStatus": str(site.get("verifyStatus") or site.get("status") or "unknown"),
            "verified": bool(site.get("verified")),
            "paused": bool(site.get("paused")),
            "accessType": str(site.get("type") or "partial"),
            "area": str(site.get("area") or "global"),
            "planId": str(site.get("planId") or self._secrets.get("planId") or ""),
            "verifyRecordName": verify_name,
            "verifyRecordType": verify_type,
            "verifyRecordValue": verify_value,
            "raw": site.get("raw") if isinstance(site.get("raw"), dict) else site,
        }

    def verify_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        self.api.identify_zone(zone_name)
        return self.get_site(zone_name, site_id=site_id)


def build_acceleration_plugin(provider: str, secrets: Dict[str, Any]) -> TencentEdgeOneAccelerationPlugin:
    provider_key = str(provider or "").strip().lower()
    if provider_key == "tencent_edgeone":
        return TencentEdgeOneAccelerationPlugin(secrets)
    raise AccelerationPluginError(f"不支持的加速插件: {provider}", 400)
