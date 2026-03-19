from __future__ import annotations

from typing import Any, Dict, Protocol

from modules.tencent_edgeone_api import TencentEdgeOneApi, TencentEdgeOneApiError


class AccelerationPluginError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = int(status)


class AccelerationPlugin(Protocol):
    provider: str

    def ensure_site(self, zone_name: str) -> Dict[str, Any]:
        ...

    def list_sites(self) -> list[Dict[str, Any]]:
        ...

    def discover_site(self, zone_name: str) -> Dict[str, Any] | None:
        ...

    def get_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        ...

    def verify_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        ...

    def set_site_status(self, zone_name: str, site_id: str | None, enabled: bool) -> Dict[str, Any]:
        ...

    def delete_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        ...


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

    def list_sites(self) -> list[Dict[str, Any]]:
        offset = 0
        limit = 100
        out: list[Dict[str, Any]] = []
        for _ in range(20):
            result = self.api.list_zones(offset=offset, limit=limit)
            zones = result.get("zones") or []
            for zone in zones:
                out.append(
                    {
                        "provider": self.provider,
                        "remoteSiteId": str(zone.get("siteId") or ""),
                        "zoneName": str(zone.get("zoneName") or ""),
                        "siteStatus": str(zone.get("status") or "unknown"),
                        "verifyStatus": str(zone.get("verifyStatus") or zone.get("status") or "unknown"),
                        "verified": bool(zone.get("verified")),
                        "paused": bool(zone.get("paused")),
                        "accessType": str(zone.get("type") or "partial"),
                        "area": str(zone.get("area") or "global"),
                        "planId": str(zone.get("planId") or self._secrets.get("planId") or ""),
                        "verifyRecordName": "",
                        "verifyRecordType": "",
                        "verifyRecordValue": "",
                        "raw": zone.get("raw") if isinstance(zone.get("raw"), dict) else zone,
                    }
                )
            if len(zones) < limit:
                break
            offset += limit
        return out

    def discover_site(self, zone_name: str) -> Dict[str, Any] | None:
        existing = self.api.find_zone_by_name(zone_name)
        if not existing:
            return None
        return self.get_site(zone_name, existing.get("siteId"))

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

    def set_site_status(self, zone_name: str, site_id: str | None, enabled: bool) -> Dict[str, Any]:
        target_site_id = str(site_id or "").strip()
        if not target_site_id:
            site = self.discover_site(zone_name)
            if not site:
                raise AccelerationPluginError("未找到要更新状态的加速站点", 404)
            target_site_id = str(site.get("remoteSiteId") or "")
        self.api.modify_zone_status(target_site_id, enabled)
        return self.get_site(zone_name, target_site_id)

    def delete_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        target_site_id = str(site_id or "").strip()
        if not target_site_id:
            site = self.discover_site(zone_name)
            if not site:
                raise AccelerationPluginError("未找到要删除的加速站点", 404)
            target_site_id = str(site.get("remoteSiteId") or "")
        return self.api.delete_zone(target_site_id)


def build_acceleration_plugin(provider: str, secrets: Dict[str, Any]) -> AccelerationPlugin:
    provider_key = str(provider or "").strip().lower()
    if provider_key == "tencent_edgeone":
        return TencentEdgeOneAccelerationPlugin(secrets)
    raise AccelerationPluginError(f"不支持的加速插件: {provider}", 400)
