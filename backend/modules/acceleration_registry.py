from __future__ import annotations

from typing import Any, Dict, Protocol

from modules.tencent_edgeone_api import TencentEdgeOneApi, TencentEdgeOneApiError


class AccelerationPluginError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = int(status)


class AccelerationPlugin(Protocol):
    provider: str

    def ensure_site(self, zone_name: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]:
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
            str(self._secrets.get("endpoint") or "").strip() or None,
        )

    @staticmethod
    def _sub_domain(zone_name: str, acceleration_domain: str) -> str:
        zone = TencentEdgeOneApi.normalize_zone_name(zone_name)
        target = TencentEdgeOneApi.normalize_domain_name(acceleration_domain)
        if not zone or not target or target == zone:
            return "@"
        suffix = f".{zone}"
        return target[:-len(suffix)] if target.endswith(suffix) else target

    def _build_acceleration_domain(self, zone_name: str, config: Dict[str, Any] | None = None) -> str:
        cfg = dict(config or {})
        explicit = TencentEdgeOneApi.normalize_domain_name(str(cfg.get("accelerationDomain") or ""))
        if explicit:
            return explicit
        sub_domain = str(cfg.get("subDomain") or "@").strip()
        zone = TencentEdgeOneApi.normalize_zone_name(zone_name)
        if not zone:
            raise AccelerationPluginError("缺少根域名", 400)
        if not sub_domain or sub_domain == "@":
            return zone
        normalized_sub = sub_domain.rstrip(".").lower()
        if normalized_sub.endswith(f".{zone}"):
            return normalized_sub
        return f"{normalized_sub}.{zone}"

    def _find_matching_domain(self, zone: Dict[str, Any], zone_name: str) -> Dict[str, Any] | None:
        site_id = str(zone.get("siteId") or "")
        if not site_id:
            return None
        target = TencentEdgeOneApi.normalize_zone_name(zone_name)
        items = self.api.list_acceleration_domains(site_id).get("items") or []
        for item in items:
            if TencentEdgeOneApi.normalize_domain_name(item.get("domainName")) == target:
                return item
        return items[0] if items else None

    def _to_state(
        self,
        zone_name: str,
        zone: Dict[str, Any],
        domain: Dict[str, Any] | None = None,
        verification: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        verification = verification or {}
        acceleration_domain = str(domain.get("domainName") or zone_name) if domain else str(zone_name)
        site_status = str(zone.get("status") or "unknown")
        domain_status = str(domain.get("domainStatus") or site_status) if domain else site_status
        verify_status = str(
            domain.get("identificationStatus")
            or domain.get("cnameStatus")
            or zone.get("verifyStatus")
            or domain_status
        ) if domain else str(zone.get("verifyStatus") or site_status)
        return {
            "provider": self.provider,
            "remoteSiteId": str(zone.get("siteId") or ""),
            "zoneName": str(zone.get("zoneName") or zone_name),
            "siteStatus": site_status,
            "verifyStatus": verify_status,
            "verified": bool(domain.get("verified")) if domain else bool(zone.get("verified")),
            "paused": bool(domain.get("paused")) if domain else bool(zone.get("paused")),
            "accessType": str(zone.get("type") or "partial"),
            "area": str(zone.get("area") or "global"),
            "planId": str(zone.get("planId") or self._secrets.get("planId") or ""),
            "accelerationDomain": acceleration_domain,
            "subDomain": self._sub_domain(str(zone.get("zoneName") or zone_name), acceleration_domain),
            "domainStatus": domain_status,
            "identificationStatus": str(domain.get("identificationStatus") or verify_status) if domain else verify_status,
            "cnameTarget": str(domain.get("cnameTarget") or ""),
            "cnameStatus": str(domain.get("cnameStatus") or verify_status) if domain else verify_status,
            "originType": str(domain.get("originType") or "IP_DOMAIN"),
            "originValue": str(domain.get("originValue") or ""),
            "backupOriginValue": str(domain.get("backupOriginValue") or ""),
            "hostHeader": str(domain.get("hostHeader") or ""),
            "originProtocol": str(domain.get("originProtocol") or "FOLLOW"),
            "httpOriginPort": int(domain.get("httpOriginPort") or 80),
            "httpsOriginPort": int(domain.get("httpsOriginPort") or 443),
            "ipv6Status": str(domain.get("ipv6Status") or "follow"),
            "verifyRecordName": str(verification.get("recordName") or domain.get("verifyRecordName") or "") if domain else str(verification.get("recordName") or ""),
            "verifyRecordType": str(verification.get("recordType") or domain.get("verifyRecordType") or "TXT") if domain else str(verification.get("recordType") or "TXT"),
            "verifyRecordValue": str(verification.get("recordValue") or domain.get("verifyRecordValue") or "") if domain else str(verification.get("recordValue") or ""),
            "raw": {
                "zone": zone.get("raw") if isinstance(zone.get("raw"), dict) else zone,
                "domain": domain.get("raw") if isinstance(domain and domain.get("raw"), dict) else domain,
            },
        }

    def ensure_site(self, zone_name: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]:
        existing = self.api.find_zone_by_name(zone_name)
        if existing:
            zone = self.api.describe_zone(zone_name, existing.get("siteId"))
        else:
            created = self.api.create_zone(zone_name)
            zone = self.api.describe_zone(zone_name, created.get("siteId"))
            verification = created.get("verification") or {}
            if config and str(config.get("originValue") or "").strip():
                domain_name = self._build_acceleration_domain(zone_name, config)
                domain = self.api.upsert_acceleration_domain(str(zone.get("siteId") or ""), domain_name, config)
                return self._to_state(zone_name, zone, domain, verification)
            return self._to_state(zone_name, zone, None, verification)

        if config and str(config.get("originValue") or "").strip():
            domain_name = self._build_acceleration_domain(zone_name, config)
            domain = self.api.upsert_acceleration_domain(str(zone.get("siteId") or ""), domain_name, config)
            return self._to_state(zone_name, zone, domain)

        domain = self._find_matching_domain(zone, zone_name)
        return self._to_state(zone_name, zone, domain)

    def list_sites(self) -> list[Dict[str, Any]]:
        offset = 0
        limit = 100
        out: list[Dict[str, Any]] = []
        for _ in range(20):
            result = self.api.list_zones(offset=offset, limit=limit)
            zones = result.get("zones") or []
            for zone in zones:
                domains = self.api.list_acceleration_domains(str(zone.get("siteId") or "")).get("items") or []
                if domains:
                    for domain in domains:
                        out.append(self._to_state(str(zone.get("zoneName") or ""), zone, domain))
                else:
                    out.append(self._to_state(str(zone.get("zoneName") or ""), zone, None))
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
        zone = self.api.describe_zone(zone_name, zone_id=site_id)
        domain = self._find_matching_domain(zone, zone_name)
        verification: Dict[str, Any] = {}
        if not zone.get("verified"):
            try:
                identification = self.api.identify_zone(zone_name)
                verification = identification.get("verification") or {}
                identified_zone = identification.get("zone")
                if isinstance(identified_zone, dict):
                    zone = identified_zone
            except TencentEdgeOneApiError:
                pass
        return self._to_state(zone_name, zone, domain, verification)

    def verify_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        try:
            self.api.identify_zone(zone_name)
        except TencentEdgeOneApiError:
            pass
        return self.get_site(zone_name, site_id=site_id)

    def set_site_status(self, zone_name: str, site_id: str | None, enabled: bool) -> Dict[str, Any]:
        zone = self.api.describe_zone(zone_name, zone_id=site_id)
        domain = self._find_matching_domain(zone, zone_name)
        if domain and domain.get("domainName"):
            self.api.modify_acceleration_domain_statuses(str(zone.get("siteId") or ""), [str(domain.get("domainName") or "")], enabled)
            domain = self.api.get_acceleration_domain(str(zone.get("siteId") or ""), str(domain.get("domainName") or ""))
            return self._to_state(zone_name, zone, domain)
        self.api.modify_zone_status(str(zone.get("siteId") or ""), enabled)
        return self.get_site(zone_name, str(zone.get("siteId") or ""))

    def delete_site(self, zone_name: str, site_id: str | None = None) -> Dict[str, Any]:
        zone = self.api.describe_zone(zone_name, zone_id=site_id)
        domain = self._find_matching_domain(zone, zone_name)
        if domain and domain.get("domainName"):
            return self.api.delete_acceleration_domains(str(zone.get("siteId") or ""), [str(domain.get("domainName") or "")])
        return self.api.delete_zone(str(zone.get("siteId") or ""))


def build_acceleration_plugin(provider: str, secrets: Dict[str, Any]) -> AccelerationPlugin:
    provider_key = str(provider or "").strip().lower()
    if provider_key == "tencent_edgeone":
        return TencentEdgeOneAccelerationPlugin(secrets)
    raise AccelerationPluginError(f"不支持的加速插件: {provider}", 400)
