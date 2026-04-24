from __future__ import annotations

from typing import Any, Dict

from modules.acceleration_registry import (
    AccelerationPluginDefinition,
    AccelerationPluginError,
    register_acceleration_plugin,
)
from modules.tencent_edgeone_api import TencentEdgeOneApi, TencentEdgeOneApiError


class EdgeOneAccelerationPlugin:
    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.secrets = dict(secrets or {})
        self.api = TencentEdgeOneApi(
            str(self.secrets.get("secretId") or "").strip(),
            str(self.secrets.get("secretKey") or "").strip(),
            plan_id=str(self.secrets.get("planId") or "").strip() or None,
            endpoint=str(self.secrets.get("endpoint") or "").strip() or None,
        )

    @staticmethod
    def validate(secrets: Dict[str, Any]) -> None:
        secret_id = str(secrets.get("secretId") or "").strip()
        secret_key = str(secrets.get("secretKey") or "").strip()
        if not secret_id or not secret_key:
            raise AccelerationPluginError("缺少 EdgeOne SecretId / SecretKey", 400)
        api = TencentEdgeOneApi(
            secret_id,
            secret_key,
            plan_id=str(secrets.get("planId") or "").strip() or None,
            endpoint=str(secrets.get("endpoint") or "").strip() or None,
        )
        api.list_zones(0, 1)

    def list_sites(self) -> list[Dict[str, Any]]:
        offset = 0
        limit = 100
        sites: list[Dict[str, Any]] = []
        for _ in range(20):
            data = self.api.list_zones(offset=offset, limit=limit)
            batch = data.get("zones") if isinstance(data, dict) else []
            items = [item for item in (batch or []) if isinstance(item, dict)]
            sites.extend(items)
            if len(items) < limit:
                break
            offset += limit
        return sites

    def discover_site(self, zone_name: str) -> Dict[str, Any] | None:
        return self.api.find_zone_by_name(zone_name)

    def get_site(
        self,
        zone_name: str,
        site_id: str | None = None,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return self.api.describe_zone(zone_name, site_id)

    def ensure_site(self, zone_name: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]:
        options = dict(config or {})
        existing = self.api.find_zone_by_name(zone_name)
        if existing:
            return existing
        created = self.api.create_zone(
            zone_name,
            plan_id=str(options.get("planId") or "").strip() or None,
            area=str(options.get("area") or "global").strip() or "global",
            zone_type=str(options.get("type") or options.get("zoneType") or "partial").strip() or "partial",
        )
        if created:
            return created
        existing = self.api.find_zone_by_name(zone_name)
        if existing:
            return existing
        raise AccelerationPluginError("创建站点失败", 500)

    def verify_site(
        self,
        zone_name: str,
        site_id: str | None = None,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        options = dict(config or {})
        verification_code = str(
            options.get("verificationCode")
            or options.get("code")
            or ""
        ).strip()
        if verification_code:
            return self.api.verify_ownership(zone_name, verification_code, site_id=site_id)
        return self.api.identify_zone(zone_name)

    def set_site_status(
        self,
        zone_name: str,
        site_id: str | None,
        enabled: bool,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        target = site_id
        if not target:
            current = self.api.describe_zone(zone_name, site_id)
            target = str(current.get("siteId") or current.get("zoneId") or "").strip()
        if not target:
            raise AccelerationPluginError("缺少站点 ID", 400)
        return self.api.modify_zone_status(target, enabled)

    def delete_site(
        self,
        zone_name: str,
        site_id: str | None = None,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        target = site_id
        if not target:
            current = self.api.describe_zone(zone_name, site_id)
            target = str(current.get("siteId") or current.get("zoneId") or "").strip()
        if not target:
            raise AccelerationPluginError("缺少站点 ID", 400)
        return self.api.delete_zone(target)


def _build_edgeone_plugin(secrets: Dict[str, Any]) -> EdgeOneAccelerationPlugin:
    try:
        return EdgeOneAccelerationPlugin(secrets)
    except TencentEdgeOneApiError as exc:
        raise AccelerationPluginError(str(exc), int(exc.status or 400)) from exc


def _validate_edgeone_credentials(secrets: Dict[str, Any]) -> None:
    try:
        EdgeOneAccelerationPlugin.validate(secrets)
    except TencentEdgeOneApiError as exc:
        raise AccelerationPluginError(str(exc), int(exc.status or 400)) from exc


register_acceleration_plugin(
    AccelerationPluginDefinition(
        provider="edgeone",
        name="腾讯云 EdgeOne",
        auth_fields=[
            {"name": "secretId", "label": "SecretId", "type": "text", "required": True, "placeholder": "输入腾讯云 SecretId"},
            {"name": "secretKey", "label": "SecretKey", "type": "password", "required": True, "placeholder": "输入腾讯云 SecretKey"},
            {"name": "planId", "label": "默认套餐 ID", "type": "text", "required": False, "placeholder": "可选，创建站点时默认使用"},
            {"name": "endpoint", "label": "API Endpoint", "type": "text", "required": False, "placeholder": "可选，默认 teo.tencentcloudapi.com"},
        ],
        factory=_build_edgeone_plugin,
        validator=_validate_edgeone_credentials,
        icon="edgeone",
        capability_overrides={
            "supportsStatus": True,
            "supportsLogs": True,
            "domainCacheTtl": 60,
            "recordCacheTtl": 30,
            "retryableErrors": ["LimitExceeded", "InternalError", "RequestLimitExceeded", "ResourceUnavailable", "ServerBusy"],
            "maxRetries": 3,
        },
    )
)
