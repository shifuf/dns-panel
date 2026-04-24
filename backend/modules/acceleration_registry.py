from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Protocol
import importlib
import pkgutil
import threading


class AccelerationPluginError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = int(status)


class AccelerationPlugin(Protocol):
    def list_sites(self) -> list[Dict[str, Any]]: ...

    def discover_site(self, zone_name: str) -> Dict[str, Any] | None: ...

    def get_site(
        self,
        zone_name: str,
        site_id: str | None = None,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]: ...

    def ensure_site(self, zone_name: str, config: Dict[str, Any] | None = None) -> Dict[str, Any]: ...

    def verify_site(
        self,
        zone_name: str,
        site_id: str | None = None,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]: ...

    def set_site_status(
        self,
        zone_name: str,
        site_id: str | None,
        enabled: bool,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]: ...

    def delete_site(
        self,
        zone_name: str,
        site_id: str | None = None,
        config: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]: ...


@dataclass
class AccelerationPluginDefinition:
    provider: str
    name: str
    auth_fields: list[Dict[str, Any]]
    factory: Callable[[Dict[str, Any]], AccelerationPlugin]
    validator: Callable[[Dict[str, Any]], None] | None = None
    icon: str | None = None
    capability_overrides: Dict[str, Any] = field(default_factory=dict)

    def to_capabilities(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "provider": str(self.provider or "").strip().lower(),
            "name": self.name,
            "category": "acceleration",
            "supportsWeight": False,
            "supportsLine": False,
            "supportsStatus": True,
            "supportsRemark": False,
            "supportsUrlForward": False,
            "supportsLogs": True,
            "remarkMode": "unsupported",
            "paging": "server",
            "requiresDomainId": False,
            "recordTypes": [],
            "authFields": list(self.auth_fields or []),
            "domainCacheTtl": 60,
            "recordCacheTtl": 0,
            "retryableErrors": [],
            "maxRetries": 2,
        }
        if self.icon:
            data["icon"] = self.icon
        if self.capability_overrides:
            data.update(self.capability_overrides)
            data["provider"] = str(self.provider or "").strip().lower()
            data["name"] = self.name
            data["category"] = "acceleration"
            data["authFields"] = list(self.auth_fields or [])
        return data


_PLUGIN_REGISTRY: dict[str, AccelerationPluginDefinition] = {}
_PLUGINS_LOADED = False
_LOAD_LOCK = threading.Lock()


def register_acceleration_plugin(definition: AccelerationPluginDefinition) -> None:
    provider = str(definition.provider or "").strip().lower()
    if not provider:
        raise AccelerationPluginError("加速插件缺少 provider 标识", 500)
    normalized = AccelerationPluginDefinition(
        provider=provider,
        name=str(definition.name or provider).strip() or provider,
        auth_fields=list(definition.auth_fields or []),
        factory=definition.factory,
        validator=definition.validator,
        icon=definition.icon,
        capability_overrides=dict(definition.capability_overrides or {}),
    )
    _PLUGIN_REGISTRY[provider] = normalized


def ensure_acceleration_plugins_loaded() -> None:
    global _PLUGINS_LOADED
    if _PLUGINS_LOADED:
        return
    with _LOAD_LOCK:
        if _PLUGINS_LOADED:
            return
        try:
            package = importlib.import_module("modules.acceleration_plugins")
            package_path = getattr(package, "__path__", None)
            if package_path:
                prefix = f"{package.__name__}."
                for module_info in pkgutil.iter_modules(package_path, prefix):
                    importlib.import_module(module_info.name)
            _PLUGINS_LOADED = True
        except ModuleNotFoundError:
            _PLUGINS_LOADED = True


def get_acceleration_provider_capabilities() -> list[Dict[str, Any]]:
    ensure_acceleration_plugins_loaded()
    return [item.to_capabilities() for item in _PLUGIN_REGISTRY.values()]


def get_registered_acceleration_providers() -> tuple[str, ...]:
    ensure_acceleration_plugins_loaded()
    return tuple(_PLUGIN_REGISTRY.keys())


def get_acceleration_plugin_definition(provider: str) -> AccelerationPluginDefinition | None:
    ensure_acceleration_plugins_loaded()
    return _PLUGIN_REGISTRY.get(str(provider or "").strip().lower())


def build_acceleration_plugin(provider: str, secrets: Dict[str, Any]) -> AccelerationPlugin:
    definition = get_acceleration_plugin_definition(provider)
    if definition is None:
        raise AccelerationPluginError(f"不支持的加速插件: {provider}", 400)
    plugin = definition.factory(dict(secrets or {}))
    if plugin is None:
        raise AccelerationPluginError(f"加速插件初始化失败: {provider}", 500)
    return plugin


def validate_acceleration_credentials(provider: str, secrets: Dict[str, Any]) -> None:
    definition = get_acceleration_plugin_definition(provider)
    if definition is None:
        raise AccelerationPluginError(f"不支持的加速插件: {provider}", 400)
    payload = dict(secrets or {})
    if callable(definition.validator):
        definition.validator(payload)
        return
    build_acceleration_plugin(provider, payload)
