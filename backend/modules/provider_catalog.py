from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List

PROVIDER_CAPABILITIES: List[Dict[str, Any]] = [
    {
        "provider": "cloudflare",
        "name": "Cloudflare",
        "supportsWeight": False,
        "supportsLine": False,
        "supportsStatus": False,
        "supportsRemark": True,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "inline",
        "paging": "client",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR"],
        "authFields": [
            {"name": "apiToken", "label": "API Token", "type": "password", "required": True, "placeholder": "输入 Cloudflare API Token"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["RATE_LIMIT", "TIMEOUT", "ECONNRESET"],
        "maxRetries": 3,
    },
    {
        "provider": "aliyun",
        "name": "阿里云 DNS",
        "supportsWeight": False,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": False,
        "supportsLogs": True,
        "remarkMode": "separate",
        "paging": "server",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR"],
        "authFields": [
            {"name": "accessKeyId", "label": "AccessKey ID", "type": "text", "required": True, "placeholder": "输入 AccessKey ID", "helpText": "在阿里云控制台获取"},
            {"name": "accessKeySecret", "label": "AccessKey Secret", "type": "password", "required": True, "placeholder": "输入 AccessKey Secret"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["Throttling", "ServiceUnavailable", "InternalError", "RequestTimeout"],
        "maxRetries": 3,
    },
    {
        "provider": "dnspod",
        "name": "腾讯云",
        "supportsWeight": True,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": True,
        "supportsLogs": True,
        "remarkMode": "separate",
        "paging": "server",
        "requiresDomainId": True,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR", "REDIRECT_URL", "FORWARD_URL"],
        "authFields": [
            {"name": "secretId", "label": "SecretId", "type": "text", "required": False, "placeholder": "输入 SecretId（方式一）"},
            {"name": "secretKey", "label": "SecretKey", "type": "password", "required": False, "placeholder": "输入 SecretKey（方式一）"},
            {"name": "tokenId", "label": "ID", "type": "text", "required": False, "placeholder": "输入 ID（方式二）"},
            {"name": "token", "label": "Token", "type": "password", "required": False, "placeholder": "输入 Token（方式二）", "helpText": "两种方式二选一：SecretId/SecretKey 或 DNSPod Token（ID + Token）"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["RequestLimitExceeded", "InternalError", "ResourceUnavailable", "ServerBusy"],
        "maxRetries": 3,
    },
    {
        "provider": "dnspod_token",
        "name": "腾讯云",
        "supportsWeight": True,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": True,
        "supportsLogs": True,
        "remarkMode": "separate",
        "paging": "server",
        "requiresDomainId": True,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "NS", "REDIRECT_URL"],
        "authFields": [
            {"name": "tokenId", "label": "Token ID", "type": "text", "required": True, "placeholder": "输入 DNSPod Token ID"},
            {"name": "token", "label": "Token", "type": "password", "required": True, "placeholder": "输入 DNSPod Token"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": [],
        "maxRetries": 2,
    },
    {
        "provider": "huawei",
        "name": "华为云 DNS",
        "supportsWeight": True,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "inline",
        "paging": "server",
        "requiresDomainId": True,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR"],
        "authFields": [
            {"name": "accessKeyId", "label": "AccessKey ID", "type": "text", "required": True, "placeholder": "华为云 AccessKey ID"},
            {"name": "secretAccessKey", "label": "SecretAccessKey", "type": "password", "required": True, "placeholder": "华为云 SecretAccessKey"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["SYSTEM_BUSY", "InternalError", "TIMEOUT"],
        "maxRetries": 3,
    },
    {
        "provider": "baidu",
        "name": "百度云 DNS",
        "supportsWeight": False,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "inline",
        "paging": "client",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"],
        "authFields": [
            {"name": "accessKey", "label": "AccessKey", "type": "text", "required": True, "placeholder": "百度云 AccessKey"},
            {"name": "secretKey", "label": "SecretKey", "type": "password", "required": True, "placeholder": "百度云 SecretKey"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["SYSTEM_BUSY", "InternalError", "TIMEOUT"],
        "maxRetries": 3,
    },
    {
        "provider": "west",
        "name": "西部数码",
        "supportsWeight": False,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": False,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "unsupported",
        "paging": "server",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"],
        "authFields": [
            {"name": "username", "label": "用户名", "type": "text", "required": True, "placeholder": "西部数码用户名"},
            {"name": "apiPassword", "label": "API密码", "type": "password", "required": True, "placeholder": "西部数码 API 密码"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["SYSTEM_BUSY", "InternalError"],
        "maxRetries": 3,
    },
    {
        "provider": "huoshan",
        "name": "火山引擎 DNS",
        "supportsWeight": True,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "inline",
        "paging": "server",
        "requiresDomainId": True,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"],
        "authFields": [
            {"name": "accessKeyId", "label": "AccessKey ID", "type": "text", "required": True, "placeholder": "火山引擎 AccessKey ID"},
            {"name": "secretAccessKey", "label": "SecretAccessKey", "type": "password", "required": True, "placeholder": "火山引擎 SecretAccessKey"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["SYSTEM_BUSY", "InternalError", "TIMEOUT"],
        "maxRetries": 3,
    },
    {
        "provider": "jdcloud",
        "name": "京东云 DNS",
        "supportsWeight": True,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": False,
        "supportsUrlForward": True,
        "supportsLogs": False,
        "remarkMode": "unsupported",
        "paging": "server",
        "requiresDomainId": True,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "REDIRECT_URL", "FORWARD_URL"],
        "authFields": [
            {"name": "accessKeyId", "label": "AccessKey ID", "type": "text", "required": True, "placeholder": "京东云 AccessKey ID"},
            {"name": "accessKeySecret", "label": "AccessKey Secret", "type": "password", "required": True, "placeholder": "京东云 AccessKey Secret"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["SYSTEM_BUSY", "InternalError", "TIMEOUT"],
        "maxRetries": 3,
    },
    {
        "provider": "dnsla",
        "name": "DNSLA",
        "supportsWeight": True,
        "supportsLine": True,
        "supportsStatus": True,
        "supportsRemark": False,
        "supportsUrlForward": True,
        "supportsLogs": False,
        "remarkMode": "unsupported",
        "paging": "server",
        "requiresDomainId": True,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "REDIRECT_URL", "FORWARD_URL"],
        "authFields": [
            {"name": "apiId", "label": "API ID", "type": "text", "required": True, "placeholder": "DNSLA API ID"},
            {"name": "apiSecret", "label": "API Secret", "type": "password", "required": True, "placeholder": "DNSLA API Secret"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["RATE_LIMIT", "TIMEOUT", "InternalError"],
        "maxRetries": 3,
    },
    {
        "provider": "namesilo",
        "name": "NameSilo",
        "supportsWeight": False,
        "supportsLine": False,
        "supportsStatus": False,
        "supportsRemark": False,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "unsupported",
        "paging": "client",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"],
        "authFields": [
            {"name": "apiKey", "label": "API Key", "type": "password", "required": True, "placeholder": "NameSilo API Key"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 120,
        "retryableErrors": ["RATE_LIMIT", "TIMEOUT"],
        "maxRetries": 3,
    },
    {
        "provider": "powerdns",
        "name": "PowerDNS",
        "supportsWeight": False,
        "supportsLine": False,
        "supportsStatus": True,
        "supportsRemark": True,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "inline",
        "paging": "client",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS", "PTR", "SOA"],
        "authFields": [
            {"name": "serverAddress", "label": "服务器地址", "type": "text", "required": True, "placeholder": "192.168.1.1:8081", "helpText": "PowerDNS API 地址 (IP:端口)"},
            {"name": "apiKey", "label": "API Key", "type": "password", "required": True, "placeholder": "PowerDNS API Key"},
        ],
        "domainCacheTtl": 60,
        "recordCacheTtl": 30,
        "retryableErrors": ["TIMEOUT", "ECONNRESET"],
        "maxRetries": 2,
    },
    {
        "provider": "spaceship",
        "name": "Spaceship",
        "supportsWeight": False,
        "supportsLine": False,
        "supportsStatus": False,
        "supportsRemark": False,
        "supportsUrlForward": True,
        "supportsLogs": False,
        "remarkMode": "unsupported",
        "paging": "server",
        "requiresDomainId": False,
        "recordTypes": ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "HTTPS", "CAA", "TLSA", "ALIAS"],
        "authFields": [
            {"name": "apiKey", "label": "API Key", "type": "password", "required": True, "placeholder": "Spaceship API Key"},
            {"name": "apiSecret", "label": "API Secret", "type": "password", "required": True, "placeholder": "Spaceship API Secret"},
        ],
        "domainCacheTtl": 300,
        "recordCacheTtl": 60,
        "retryableErrors": ["RATE_LIMIT", "TIMEOUT"],
        "maxRetries": 3,
    },
    {
        "provider": "tencent_ssl",
        "name": "腾讯云 SSL",
        "category": "ssl",
        "supportsWeight": False,
        "supportsLine": False,
        "supportsStatus": False,
        "supportsRemark": False,
        "supportsUrlForward": False,
        "supportsLogs": False,
        "remarkMode": "unsupported",
        "paging": "server",
        "requiresDomainId": False,
        "recordTypes": [],
        "authFields": [
            {"name": "secretId", "label": "SecretId", "type": "text", "required": True, "placeholder": "腾讯云 SecretId"},
            {"name": "secretKey", "label": "SecretKey", "type": "password", "required": True, "placeholder": "腾讯云 SecretKey"},
        ],
        "domainCacheTtl": 0,
        "recordCacheTtl": 0,
        "retryableErrors": [],
        "maxRetries": 2,
    },
]


def get_all_provider_capabilities() -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    source_items: List[Dict[str, Any]] = list(PROVIDER_CAPABILITIES)
    try:
        from modules.acceleration_registry import get_acceleration_provider_capabilities

        source_items.extend(get_acceleration_provider_capabilities())
    except Exception:
        pass
    for item in source_items:
        provider = str(item.get("provider") or "").strip().lower()
        if not provider:
            continue
        normalized = deepcopy(item)
        normalized["provider"] = provider
        normalized["category"] = str(normalized.get("category") or "dns").strip().lower() or "dns"
        merged.append(normalized)
    deduped: Dict[str, Dict[str, Any]] = {}
    for item in merged:
        deduped[str(item["provider"])] = item
    return list(deduped.values())


def get_provider_capabilities(provider: str) -> Dict[str, Any] | None:
    p = str(provider or "").strip().lower()
    for item in get_all_provider_capabilities():
        if str(item.get("provider") or "") == p:
            return item
    return None


def get_provider_category(provider: str) -> str | None:
    item = get_provider_capabilities(provider)
    if item is None:
        return None
    return str(item.get("category") or "dns").strip().lower() or "dns"


def get_supported_provider_types() -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            str(item.get("provider") or "").strip().lower()
            for item in get_all_provider_capabilities()
            if str(item.get("provider") or "").strip()
        )
    )


def get_supported_provider_types_by_category(category: str) -> tuple[str, ...]:
    normalized = str(category or "").strip().lower()
    return tuple(
        str(item.get("provider") or "").strip().lower()
        for item in get_all_provider_capabilities()
        if str(item.get("provider") or "").strip()
        and str(item.get("category") or "dns").strip().lower() == normalized
    )


def get_provider_display_name(provider: str) -> str:
    item = get_provider_capabilities(provider)
    if item and str(item.get("name") or "").strip():
        return str(item.get("name") or "").strip()
    return str(provider or "").strip()
