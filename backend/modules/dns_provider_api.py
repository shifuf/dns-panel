"""Unified multi-provider DNS zone/record API adapters.

All adapters return normalized zone/record shapes and raise DnsProviderApiError
on failure. HTTP uses stdlib urllib only — no extra dependencies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import string
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from modules.cloudflare_api import CloudflareApi, CloudflareApiError
from modules.dnspod_api import DnspodApi, DnspodApiError


# ── Errors ─────────────────────────────────────────────────────────────


class DnsProviderApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = int(status)


# ── Helpers ────────────────────────────────────────────────────────────


def to_rr(name: str, domain: str) -> str:
    name = str(name or "").strip().rstrip(".")
    domain = str(domain or "").strip().rstrip(".")
    if not name or name.lower() == domain.lower() or name == "@":
        return "@"
    suffix = f".{domain}"
    if name.lower().endswith(suffix.lower()):
        return name[: -len(suffix)]
    return name


def to_fqdn(rr: str, domain: str) -> str:
    rr = str(rr or "").strip().rstrip(".")
    domain = str(domain or "").strip().rstrip(".")
    if not rr or rr == "@":
        return domain
    if domain and rr.lower().endswith(f".{domain.lower()}"):
        return rr
    if domain and rr.lower() == domain.lower():
        return domain
    return f"{rr}.{domain}" if domain else rr


def _iso8601_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _percent_encode(value: str) -> str:
    return urllib.parse.quote(str(value or ""), safe="~")


def _canonical_query(params: Dict[str, str]) -> str:
    keys = sorted(params.keys())
    return "&".join(f"{_percent_encode(k)}={_percent_encode(params[k])}" for k in keys)


def _http_json(
    method: str,
    url: str,
    *,
    headers: Dict[str, str] | None = None,
    body: Any = None,
    form: Dict[str, Any] | None = None,
    timeout: int = 60,
    expect_json: bool = True,
) -> Any:
    data: bytes | None = None
    req_headers = {
        "User-Agent": "dns-panel-python-v2/1.0",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)
    if form is not None:
        data = urllib.parse.urlencode({k: str(v) for k, v in form.items() if v is not None}).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        if isinstance(body, (bytes, bytearray)):
            data = bytes(body)
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

    req = urllib.request.Request(url, method=method.upper(), data=data, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            status = int(resp.getcode() or 200)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        status = int(e.code or 400)
        if not expect_json:
            raise DnsProviderApiError(raw or f"HTTP {status}", status)
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            payload = {}
        msg = ""
        if isinstance(payload, dict):
            for key in ("message", "Message", "error", "Error", "msg", "Msg", "errorMessage"):
                if payload.get(key):
                    msg = str(payload.get(key))
                    break
            err = payload.get("error") or payload.get("Error")
            if isinstance(err, dict) and not msg:
                msg = str(err.get("message") or err.get("Message") or err.get("code") or "")
        raise DnsProviderApiError(msg or raw or f"HTTP {status}", status)
    except DnsProviderApiError:
        raise
    except Exception as e:
        raise DnsProviderApiError(f"网络请求失败: {e}", 503)

    if not expect_json:
        return raw
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        raise DnsProviderApiError(f"返回非 JSON 响应: {raw[:200]}", 502)


def _norm_zone(
    zone_id: Any,
    name: Any,
    status: Any = "active",
    record_count: Any = None,
    updated_at: Any = None,
    name_servers: Any = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "id": str(zone_id or ""),
        "name": str(name or "").strip().rstrip("."),
        "status": str(status or "active"),
        "recordCount": record_count,
        "updatedAt": updated_at,
    }
    if isinstance(name_servers, list):
        out["nameServers"] = [str(x) for x in name_servers if str(x or "").strip()]
    return out


def _norm_record(
    record_id: Any,
    name: Any,
    rtype: Any,
    value: Any,
    *,
    ttl: Any = None,
    line: Any = None,
    weight: Any = None,
    priority: Any = None,
    status: Any = None,
    remark: Any = None,
    proxied: Any = None,
    updated_at: Any = None,
) -> Dict[str, Any]:
    st = status
    if st is True or st == 1 or st == "ENABLE" or st == "enable" or st == "enabled" or st == "ENABLE":
        st = "1"
    elif st is False or st == 0 or st == "DISABLE" or st == "disable" or st == "disabled" or st == "DISABLE":
        st = "0"
    elif st is not None:
        st = str(st)
    return {
        "id": str(record_id or ""),
        "name": str(name or "").strip().rstrip("."),
        "type": str(rtype or "").strip().upper(),
        "value": str(value if value is not None else ""),
        "ttl": ttl,
        "line": str(line) if line not in (None, "") else None,
        "weight": weight,
        "priority": priority,
        "status": st,
        "remark": remark,
        "proxied": bool(proxied) if proxied is not None else None,
        "updatedAt": updated_at,
    }


def _paginate_client(items: List[Any], page: int, page_size: int) -> tuple[List[Any], int]:
    total = len(items)
    page = max(1, int(page or 1))
    page_size = max(1, int(page_size or 20))
    start = (page - 1) * page_size
    return items[start : start + page_size], total


def _filter_keyword(items: List[Dict[str, Any]], keyword: str | None, keys: List[str]) -> List[Dict[str, Any]]:
    kw = str(keyword or "").strip().lower()
    if not kw:
        return items
    out = []
    for item in items:
        hay = " ".join(str(item.get(k) or "") for k in keys).lower()
        if kw in hay:
            out.append(item)
    return out


# ── Base ───────────────────────────────────────────────────────────────


class DnsProviderApi:
    provider: str = ""
    supports_status: bool = False
    supports_line: bool = False

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        raise NotImplementedError

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError

    def delete_zone(self, zone_id: str) -> bool:
        raise NotImplementedError

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        raise NotImplementedError

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        raise NotImplementedError

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        raise NotImplementedError

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        raise DnsProviderApiError("当前提供商不支持启用/禁用记录", 400)

    def get_lines(self, zone_id: str | None = None) -> List[Dict[str, str]]:
        return [{"code": "default", "name": "默认"}]

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 600

    def verify_credentials(self) -> bool:
        try:
            self.list_zones(1, 1)
            return True
        except Exception:
            return False

    def get_zone_by_name(self, domain: str) -> Dict[str, Any] | None:
        domain_n = str(domain or "").strip().rstrip(".").lower()
        if not domain_n:
            return None
        try:
            result = self.list_zones(1, 100, domain_n)
        except Exception:
            return None
        for z in result.get("zones") or []:
            if str(z.get("name") or "").strip().rstrip(".").lower() == domain_n:
                return z
        return None


# ── Cloudflare ─────────────────────────────────────────────────────────


class CloudflareDnsApi(DnsProviderApi):
    provider = "cloudflare"
    supports_status = False
    supports_line = False

    def __init__(self, secrets: Dict[str, Any]) -> None:
        token = str(secrets.get("apiToken") or "").strip()
        if not token:
            raise DnsProviderApiError("缺少 Cloudflare API Token", 400)
        self._cf = CloudflareApi(token)

    def _wrap(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except CloudflareApiError as e:
            raise DnsProviderApiError(str(e), e.status) from e

    def _map_zone(self, zone: Dict[str, Any]) -> Dict[str, Any]:
        meta = zone.get("meta") if isinstance(zone.get("meta"), dict) else {}
        ns = zone.get("name_servers") if isinstance(zone.get("name_servers"), list) else None
        return _norm_zone(
            zone.get("id"),
            zone.get("name"),
            zone.get("status") or "active",
            meta.get("dns_records_count") if isinstance(meta, dict) else None,
            zone.get("modified_on"),
            ns,
        )

    def _map_record(self, row: Dict[str, Any]) -> Dict[str, Any]:
        return _norm_record(
            row.get("id"),
            row.get("name"),
            row.get("type"),
            row.get("content"),
            ttl=row.get("ttl"),
            priority=row.get("priority"),
            remark=row.get("comment"),
            proxied=bool(row.get("proxied")) if row.get("proxied") is not None else None,
            updated_at=row.get("modified_on"),
        )

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        result = self._wrap(self._cf.list_zones, page, page_size, keyword)
        zones = [self._map_zone(z) for z in (result.get("zones") or []) if isinstance(z, dict)]
        return {"zones": zones, "total": int(result.get("total") or len(zones))}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        return self._map_zone(self._wrap(self._cf.get_zone, zone_id))

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        account_id = str(kwargs.get("account_id") or kwargs.get("accountId") or "").strip()
        if not account_id:
            account_id = self._wrap(self._cf.get_default_account_id)
        if not account_id:
            raise DnsProviderApiError("缺少 Cloudflare Account ID", 400)
        existed = self._wrap(self._cf.get_zone_by_name, domain, account_id)
        if existed:
            return self._map_zone(existed)
        return self._map_zone(self._wrap(self._cf.create_zone, domain, account_id))

    def delete_zone(self, zone_id: str) -> bool:
        return bool(self._wrap(self._cf.delete_zone, zone_id))

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        filters = dict(filters or {})
        cf_filters: Dict[str, Any] = {}
        name = filters.get("name") or filters.get("subDomain")
        if name:
            cf_filters["name"] = name
        if filters.get("type"):
            cf_filters["type"] = filters.get("type")
        content = filters.get("value") or filters.get("content")
        if content:
            cf_filters["content"] = content
        result = self._wrap(self._cf.list_records, zone_id, page, page_size, cf_filters)
        records = [self._map_record(r) for r in (result.get("records") or []) if isinstance(r, dict)]
        keyword = filters.get("keyword")
        if keyword:
            records = _filter_keyword(records, str(keyword), ["name", "value", "type"])
        return {"records": records, "total": int(result.get("total") or len(records))}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        return self._map_record(self._wrap(self._cf.get_record, zone_id, record_id))

    def _build_payload(self, params: Dict[str, Any], base: Dict[str, Any] | None = None) -> Dict[str, Any]:
        base = base or {}
        rtype = str(params.get("type") or base.get("type") or "").strip().upper()
        name = str(params.get("name") or base.get("name") or "").strip()
        value = params.get("value")
        if value is None:
            value = base.get("content") if base else None
        if value is None:
            value = base.get("value") if base else None
        ttl = params.get("ttl")
        if ttl is None:
            ttl = base.get("ttl") if base else 1
        try:
            ttl_i = int(ttl) if ttl is not None else 1
        except Exception:
            ttl_i = 1
        content = str(value or "")
        if rtype == "TXT":
            s = content.strip()
            if s and not (s.startswith('"') and s.endswith('"')) and '"' not in s:
                content = f'"{s}"'
        payload: Dict[str, Any] = {
            "type": rtype,
            "name": name,
            "content": content,
            "ttl": ttl_i if ttl_i > 0 else 1,
        }
        priority = params.get("priority")
        if priority is None and base:
            priority = base.get("priority")
        if isinstance(priority, (int, float)):
            payload["priority"] = int(priority)
        remark = params.get("remark")
        if remark is None and base:
            remark = base.get("comment") or base.get("remark")
        if remark is not None:
            payload["comment"] = remark
        if rtype in {"A", "AAAA", "CNAME"}:
            if "proxied" in params and params.get("proxied") is not None:
                payload["proxied"] = bool(params.get("proxied"))
            elif base and base.get("proxied") is not None:
                payload["proxied"] = bool(base.get("proxied"))
            else:
                payload["proxied"] = False
        return payload

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._build_payload(params)
        if not payload.get("name") or not payload.get("type"):
            raise DnsProviderApiError("缺少必需参数: name, type, value", 400)
        return self._map_record(self._wrap(self._cf.create_record, zone_id, payload))

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        old = None
        try:
            old = self._wrap(self._cf.get_record, zone_id, record_id)
        except Exception:
            old = None
        payload = self._build_payload(params, old if isinstance(old, dict) else None)
        if not payload.get("name") or not payload.get("type"):
            raise DnsProviderApiError("缺少必需参数: name, type, value", 400)
        return self._map_record(self._wrap(self._cf.update_record, zone_id, record_id, payload))

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        return bool(self._wrap(self._cf.delete_record, zone_id, record_id))

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 1

    def verify_credentials(self) -> bool:
        try:
            return bool(self._cf.verify_token())
        except Exception:
            return False

    @property
    def raw(self) -> CloudflareApi:
        return self._cf


# ── DNSPod ─────────────────────────────────────────────────────────────


class DnspodDnsApi(DnsProviderApi):
    supports_status = True
    supports_line = True

    def __init__(self, secrets: Dict[str, Any], provider: str = "dnspod") -> None:
        self.provider = provider
        try:
            self._api = DnspodApi(secrets)
        except DnspodApiError as e:
            raise DnsProviderApiError(str(e), e.status) from e

    def _wrap(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except DnspodApiError as e:
            raise DnsProviderApiError(str(e), e.status) from e

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        return self._wrap(self._api.list_zones, page, page_size, keyword)

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        return self._wrap(self._api.get_zone, zone_id)

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        return self._wrap(self._api.create_zone, domain)

    def delete_zone(self, zone_id: str) -> bool:
        return bool(self._wrap(self._api.delete_zone, zone_id))

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        return self._wrap(self._api.list_records, zone_id, page, page_size, filters)

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        return self._wrap(self._api.get_record, zone_id, record_id)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return self._wrap(self._api.create_record, zone_id, params)

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return self._wrap(self._api.update_record, zone_id, record_id, params)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        return bool(self._wrap(self._api.delete_record, zone_id, record_id))

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        return bool(self._wrap(self._api.set_record_status, zone_id, record_id, enabled))

    def get_lines(self, zone_id: str | None = None) -> List[Dict[str, str]]:
        return self._wrap(self._api.get_lines, zone_id)

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return int(self._wrap(self._api.get_min_ttl, zone_id) or 600)

    @property
    def raw(self) -> DnspodApi:
        return self._api


# ── Aliyun DNS (Signature V1.0 HMAC-SHA1) ───────────────────────────────


class AliyunDnsApi(DnsProviderApi):
    provider = "aliyun"
    supports_status = True
    supports_line = True
    HOST = "alidns.aliyuncs.com"
    VERSION = "2015-01-09"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.access_key_id = str(secrets.get("accessKeyId") or "").strip()
        self.access_key_secret = str(secrets.get("accessKeySecret") or "").strip()
        if not self.access_key_id or not self.access_key_secret:
            raise DnsProviderApiError("缺少阿里云 AccessKeyId / AccessKeySecret", 400)
        self._domain_cache: Dict[str, str] = {}

    def _request(self, action: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        base: Dict[str, str] = {
            "Action": action,
            "Version": self.VERSION,
            "Format": "JSON",
            "AccessKeyId": self.access_key_id,
            "SignatureMethod": "HMAC-SHA1",
            "SignatureVersion": "1.0",
            "SignatureNonce": "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24)),
            "Timestamp": _iso8601_now(),
        }
        for k, v in (params or {}).items():
            if v is None or v == "":
                continue
            base[str(k)] = str(v)
        canonical = _canonical_query(base)
        string_to_sign = f"POST&%2F&{_percent_encode(canonical)}"
        key = f"{self.access_key_secret}&".encode("utf-8")
        digest = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha1).digest()
        base["Signature"] = base64.b64encode(digest).decode("ascii")
        url = f"https://{self.HOST}/"
        try:
            payload = _http_json("POST", url, form=base)
        except DnsProviderApiError:
            raise
        if not isinstance(payload, dict):
            raise DnsProviderApiError("阿里云 DNS 返回格式错误", 502)
        code = str(payload.get("Code") or "").strip()
        if code:
            raise DnsProviderApiError(str(payload.get("Message") or code), 400)
        return payload

    def _domain_name(self, zone_id: str) -> str:
        zid = str(zone_id or "").strip()
        if zid in self._domain_cache:
            return self._domain_cache[zid]
        # zone_id is domain name for Aliyun
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", zid):
            self._domain_cache[zid] = zid
            return zid
        zone = self.get_zone(zid)
        name = str(zone.get("name") or zid)
        self._domain_cache[zid] = name
        self._domain_cache[name] = name
        return name

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        params: Dict[str, Any] = {"PageNumber": max(1, int(page)), "PageSize": max(1, min(100, int(page_size)))}
        if keyword:
            params["KeyWord"] = keyword
        resp = self._request("DescribeDomains", params)
        domains = ((resp.get("Domains") or {}).get("Domain") if isinstance(resp.get("Domains"), dict) else None) or []
        if not isinstance(domains, list):
            domains = []
        zones = []
        for d in domains:
            if not isinstance(d, dict):
                continue
            name = str(d.get("DomainName") or "")
            did = str(d.get("DomainId") or name)
            if name:
                self._domain_cache[did] = name
                self._domain_cache[name] = name
            zones.append(
                _norm_zone(name or did, name, d.get("DomainStatus") or "ENABLE", d.get("RecordCount"), d.get("CreateTime"))
            )
        total = int(resp.get("TotalCount") or len(zones))
        return {"zones": zones, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        name = str(zone_id or "").strip()
        resp = self._request("DescribeDomainInfo", {"DomainName": name})
        dname = str(resp.get("DomainName") or name)
        self._domain_cache[dname] = dname
        return _norm_zone(
            dname,
            dname,
            resp.get("DomainStatus") or "ENABLE",
            resp.get("RecordCount"),
            resp.get("CreateTime"),
            resp.get("DnsServers", {}).get("DnsServer") if isinstance(resp.get("DnsServers"), dict) else None,
        )

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        domain = str(domain or "").strip()
        try:
            self._request("AddDomain", {"DomainName": domain})
        except DnsProviderApiError as e:
            if "DomainExist" not in str(e) and "已存在" not in str(e):
                raise
        return self.get_zone(domain)

    def delete_zone(self, zone_id: str) -> bool:
        self._request("DeleteDomain", {"DomainName": self._domain_name(zone_id)})
        return True

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        domain = self._domain_name(zone_id)
        filters = filters or {}
        params: Dict[str, Any] = {
            "DomainName": domain,
            "PageNumber": max(1, int(page)),
            "PageSize": max(1, min(500, int(page_size))),
        }
        name = filters.get("subDomain") or filters.get("name")
        if name:
            params["RRKeyWord"] = to_rr(str(name), domain)
        if filters.get("type"):
            params["TypeKeyWord"] = str(filters.get("type")).upper()
        value = filters.get("value") or filters.get("content")
        if value:
            params["ValueKeyWord"] = value
        if filters.get("keyword"):
            params["KeyWord"] = filters.get("keyword")
        if filters.get("line"):
            params["Line"] = filters.get("line")
        resp = self._request("DescribeDomainRecords", params)
        rows = ((resp.get("DomainRecords") or {}).get("Record") if isinstance(resp.get("DomainRecords"), dict) else None) or []
        if not isinstance(rows, list):
            rows = []
        records = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            rr = str(r.get("RR") or "")
            records.append(
                _norm_record(
                    r.get("RecordId"),
                    to_fqdn(rr, domain),
                    r.get("Type"),
                    r.get("Value"),
                    ttl=r.get("TTL"),
                    line=r.get("Line"),
                    weight=r.get("Weight"),
                    priority=r.get("Priority") if r.get("Priority") is not None else r.get("Priority"),
                    status="1" if str(r.get("Status") or "").upper() == "ENABLE" else "0",
                    remark=r.get("Remark"),
                    updated_at=r.get("UpdateTimestamp") or r.get("UpdateDate"),
                )
            )
        return {"records": records, "total": int(resp.get("TotalCount") or len(records))}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        domain = self._domain_name(zone_id)
        resp = self._request("DescribeDomainRecordInfo", {"RecordId": str(record_id)})
        rr = str(resp.get("RR") or "")
        return _norm_record(
            resp.get("RecordId") or record_id,
            to_fqdn(rr, domain),
            resp.get("Type"),
            resp.get("Value"),
            ttl=resp.get("TTL"),
            line=resp.get("Line"),
            weight=resp.get("Weight"),
            priority=resp.get("Priority"),
            status="1" if str(resp.get("Status") or "").upper() == "ENABLE" else "0",
            remark=resp.get("Remark"),
        )

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._domain_name(zone_id)
        rr = to_rr(str(params.get("name") or ""), domain)
        payload: Dict[str, Any] = {
            "DomainName": domain,
            "RR": rr,
            "Type": str(params.get("type") or "").upper(),
            "Value": str(params.get("value") or ""),
        }
        if params.get("ttl") is not None:
            payload["TTL"] = int(params.get("ttl"))
        if params.get("line"):
            payload["Line"] = params.get("line")
        if params.get("priority") is not None:
            payload["Priority"] = int(params.get("priority"))
        if params.get("weight") is not None:
            payload["Weight"] = int(params.get("weight"))
        resp = self._request("AddDomainRecord", payload)
        rid = str(resp.get("RecordId") or "")
        if params.get("remark") and rid:
            try:
                self._request("UpdateDomainRecordRemark", {"RecordId": rid, "Remark": str(params.get("remark"))})
            except Exception:
                pass
        return self.get_record(zone_id, rid)

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._domain_name(zone_id)
        old = self.get_record(zone_id, record_id)
        name = params.get("name") if params.get("name") is not None else old.get("name")
        rtype = params.get("type") if params.get("type") is not None else old.get("type")
        value = params.get("value") if params.get("value") is not None else old.get("value")
        ttl = params.get("ttl") if params.get("ttl") is not None else old.get("ttl")
        line = params.get("line") if params.get("line") is not None else old.get("line")
        priority = params.get("priority") if params.get("priority") is not None else old.get("priority")
        payload: Dict[str, Any] = {
            "RecordId": str(record_id),
            "RR": to_rr(str(name or ""), domain),
            "Type": str(rtype or "").upper(),
            "Value": str(value or ""),
        }
        if ttl is not None:
            payload["TTL"] = int(ttl)
        if line:
            payload["Line"] = line
        if priority is not None:
            payload["Priority"] = int(priority)
        self._request("UpdateDomainRecord", payload)
        if "remark" in params and params.get("remark") is not None:
            try:
                self._request("UpdateDomainRecordRemark", {"RecordId": str(record_id), "Remark": str(params.get("remark"))})
            except Exception:
                pass
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request("DeleteDomainRecord", {"RecordId": str(record_id)})
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        self._request(
            "SetDomainRecordStatus",
            {"RecordId": str(record_id), "Status": "Enable" if enabled else "Disable"},
        )
        return True

    def get_lines(self, zone_id: str | None = None) -> List[Dict[str, str]]:
        try:
            domain = self._domain_name(zone_id) if zone_id else None
            params: Dict[str, Any] = {}
            if domain:
                params["DomainName"] = domain
            resp = self._request("DescribeSupportLines", params)
            rows = ((resp.get("RecordLines") or {}).get("RecordLine") if isinstance(resp.get("RecordLines"), dict) else None) or []
            if not isinstance(rows, list):
                rows = []
            lines = []
            for r in rows:
                if not isinstance(r, dict):
                    continue
                code = str(r.get("LineCode") or r.get("LineName") or "")
                name = str(r.get("LineDisplayName") or r.get("LineName") or code)
                if code:
                    lines.append({"code": code, "name": name})
            return lines or [{"code": "default", "name": "默认"}]
        except Exception:
            return [
                {"code": "default", "name": "默认"},
                {"code": "telecom", "name": "电信"},
                {"code": "unicom", "name": "联通"},
                {"code": "mobile", "name": "移动"},
                {"code": "oversea", "name": "海外"},
            ]

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 600


# ── Huawei Cloud DNS (AK/SK SDK signing simplified) ────────────────────


class HuaweiDnsApi(DnsProviderApi):
    """Huawei Cloud DNS with AK/SK V1 (SDK-HMAC-SHA256) signing."""

    provider = "huawei"
    supports_status = True
    supports_line = True
    HOST = "dns.myhuaweicloud.com"
    REGION = "cn-north-4"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.ak = str(secrets.get("accessKeyId") or "").strip()
        self.sk = str(secrets.get("secretAccessKey") or secrets.get("accessKeySecret") or "").strip()
        self.project_id = str(secrets.get("projectId") or secrets.get("project_id") or "").strip()
        if not self.ak or not self.sk:
            raise DnsProviderApiError("缺少华为云 AccessKeyId / SecretAccessKey", 400)
        self._zone_names: Dict[str, str] = {}

    def _sign(self, method: str, path: str, query: str, headers: Dict[str, str], body: str) -> Dict[str, str]:
        # SDK-HMAC-SHA256 simplified (Huawei API Signature V1)
        now = datetime.now(timezone.utc)
        date = now.strftime("%Y%m%dT%H%M%SZ")
        headers = dict(headers)
        headers["X-Sdk-Date"] = date
        headers["host"] = self.HOST
        signed_headers = "content-type;host;x-sdk-date"
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical_headers = (
            f"content-type:{headers.get('Content-Type', 'application/json')}\n"
            f"host:{self.HOST}\n"
            f"x-sdk-date:{date}\n"
        )
        canonical_request = f"{method.upper()}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        string_to_sign = f"SDK-HMAC-SHA256\n{date}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        signature = hmac.new(self.sk.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["Authorization"] = (
            f"SDK-HMAC-SHA256 Access={self.ak}, SignedHeaders={signed_headers}, Signature={signature}"
        )
        return headers

    def _request(self, method: str, path: str, query: Dict[str, Any] | None = None, body: Any = None) -> Any:
        qp = {str(k): str(v) for k, v in (query or {}).items() if v is not None and v != ""}
        query_str = urllib.parse.urlencode(sorted(qp.items()))
        url = f"https://{self.HOST}{path}"
        if query_str:
            url += f"?{query_str}"
        body_str = json.dumps(body, ensure_ascii=False, separators=(",", ":")) if body is not None else ""
        headers = {"Content-Type": "application/json"}
        headers = self._sign(method, path, query_str, headers, body_str)
        try:
            return _http_json(method, url, headers=headers, body=body_str if body is not None else None)
        except DnsProviderApiError as e:
            # rethrow with Chinese context
            raise DnsProviderApiError(f"华为云 DNS: {e}", e.status) from e

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        query: Dict[str, Any] = {"limit": int(page_size), "offset": (max(1, int(page)) - 1) * int(page_size)}
        if keyword:
            query["name"] = keyword
        resp = self._request("GET", "/v2/zones", query)
        zones_raw = resp.get("zones") if isinstance(resp, dict) else []
        zones = []
        for z in zones_raw or []:
            if not isinstance(z, dict):
                continue
            zid = str(z.get("id") or "")
            name = str(z.get("name") or "").rstrip(".")
            if zid:
                self._zone_names[zid] = name
            zones.append(
                _norm_zone(zid, name, z.get("status"), z.get("record_num"), z.get("updated_at"), z.get("name_servers"))
            )
        total = int((resp.get("metadata") or {}).get("total_count") or len(zones)) if isinstance(resp, dict) else len(zones)
        return {"zones": zones, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        resp = self._request("GET", f"/v2/zones/{quote(str(zone_id), safe='')}")
        z = resp if isinstance(resp, dict) else {}
        # sometimes wrapped
        if "zone" in z and isinstance(z["zone"], dict):
            z = z["zone"]
        zid = str(z.get("id") or zone_id)
        name = str(z.get("name") or "").rstrip(".")
        self._zone_names[zid] = name
        return _norm_zone(zid, name, z.get("status"), z.get("record_num"), z.get("updated_at"), z.get("name_servers"))

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        name = str(domain or "").strip().rstrip(".") + "."
        body: Dict[str, Any] = {"name": name, "zone_type": "public"}
        if self.project_id:
            body["router"] = {"router_id": self.project_id}
        resp = self._request("POST", "/v2/zones", body=body)
        z = resp.get("zone") if isinstance(resp, dict) and isinstance(resp.get("zone"), dict) else resp
        return self.get_zone(str((z or {}).get("id") or ""))

    def delete_zone(self, zone_id: str) -> bool:
        self._request("DELETE", f"/v2/zones/{quote(str(zone_id), safe='')}")
        return True

    def _zone_name(self, zone_id: str) -> str:
        if zone_id in self._zone_names:
            return self._zone_names[zone_id]
        z = self.get_zone(zone_id)
        return str(z.get("name") or "")

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        domain = self._zone_name(zone_id)
        filters = filters or {}
        query: Dict[str, Any] = {"limit": int(page_size), "offset": (max(1, int(page)) - 1) * int(page_size)}
        name = filters.get("name") or filters.get("subDomain")
        if name:
            query["name"] = to_fqdn(str(name), domain) + "."
        if filters.get("type"):
            query["type"] = str(filters.get("type")).upper()
        resp = self._request("GET", f"/v2/zones/{quote(str(zone_id), safe='')}/recordsets", query)
        rows = resp.get("recordsets") if isinstance(resp, dict) else []
        records = []
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            records.extend(self._expand_recordset(r, domain))
        total = int((resp.get("metadata") or {}).get("total_count") or len(records)) if isinstance(resp, dict) else len(records)
        keyword = filters.get("keyword")
        if keyword:
            records = _filter_keyword(records, str(keyword), ["name", "value", "type"])
        return {"records": records, "total": total}

    def _expand_recordset(self, r: Dict[str, Any], domain: str) -> List[Dict[str, Any]]:
        records = []
        name = str(r.get("name") or "").rstrip(".")
        rtype = str(r.get("type") or "").upper()
        values = r.get("records") if isinstance(r.get("records"), list) else []
        status = "1" if str(r.get("status") or "").upper() in {"ACTIVE", "ENABLE", "PENDING_CREATE"} else "0"
        if not values:
            records.append(
                _norm_record(r.get("id"), name, rtype, "", ttl=r.get("ttl"), status=status, remark=r.get("description"), updated_at=r.get("updated_at"))
            )
            return records
        for idx, val in enumerate(values):
            rid = str(r.get("id") or "")
            if len(values) > 1:
                rid = f"{rid}#{idx}"
            value = str(val)
            priority = None
            if rtype == "MX" and " " in value:
                parts = value.split(None, 1)
                try:
                    priority = int(parts[0])
                    value = parts[1] if len(parts) > 1 else value
                except Exception:
                    pass
            records.append(
                _norm_record(
                    rid,
                    name,
                    rtype,
                    value.rstrip("."),
                    ttl=r.get("ttl"),
                    priority=priority,
                    status=status,
                    remark=r.get("description"),
                    updated_at=r.get("updated_at"),
                )
            )
        return records

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        domain = self._zone_name(zone_id)
        base_id = str(record_id).split("#", 1)[0]
        resp = self._request("GET", f"/v2/zones/{quote(str(zone_id), safe='')}/recordsets/{quote(base_id, safe='')}")
        r = resp.get("recordset") if isinstance(resp, dict) and isinstance(resp.get("recordset"), dict) else resp
        expanded = self._expand_recordset(r if isinstance(r, dict) else {}, domain)
        for item in expanded:
            if item.get("id") == str(record_id):
                return item
        if expanded:
            return expanded[0]
        raise DnsProviderApiError("记录不存在", 404)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._zone_name(zone_id)
        name = to_fqdn(str(params.get("name") or ""), domain) + "."
        rtype = str(params.get("type") or "").upper()
        value = str(params.get("value") or "")
        if rtype == "MX" and params.get("priority") is not None:
            value = f"{int(params.get('priority'))} {value}"
        body: Dict[str, Any] = {
            "name": name,
            "type": rtype,
            "records": [value if rtype in {"TXT", "A", "AAAA"} else (value if value.endswith(".") or rtype in {"A", "AAAA", "TXT"} else value + ("." if rtype in {"CNAME", "NS", "MX", "SRV"} else ""))],
            "ttl": int(params.get("ttl") or 300),
        }
        if params.get("remark"):
            body["description"] = str(params.get("remark"))
        # normalize records list
        recs = []
        for v in body["records"]:
            vv = str(v)
            if rtype in {"CNAME", "NS", "MX", "SRV"} and not vv.endswith(".") and " " not in vv:
                vv = vv + "."
            recs.append(vv)
        body["records"] = recs
        resp = self._request("POST", f"/v2/zones/{quote(str(zone_id), safe='')}/recordsets", body=body)
        r = resp.get("recordset") if isinstance(resp, dict) and isinstance(resp.get("recordset"), dict) else resp
        expanded = self._expand_recordset(r if isinstance(r, dict) else {}, domain)
        return expanded[0] if expanded else self.get_record(zone_id, str((r or {}).get("id") or ""))

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._zone_name(zone_id)
        base_id = str(record_id).split("#", 1)[0]
        old = self.get_record(zone_id, record_id)
        rtype = str(params.get("type") or old.get("type") or "").upper()
        value = str(params.get("value") if params.get("value") is not None else old.get("value") or "")
        if rtype == "MX":
            pr = params.get("priority") if params.get("priority") is not None else old.get("priority")
            if pr is not None and " " not in value:
                value = f"{int(pr)} {value}"
        if rtype in {"CNAME", "NS", "MX", "SRV"} and not value.endswith(".") and " " not in value:
            value = value + "."
        body: Dict[str, Any] = {
            "records": [value],
            "ttl": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 300),
        }
        if params.get("remark") is not None:
            body["description"] = str(params.get("remark"))
        self._request("PUT", f"/v2/zones/{quote(str(zone_id), safe='')}/recordsets/{quote(base_id, safe='')}", body=body)
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        base_id = str(record_id).split("#", 1)[0]
        self._request("DELETE", f"/v2/zones/{quote(str(zone_id), safe='')}/recordsets/{quote(base_id, safe='')}")
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        # Huawei recordsets don't have a simple enable/disable; best-effort no-op with message
        raise DnsProviderApiError("华为云 DNS 记录集不支持单独启用/禁用，请删除或修改记录", 400)

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 1


# ── NameSilo ───────────────────────────────────────────────────────────


class NamesiloDnsApi(DnsProviderApi):
    provider = "namesilo"
    supports_status = False
    supports_line = False
    BASE = "https://www.namesilo.com/api"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.api_key = str(secrets.get("apiKey") or "").strip()
        if not self.api_key:
            raise DnsProviderApiError("缺少 NameSilo API Key", 400)

    def _request(self, operation: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        q = {"version": "1", "type": "json", "key": self.api_key}
        for k, v in (params or {}).items():
            if v is not None and v != "":
                q[str(k)] = str(v)
        url = f"{self.BASE}/{operation}?{urllib.parse.urlencode(q)}"
        payload = _http_json("GET", url)
        if not isinstance(payload, dict):
            raise DnsProviderApiError("NameSilo 返回格式错误", 502)
        reply = payload.get("reply") if isinstance(payload.get("reply"), dict) else payload
        code = str(reply.get("code") or "")
        if code and code not in {"300", "301", "302"}:
            raise DnsProviderApiError(str(reply.get("detail") or f"NameSilo 错误 {code}"), 400)
        return reply

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        reply = self._request("listDomains")
        domains = reply.get("domains")
        names: List[str] = []
        if isinstance(domains, dict):
            d = domains.get("domain")
            if isinstance(d, list):
                names = [str(x.get("domain") if isinstance(x, dict) else x) for x in d]
            elif isinstance(d, str):
                names = [d]
            elif isinstance(d, dict):
                names = [str(d.get("domain") or "")]
        elif isinstance(domains, list):
            names = [str(x.get("domain") if isinstance(x, dict) else x) for x in domains]
        zones = [_norm_zone(n, n, "active") for n in names if n]
        zones = _filter_keyword(zones, keyword, ["name"])
        page_items, total = _paginate_client(zones, page, page_size)
        return {"zones": page_items, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        return _norm_zone(zone_id, zone_id, "active")

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        raise DnsProviderApiError("NameSilo 不支持通过 API 添加域名（请先在控制台注册/转入）", 400)

    def delete_zone(self, zone_id: str) -> bool:
        raise DnsProviderApiError("NameSilo 不支持通过 API 删除域名", 400)

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        reply = self._request("dnsListRecords", {"domain": domain})
        rows = reply.get("resource_record")
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            rows = []
        records = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            host = str(r.get("host") or "")
            records.append(
                _norm_record(
                    r.get("record_id"),
                    host if "." in host else to_fqdn(host, domain),
                    r.get("type"),
                    r.get("value"),
                    ttl=int(r.get("ttl") or 3600) if r.get("ttl") else 3600,
                    priority=r.get("distance"),
                )
            )
        filters = filters or {}
        if filters.get("type"):
            t = str(filters.get("type")).upper()
            records = [r for r in records if r.get("type") == t]
        name = filters.get("name") or filters.get("subDomain")
        if name:
            target = to_fqdn(str(name), domain).lower()
            records = [r for r in records if str(r.get("name") or "").lower() == target]
        if filters.get("keyword"):
            records = _filter_keyword(records, str(filters.get("keyword")), ["name", "value", "type"])
        page_items, total = _paginate_client(records, page, page_size)
        return {"records": page_items, "total": total}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        result = self.list_records(zone_id, 1, 500)
        for r in result.get("records") or []:
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        rr = to_rr(str(params.get("name") or ""), domain)
        q: Dict[str, Any] = {
            "domain": domain,
            "rrtype": str(params.get("type") or "").upper(),
            "rrhost": "" if rr == "@" else rr,
            "rrvalue": str(params.get("value") or ""),
            "rrttl": int(params.get("ttl") or 3600),
        }
        if params.get("priority") is not None:
            q["rrdistance"] = int(params.get("priority"))
        reply = self._request("dnsAddRecord", q)
        rid = str(reply.get("record_id") or "")
        if rid:
            try:
                return self.get_record(zone_id, rid)
            except Exception:
                pass
        return _norm_record(rid, to_fqdn(rr, domain), q["rrtype"], q["rrvalue"], ttl=q["rrttl"], priority=params.get("priority"))

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        old = self.get_record(zone_id, record_id)
        rr = to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain)
        q: Dict[str, Any] = {
            "domain": domain,
            "rrid": str(record_id),
            "rrtype": str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper(),
            "rrhost": "" if rr == "@" else rr,
            "rrvalue": str(params.get("value") if params.get("value") is not None else old.get("value") or ""),
            "rrttl": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 3600),
        }
        pr = params.get("priority") if params.get("priority") is not None else old.get("priority")
        if pr is not None:
            q["rrdistance"] = int(pr)
        self._request("dnsUpdateRecord", q)
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request("dnsDeleteRecord", {"domain": str(zone_id), "rrid": str(record_id)})
        return True

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 3600


# ── PowerDNS ───────────────────────────────────────────────────────────


class PowerDnsApi(DnsProviderApi):
    provider = "powerdns"
    supports_status = True
    supports_line = False

    def __init__(self, secrets: Dict[str, Any]) -> None:
        addr = str(secrets.get("serverAddress") or "").strip()
        self.api_key = str(secrets.get("apiKey") or "").strip()
        if not addr or not self.api_key:
            raise DnsProviderApiError("缺少 PowerDNS serverAddress / apiKey", 400)
        if not addr.startswith("http://") and not addr.startswith("https://"):
            addr = f"http://{addr}"
        self.base = addr.rstrip("/")
        self.server_id = str(secrets.get("serverId") or "localhost").strip() or "localhost"

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        url = f"{self.base}{path}"
        headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}
        try:
            return _http_json(method, url, headers=headers, body=body)
        except DnsProviderApiError as e:
            raise DnsProviderApiError(f"PowerDNS: {e}", e.status) from e

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        rows = self._request("GET", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones")
        if not isinstance(rows, list):
            rows = []
        zones = []
        for z in rows:
            if not isinstance(z, dict):
                continue
            name = str(z.get("name") or "").rstrip(".")
            zid = str(z.get("id") or z.get("name") or name)
            zones.append(_norm_zone(zid, name, "active", None, None, z.get("nameservers")))
        zones = _filter_keyword(zones, keyword, ["name"])
        page_items, total = _paginate_client(zones, page, page_size)
        return {"zones": page_items, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        zid = str(zone_id or "")
        if not zid.endswith(".") and "." in zid:
            # try as-is first, PowerDNS uses trailing-dot ids
            pass
        try:
            z = self._request("GET", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid, safe='')}")
        except DnsProviderApiError:
            if not zid.endswith("."):
                z = self._request(
                    "GET", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid + '.', safe='')}"
                )
            else:
                raise
        if not isinstance(z, dict):
            raise DnsProviderApiError("域名不存在", 404)
        name = str(z.get("name") or "").rstrip(".")
        return _norm_zone(z.get("id") or z.get("name") or name, name, "active", None, None, z.get("nameservers"))

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        name = str(domain or "").strip().rstrip(".") + "."
        body = {
            "name": name,
            "kind": "Native",
            "nameservers": kwargs.get("nameServers") or kwargs.get("nameservers") or [],
        }
        z = self._request("POST", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones", body=body)
        if isinstance(z, dict):
            return _norm_zone(z.get("id") or name, str(z.get("name") or name).rstrip("."), "active")
        return self.get_zone(name)

    def delete_zone(self, zone_id: str) -> bool:
        zid = str(zone_id or "")
        try:
            self._request("DELETE", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid, safe='')}")
        except DnsProviderApiError:
            if not zid.endswith("."):
                self._request(
                    "DELETE", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid + '.', safe='')}"
                )
            else:
                raise
        return True

    def _zone_payload(self, zone_id: str) -> Dict[str, Any]:
        zid = str(zone_id or "")
        try:
            z = self._request("GET", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid, safe='')}")
        except DnsProviderApiError:
            z = self._request(
                "GET", f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid.rstrip('.') + '.', safe='')}"
            )
        if not isinstance(z, dict):
            raise DnsProviderApiError("域名不存在", 404)
        return z

    def _rrsets_to_records(self, zone: Dict[str, Any]) -> List[Dict[str, Any]]:
        domain = str(zone.get("name") or "").rstrip(".")
        records: List[Dict[str, Any]] = []
        for rrset in zone.get("rrsets") or []:
            if not isinstance(rrset, dict):
                continue
            name = str(rrset.get("name") or "").rstrip(".")
            rtype = str(rrset.get("type") or "").upper()
            ttl = rrset.get("ttl")
            disabled_set = bool(rrset.get("disabled"))
            for idx, rec in enumerate(rrset.get("records") or []):
                if not isinstance(rec, dict):
                    continue
                value = str(rec.get("content") or "")
                priority = None
                if rtype == "MX" and " " in value:
                    parts = value.split(None, 1)
                    try:
                        priority = int(parts[0])
                        value = parts[1]
                    except Exception:
                        pass
                rid = f"{name}|{rtype}|{idx}"
                records.append(
                    _norm_record(
                        rid,
                        name,
                        rtype,
                        value.rstrip("."),
                        ttl=ttl,
                        priority=priority,
                        status="0" if (disabled_set or rec.get("disabled")) else "1",
                        remark=rrset.get("comments", [{}])[0].get("content")
                        if isinstance(rrset.get("comments"), list) and rrset.get("comments")
                        else None,
                    )
                )
        return records

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        zone = self._zone_payload(zone_id)
        domain = str(zone.get("name") or "").rstrip(".")
        records = self._rrsets_to_records(zone)
        filters = filters or {}
        if filters.get("type"):
            t = str(filters.get("type")).upper()
            records = [r for r in records if r.get("type") == t]
        name = filters.get("name") or filters.get("subDomain")
        if name:
            target = to_fqdn(str(name), domain).lower()
            records = [r for r in records if str(r.get("name") or "").lower() == target]
        if filters.get("keyword"):
            records = _filter_keyword(records, str(filters.get("keyword")), ["name", "value", "type"])
        page_items, total = _paginate_client(records, page, page_size)
        return {"records": page_items, "total": total}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        result = self.list_records(zone_id, 1, 5000)
        for r in result.get("records") or []:
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def _patch_rrset(self, zone_id: str, rrsets: List[Dict[str, Any]]) -> None:
        zid = str(zone_id or "")
        path = f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid, safe='')}"
        try:
            self._request("PATCH", path, body={"rrsets": rrsets})
        except DnsProviderApiError:
            path = f"/api/v1/servers/{quote(self.server_id, safe='')}/zones/{quote(zid.rstrip('.') + '.', safe='')}"
            self._request("PATCH", path, body={"rrsets": rrsets})

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        zone = self._zone_payload(zone_id)
        domain = str(zone.get("name") or "").rstrip(".")
        name = to_fqdn(str(params.get("name") or ""), domain) + "."
        rtype = str(params.get("type") or "").upper()
        value = str(params.get("value") or "")
        if rtype == "MX" and params.get("priority") is not None:
            value = f"{int(params.get('priority'))} {value}"
        if rtype in {"CNAME", "NS", "MX", "SRV"} and not value.endswith("."):
            value = value + "."
        ttl = int(params.get("ttl") or 3600)
        # replace/add: fetch existing rrset values of same name/type and append
        existing = []
        for rrset in zone.get("rrsets") or []:
            if str(rrset.get("name") or "") == name and str(rrset.get("type") or "").upper() == rtype:
                existing = list(rrset.get("records") or [])
                ttl = int(rrset.get("ttl") or ttl)
                break
        existing.append({"content": value, "disabled": False})
        self._patch_rrset(
            zone_id,
            [{"name": name, "type": rtype, "ttl": ttl, "changetype": "REPLACE", "records": existing}],
        )
        # find created
        result = self.list_records(zone_id, 1, 5000, {"name": name.rstrip("."), "type": rtype})
        for r in result.get("records") or []:
            if str(r.get("value") or "").rstrip(".") == value.rstrip("."):
                return r
        records = result.get("records") or []
        return records[-1] if records else _norm_record(f"{name.rstrip('.')}|{rtype}|0", name.rstrip("."), rtype, value.rstrip("."), ttl=ttl)

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        old = self.get_record(zone_id, record_id)
        parts = str(record_id).split("|")
        name = (parts[0] if parts else old.get("name")) or ""
        rtype = (parts[1] if len(parts) > 1 else old.get("type")) or ""
        idx = int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0
        zone = self._zone_payload(zone_id)
        domain = str(zone.get("name") or "").rstrip(".")
        new_name = to_fqdn(str(params.get("name") if params.get("name") is not None else name), domain) + "."
        new_type = str(params.get("type") if params.get("type") is not None else rtype).upper()
        new_value = str(params.get("value") if params.get("value") is not None else old.get("value") or "")
        if new_type == "MX":
            pr = params.get("priority") if params.get("priority") is not None else old.get("priority")
            if pr is not None and " " not in new_value:
                new_value = f"{int(pr)} {new_value}"
        if new_type in {"CNAME", "NS", "MX", "SRV"} and not new_value.endswith("."):
            new_value = new_value + "."
        ttl = int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 3600)
        # rebuild rrset for old name/type without this index, then set new
        old_name = str(name).rstrip(".") + "."
        old_type = str(rtype).upper()
        old_records = []
        for rrset in zone.get("rrsets") or []:
            if str(rrset.get("name") or "") == old_name and str(rrset.get("type") or "").upper() == old_type:
                old_records = list(rrset.get("records") or [])
                break
        if 0 <= idx < len(old_records):
            old_records.pop(idx)
        patches = []
        if old_records:
            patches.append({"name": old_name, "type": old_type, "ttl": ttl, "changetype": "REPLACE", "records": old_records})
        else:
            patches.append({"name": old_name, "type": old_type, "changetype": "DELETE", "records": []})
        # add/replace new
        new_existing = []
        if new_name != old_name or new_type != old_type:
            for rrset in zone.get("rrsets") or []:
                if str(rrset.get("name") or "") == new_name and str(rrset.get("type") or "").upper() == new_type:
                    new_existing = list(rrset.get("records") or [])
                    break
        else:
            new_existing = list(old_records)
        new_existing.append({"content": new_value, "disabled": old.get("status") == "0"})
        patches.append({"name": new_name, "type": new_type, "ttl": ttl, "changetype": "REPLACE", "records": new_existing})
        self._patch_rrset(zone_id, patches)
        result = self.list_records(zone_id, 1, 5000, {"name": new_name.rstrip("."), "type": new_type})
        for r in result.get("records") or []:
            if str(r.get("value") or "").rstrip(".") == new_value.rstrip("."):
                return r
        records = result.get("records") or []
        return records[-1] if records else old

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        old = self.get_record(zone_id, record_id)
        parts = str(record_id).split("|")
        name = (parts[0] if parts else old.get("name")) or ""
        rtype = (parts[1] if len(parts) > 1 else old.get("type")) or ""
        idx = int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0
        zone = self._zone_payload(zone_id)
        old_name = str(name).rstrip(".") + "."
        old_type = str(rtype).upper()
        old_records = []
        ttl = 3600
        for rrset in zone.get("rrsets") or []:
            if str(rrset.get("name") or "") == old_name and str(rrset.get("type") or "").upper() == old_type:
                old_records = list(rrset.get("records") or [])
                ttl = int(rrset.get("ttl") or 3600)
                break
        if 0 <= idx < len(old_records):
            old_records.pop(idx)
        if old_records:
            self._patch_rrset(
                zone_id, [{"name": old_name, "type": old_type, "ttl": ttl, "changetype": "REPLACE", "records": old_records}]
            )
        else:
            self._patch_rrset(zone_id, [{"name": old_name, "type": old_type, "changetype": "DELETE", "records": []}])
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        old = self.get_record(zone_id, record_id)
        parts = str(record_id).split("|")
        name = (parts[0] if parts else old.get("name")) or ""
        rtype = (parts[1] if len(parts) > 1 else old.get("type")) or ""
        idx = int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0
        zone = self._zone_payload(zone_id)
        old_name = str(name).rstrip(".") + "."
        old_type = str(rtype).upper()
        old_records = []
        ttl = 3600
        for rrset in zone.get("rrsets") or []:
            if str(rrset.get("name") or "") == old_name and str(rrset.get("type") or "").upper() == old_type:
                old_records = list(rrset.get("records") or [])
                ttl = int(rrset.get("ttl") or 3600)
                break
        if 0 <= idx < len(old_records) and isinstance(old_records[idx], dict):
            old_records[idx]["disabled"] = not enabled
            self._patch_rrset(
                zone_id, [{"name": old_name, "type": old_type, "ttl": ttl, "changetype": "REPLACE", "records": old_records}]
            )
            return True
        raise DnsProviderApiError("记录不存在", 404)

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 1


# ── Baidu Cloud DNS ────────────────────────────────────────────────────


class BaiduDnsApi(DnsProviderApi):
    """Baidu BCE DNS (bcd / dns) with BCE auth best-effort."""

    provider = "baidu"
    supports_status = True
    supports_line = True
    HOST = "dns.baidubce.com"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.ak = str(secrets.get("accessKey") or secrets.get("accessKeyId") or "").strip()
        self.sk = str(secrets.get("secretKey") or secrets.get("accessKeySecret") or "").strip()
        if not self.ak or not self.sk:
            raise DnsProviderApiError("缺少百度云 AccessKey / SecretKey", 400)

    def _bce_headers(self, method: str, path: str, query: str, body: str) -> Dict[str, str]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {
            "Host": self.HOST,
            "Content-Type": "application/json",
            "x-bce-date": now,
        }
        # BCE signature v1
        signed_headers = "host;x-bce-date"
        canonical_headers = f"host:{self.HOST}\nx-bce-date:{now}"
        auth_string_prefix = f"bce-auth-v1/{self.ak}/{now}/1800"
        canonical_request = f"{method.upper()}\n{path}\n{query}\n{canonical_headers}"
        signing_key = hmac.new(self.sk.encode("utf-8"), auth_string_prefix.encode("utf-8"), hashlib.sha256).hexdigest()
        signature = hmac.new(signing_key.encode("utf-8"), canonical_request.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["Authorization"] = f"{auth_string_prefix}/{signed_headers}/{signature}"
        return headers

    def _request(self, method: str, path: str, query: Dict[str, Any] | None = None, body: Any = None) -> Any:
        qp = {str(k): str(v) for k, v in (query or {}).items() if v is not None and v != ""}
        query_str = urllib.parse.urlencode(sorted(qp.items()))
        url = f"https://{self.HOST}{path}"
        if query_str:
            url += f"?{query_str}"
        body_str = json.dumps(body, ensure_ascii=False) if body is not None else ""
        headers = self._bce_headers(method, path, query_str, body_str)
        try:
            return _http_json(method, url, headers=headers, body=body_str if body is not None else None)
        except DnsProviderApiError as e:
            raise DnsProviderApiError(f"百度云 DNS: {e}", e.status) from e

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        resp = self._request("GET", "/v1/dns/zone", {"name": keyword or "", "marker": "", "maxKeys": int(page_size)})
        rows = resp.get("zones") if isinstance(resp, dict) else []
        zones = []
        for z in rows or []:
            if not isinstance(z, dict):
                continue
            name = str(z.get("name") or "")
            zones.append(_norm_zone(name, name, z.get("status") or "active"))
        zones = _filter_keyword(zones, keyword, ["name"])
        page_items, total = _paginate_client(zones, page, page_size)
        return {"zones": page_items, "total": total or int(resp.get("totalCount") or len(zones)) if isinstance(resp, dict) else total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        return _norm_zone(zone_id, zone_id, "active")

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        self._request("POST", "/v1/dns/zone", body={"name": str(domain or "").strip()})
        return self.get_zone(str(domain or "").strip())

    def delete_zone(self, zone_id: str) -> bool:
        self._request("DELETE", f"/v1/dns/zone/{quote(str(zone_id), safe='')}")
        return True

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        resp = self._request("GET", f"/v1/dns/zone/{quote(domain, safe='')}/record", {"maxKeys": 1000})
        rows = resp.get("records") if isinstance(resp, dict) else []
        records = []
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            rr = str(r.get("rr") or r.get("name") or "")
            records.append(
                _norm_record(
                    r.get("id") or r.get("recordId"),
                    to_fqdn(rr, domain),
                    r.get("type"),
                    r.get("value"),
                    ttl=r.get("ttl"),
                    line=r.get("line"),
                    priority=r.get("priority") or r.get("mx"),
                    status="1" if str(r.get("status") or "enable").lower() in {"enable", "1", "running"} else "0",
                    remark=r.get("description") or r.get("remark"),
                )
            )
        filters = filters or {}
        if filters.get("type"):
            t = str(filters.get("type")).upper()
            records = [x for x in records if x.get("type") == t]
        name = filters.get("name") or filters.get("subDomain")
        if name:
            target = to_fqdn(str(name), domain).lower()
            records = [x for x in records if str(x.get("name") or "").lower() == target]
        if filters.get("keyword"):
            records = _filter_keyword(records, str(filters.get("keyword")), ["name", "value", "type"])
        page_items, total = _paginate_client(records, page, page_size)
        return {"records": page_items, "total": total}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        for r in (self.list_records(zone_id, 1, 1000).get("records") or []):
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        body = {
            "rr": to_rr(str(params.get("name") or ""), domain),
            "type": str(params.get("type") or "").upper(),
            "value": str(params.get("value") or ""),
            "ttl": int(params.get("ttl") or 300),
        }
        if params.get("line"):
            body["line"] = params.get("line")
        if params.get("priority") is not None:
            body["priority"] = int(params.get("priority"))
        if params.get("remark"):
            body["description"] = str(params.get("remark"))
        resp = self._request("POST", f"/v1/dns/zone/{quote(domain, safe='')}/record", body=body)
        rid = str(resp.get("id") or resp.get("recordId") or "")
        if rid:
            try:
                return self.get_record(zone_id, rid)
            except Exception:
                pass
        return _norm_record(rid, to_fqdn(body["rr"], domain), body["type"], body["value"], ttl=body["ttl"])

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        old = self.get_record(zone_id, record_id)
        body = {
            "rr": to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain),
            "type": str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper(),
            "value": str(params.get("value") if params.get("value") is not None else old.get("value") or ""),
            "ttl": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 300),
        }
        if params.get("line") is not None or old.get("line"):
            body["line"] = params.get("line") if params.get("line") is not None else old.get("line")
        self._request("PUT", f"/v1/dns/zone/{quote(domain, safe='')}/record/{quote(str(record_id), safe='')}", body=body)
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        domain = str(zone_id or "").strip()
        self._request("DELETE", f"/v1/dns/zone/{quote(domain, safe='')}/record/{quote(str(record_id), safe='')}")
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        domain = str(zone_id or "").strip()
        self._request(
            "PUT",
            f"/v1/dns/zone/{quote(domain, safe='')}/record/{quote(str(record_id), safe='')}/status",
            body={"status": "enable" if enabled else "disable"},
        )
        return True


# ── 西部数码 West.cn ───────────────────────────────────────────────────


class WestDnsApi(DnsProviderApi):
    provider = "west"
    supports_status = True
    supports_line = True
    BASE = "https://api.west.cn/API/v2"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.username = str(secrets.get("username") or "").strip()
        self.api_password = str(secrets.get("apiPassword") or secrets.get("password") or "").strip()
        if not self.username or not self.api_password:
            raise DnsProviderApiError("缺少西部数码 username / apiPassword", 400)

    def _request(self, act: str, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
        form = {
            "username": self.username,
            "password": hashlib.md5(self.api_password.encode("utf-8")).hexdigest(),
            "act": act,
        }
        for k, v in (params or {}).items():
            if v is not None:
                form[str(k)] = v
        try:
            payload = _http_json("POST", f"{self.BASE}/domain/", form=form)
        except DnsProviderApiError:
            # try alternate endpoint
            payload = _http_json("POST", "https://api.west.cn/API/v2/dns/", form=form)
        if not isinstance(payload, dict):
            raise DnsProviderApiError("西部数码返回格式错误", 502)
        code = payload.get("result") if "result" in payload else payload.get("code")
        if str(code) not in {"200", "0", "success", "ok", "None"} and code not in (200, 0, None):
            # west sometimes uses result=200 success
            if int(code or -1) != 200 and str(payload.get("msg") or payload.get("message") or ""):
                msg = str(payload.get("msg") or payload.get("message") or f"西部数码错误 {code}")
                # soft-fail only when clearly error
                if str(code) not in {"200"}:
                    raise DnsProviderApiError(msg, 400)
        return payload

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        payload = self._request("getdomains", {"page": page, "limit": page_size, "domain": keyword or ""})
        data = payload.get("data") if isinstance(payload.get("data"), (list, dict)) else payload.get("body")
        rows: List[Any] = []
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = data.get("items") or data.get("list") or data.get("domains") or []
        zones = []
        for d in rows or []:
            if isinstance(d, str):
                zones.append(_norm_zone(d, d, "active"))
            elif isinstance(d, dict):
                name = str(d.get("domain") or d.get("name") or d.get("Domain") or "")
                if name:
                    zones.append(_norm_zone(name, name, d.get("status") or "active", d.get("record_count")))
        zones = _filter_keyword(zones, keyword, ["name"])
        total = int(payload.get("total") or len(zones))
        return {"zones": zones, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        return _norm_zone(zone_id, zone_id, "active")

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        self._request("adddomain", {"domain": str(domain or "").strip()})
        return self.get_zone(str(domain or "").strip())

    def delete_zone(self, zone_id: str) -> bool:
        self._request("deldomain", {"domain": str(zone_id or "").strip()})
        return True

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        payload = self._request("getdnsrecord", {"domain": domain, "page": page, "limit": page_size})
        data = payload.get("data") if isinstance(payload.get("data"), (list, dict)) else payload.get("body")
        rows: List[Any] = []
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = data.get("items") or data.get("list") or data.get("records") or []
        records = []
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            rr = str(r.get("host") or r.get("rr") or r.get("name") or "")
            records.append(
                _norm_record(
                    r.get("id") or r.get("record_id"),
                    to_fqdn(rr, domain),
                    r.get("type") or r.get("record_type"),
                    r.get("value") or r.get("record_value"),
                    ttl=r.get("ttl"),
                    line=r.get("line") or r.get("view"),
                    priority=r.get("mx") or r.get("priority"),
                    status="1" if str(r.get("status") or "1") in {"1", "enable", "active"} else "0",
                )
            )
        filters = filters or {}
        if filters.get("keyword"):
            records = _filter_keyword(records, str(filters.get("keyword")), ["name", "value", "type"])
        return {"records": records, "total": int(payload.get("total") or len(records))}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        for r in (self.list_records(zone_id, 1, 500).get("records") or []):
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        rr = to_rr(str(params.get("name") or ""), domain)
        form = {
            "domain": domain,
            "host": "" if rr == "@" else rr,
            "type": str(params.get("type") or "").upper(),
            "value": str(params.get("value") or ""),
            "ttl": int(params.get("ttl") or 600),
            "line": params.get("line") or "default",
        }
        if params.get("priority") is not None:
            form["mx"] = int(params.get("priority"))
        payload = self._request("adddnsrecord", form)
        rid = str((payload.get("data") or {}).get("id") if isinstance(payload.get("data"), dict) else payload.get("id") or "")
        if rid:
            try:
                return self.get_record(zone_id, rid)
            except Exception:
                pass
        return _norm_record(rid, to_fqdn(rr, domain), form["type"], form["value"], ttl=form["ttl"], line=form["line"])

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        old = self.get_record(zone_id, record_id)
        rr = to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain)
        form = {
            "domain": domain,
            "id": str(record_id),
            "host": "" if rr == "@" else rr,
            "type": str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper(),
            "value": str(params.get("value") if params.get("value") is not None else old.get("value") or ""),
            "ttl": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 600),
            "line": params.get("line") if params.get("line") is not None else old.get("line") or "default",
        }
        self._request("moddnsrecord", form)
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request("deldnsrecord", {"domain": str(zone_id), "id": str(record_id)})
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        self._request(
            "pause",
            {"domain": str(zone_id), "id": str(record_id), "val": 0 if enabled else 1},
        )
        return True


# ── 火山引擎 Volcengine DNS ────────────────────────────────────────────


class HuoshanDnsApi(DnsProviderApi):
    """Volcengine DNS OpenAPI with HMAC-SHA256 signing."""

    provider = "huoshan"
    supports_status = True
    supports_line = True
    HOST = "open.volcengineapi.com"
    SERVICE = "dns"
    REGION = "cn-north-1"
    VERSION = "2018-08-01"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.ak = str(secrets.get("accessKeyId") or "").strip()
        self.sk = str(secrets.get("secretAccessKey") or secrets.get("accessKeySecret") or "").strip()
        if not self.ak or not self.sk:
            raise DnsProviderApiError("缺少火山引擎 AccessKeyId / SecretAccessKey", 400)
        self._zid_to_name: Dict[str, str] = {}

    def _sign_request(self, action: str, body: Dict[str, Any]) -> tuple[str, Dict[str, str], bytes]:
        payload = json.dumps(body or {}, ensure_ascii=False, separators=(",", ":"))
        data = payload.encode("utf-8")
        now = datetime.now(timezone.utc)
        x_date = now.strftime("%Y%m%dT%H%M%SZ")
        short_date = now.strftime("%Y%m%d")
        content_type = "application/json; charset=utf-8"
        query = urllib.parse.urlencode({"Action": action, "Version": self.VERSION})
        canonical_headers = f"content-type:{content_type}\nhost:{self.HOST}\nx-date:{x_date}\n"
        signed_headers = "content-type;host;x-date"
        payload_hash = hashlib.sha256(data).hexdigest()
        canonical_request = f"POST\n/\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        credential_scope = f"{short_date}/{self.REGION}/{self.SERVICE}/request"
        string_to_sign = f"HMAC-SHA256\n{x_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        k_date = hmac.new(self.sk.encode("utf-8"), short_date.encode("utf-8"), hashlib.sha256).digest()
        k_region = hmac.new(k_date, self.REGION.encode("utf-8"), hashlib.sha256).digest()
        k_service = hmac.new(k_region, self.SERVICE.encode("utf-8"), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b"request", hashlib.sha256).digest()
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        authorization = (
            f"HMAC-SHA256 Credential={self.ak}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers = {
            "Content-Type": content_type,
            "Host": self.HOST,
            "X-Date": x_date,
            "Authorization": authorization,
        }
        url = f"https://{self.HOST}/?{query}"
        return url, headers, data

    def _request(self, action: str, body: Dict[str, Any] | None = None) -> Dict[str, Any]:
        url, headers, data = self._sign_request(action, body or {})
        try:
            payload = _http_json("POST", url, headers=headers, body=data)
        except DnsProviderApiError as e:
            raise DnsProviderApiError(f"火山引擎 DNS: {e}", e.status) from e
        if not isinstance(payload, dict):
            raise DnsProviderApiError("火山引擎返回格式错误", 502)
        meta = payload.get("ResponseMetadata") if isinstance(payload.get("ResponseMetadata"), dict) else {}
        err = meta.get("Error") if isinstance(meta.get("Error"), dict) else None
        if err:
            raise DnsProviderApiError(str(err.get("Message") or err.get("Code") or "火山引擎 API 错误"), 400)
        result = payload.get("Result")
        return result if isinstance(result, dict) else payload

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"PageNumber": max(1, int(page)), "PageSize": max(1, min(100, int(page_size)))}
        if keyword:
            body["Key"] = keyword
        resp = self._request("ListZones", body)
        rows = resp.get("Zones") or resp.get("zones") or []
        zones = []
        for z in rows if isinstance(rows, list) else []:
            if not isinstance(z, dict):
                continue
            zid = str(z.get("ZID") or z.get("ZoneID") or z.get("id") or "")
            name = str(z.get("ZoneName") or z.get("name") or "")
            if zid:
                self._zid_to_name[zid] = name
            zones.append(_norm_zone(zid or name, name, z.get("Status") or "active", z.get("RecordCount"), z.get("UpdatedAt")))
        total = int(resp.get("Total") or resp.get("TotalCount") or len(zones))
        return {"zones": zones, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        try:
            resp = self._request("QueryZone", {"ZID": int(zone_id) if str(zone_id).isdigit() else zone_id})
        except Exception:
            resp = self._request("ListZones", {"Key": str(zone_id), "PageNumber": 1, "PageSize": 50})
            for z in resp.get("Zones") or []:
                if str(z.get("ZID") or "") == str(zone_id) or str(z.get("ZoneName") or "") == str(zone_id):
                    resp = z
                    break
        z = resp if isinstance(resp, dict) else {}
        zid = str(z.get("ZID") or z.get("ZoneID") or zone_id)
        name = str(z.get("ZoneName") or z.get("name") or self._zid_to_name.get(zid) or zone_id)
        self._zid_to_name[zid] = name
        return _norm_zone(zid, name, z.get("Status") or "active", z.get("RecordCount"), z.get("UpdatedAt"))

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        self._request("CreateZone", {"ZoneName": str(domain or "").strip()})
        result = self.list_zones(1, 50, domain)
        for z in result.get("zones") or []:
            if str(z.get("name") or "").lower() == str(domain).lower():
                return z
        return _norm_zone(domain, domain, "active")

    def delete_zone(self, zone_id: str) -> bool:
        body: Dict[str, Any] = {"ZID": int(zone_id) if str(zone_id).isdigit() else zone_id}
        self._request("DeleteZone", body)
        return True

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        filters = filters or {}
        body: Dict[str, Any] = {
            "ZID": int(zone_id) if str(zone_id).isdigit() else zone_id,
            "PageNumber": max(1, int(page)),
            "PageSize": max(1, min(500, int(page_size))),
        }
        name = filters.get("name") or filters.get("subDomain")
        domain = self._zid_to_name.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        if name:
            body["Host"] = to_rr(str(name), domain)
        if filters.get("type"):
            body["Type"] = str(filters.get("type")).upper()
        if filters.get("keyword"):
            body["Search"] = filters.get("keyword")
        resp = self._request("ListRecords", body)
        rows = resp.get("Records") or resp.get("records") or []
        records = []
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            host = str(r.get("Host") or r.get("host") or "")
            records.append(
                _norm_record(
                    r.get("RecordID") or r.get("RecordId") or r.get("ID"),
                    to_fqdn(host, domain),
                    r.get("Type"),
                    r.get("Value"),
                    ttl=r.get("TTL"),
                    line=r.get("Line"),
                    weight=r.get("Weight"),
                    priority=r.get("MX") or r.get("Priority"),
                    status="1" if str(r.get("Enable") if r.get("Enable") is not None else r.get("Status") or "1") in {"1", "True", "true", "ENABLE", "enable"} else "0",
                    remark=r.get("Remark"),
                    updated_at=r.get("UpdatedAt"),
                )
            )
        return {"records": records, "total": int(resp.get("Total") or resp.get("TotalCount") or len(records))}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        for r in (self.list_records(zone_id, 1, 500).get("records") or []):
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._zid_to_name.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        body: Dict[str, Any] = {
            "ZID": int(zone_id) if str(zone_id).isdigit() else zone_id,
            "Host": to_rr(str(params.get("name") or ""), domain),
            "Type": str(params.get("type") or "").upper(),
            "Value": str(params.get("value") or ""),
            "TTL": int(params.get("ttl") or 600),
            "Line": params.get("line") or "default",
        }
        if params.get("priority") is not None:
            body["MX"] = int(params.get("priority"))
        if params.get("weight") is not None:
            body["Weight"] = int(params.get("weight"))
        if params.get("remark"):
            body["Remark"] = str(params.get("remark"))
        resp = self._request("CreateRecord", body)
        rid = str(resp.get("RecordID") or resp.get("RecordId") or resp.get("ID") or "")
        if rid:
            try:
                return self.get_record(zone_id, rid)
            except Exception:
                pass
        return _norm_record(rid, to_fqdn(body["Host"], domain), body["Type"], body["Value"], ttl=body["TTL"], line=body["Line"])

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._zid_to_name.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        old = self.get_record(zone_id, record_id)
        body: Dict[str, Any] = {
            "RecordID": str(record_id),
            "Host": to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain),
            "Type": str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper(),
            "Value": str(params.get("value") if params.get("value") is not None else old.get("value") or ""),
            "TTL": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 600),
            "Line": params.get("line") if params.get("line") is not None else old.get("line") or "default",
        }
        if params.get("priority") is not None or old.get("priority") is not None:
            body["MX"] = int(params.get("priority") if params.get("priority") is not None else old.get("priority") or 0)
        self._request("UpdateRecord", body)
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request("DeleteRecord", {"RecordID": str(record_id)})
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        self._request("UpdateRecordStatus", {"RecordID": str(record_id), "Enable": bool(enabled)})
        return True


# ── 京东云 JD Cloud DNS ────────────────────────────────────────────────


class JdcloudDnsApi(DnsProviderApi):
    provider = "jdcloud"
    supports_status = True
    supports_line = True
    HOST = "domainservice.jdcloud-api.com"
    REGION = "cn-north-1"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.ak = str(secrets.get("accessKeyId") or "").strip()
        self.sk = str(secrets.get("accessKeySecret") or secrets.get("secretAccessKey") or "").strip()
        if not self.ak or not self.sk:
            raise DnsProviderApiError("缺少京东云 AccessKeyId / AccessKeySecret", 400)

    def _sign(self, method: str, path: str, query: str, headers: Dict[str, str], body: str) -> Dict[str, str]:
        now = datetime.now(timezone.utc)
        x_date = now.strftime("%Y%m%dT%H%M%SZ")
        short_date = now.strftime("%Y%m%d")
        headers = dict(headers)
        headers["x-jdcloud-date"] = x_date
        headers["host"] = self.HOST
        content_type = headers.get("Content-Type", "application/json")
        signed_headers = "content-type;host;x-jdcloud-date"
        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        canonical_headers = f"content-type:{content_type}\nhost:{self.HOST}\nx-jdcloud-date:{x_date}\n"
        canonical_request = f"{method.upper()}\n{path}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        credential_scope = f"{short_date}/{self.REGION}/domainservice/jdcloud_request"
        string_to_sign = f"JDCLOUD2-HMAC-SHA256\n{x_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        k_date = hmac.new(("JDCLOUD2" + self.sk).encode("utf-8"), short_date.encode("utf-8"), hashlib.sha256).digest()
        k_region = hmac.new(k_date, self.REGION.encode("utf-8"), hashlib.sha256).digest()
        k_service = hmac.new(k_region, b"domainservice", hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b"jdcloud_request", hashlib.sha256).digest()
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        headers["Authorization"] = (
            f"JDCLOUD2-HMAC-SHA256 Credential={self.ak}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return headers

    def _request(self, method: str, path: str, query: Dict[str, Any] | None = None, body: Any = None) -> Any:
        qp = {str(k): str(v) for k, v in (query or {}).items() if v is not None and v != ""}
        query_str = urllib.parse.urlencode(sorted(qp.items()))
        url = f"https://{self.HOST}{path}"
        if query_str:
            url += f"?{query_str}"
        body_str = json.dumps(body, ensure_ascii=False) if body is not None else ""
        headers = self._sign(method, path, query_str, {"Content-Type": "application/json"}, body_str)
        try:
            return _http_json(method, url, headers=headers, body=body_str if body is not None else None)
        except DnsProviderApiError as e:
            raise DnsProviderApiError(f"京东云 DNS: {e}", e.status) from e

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        query: Dict[str, Any] = {"pageNumber": max(1, int(page)), "pageSize": max(1, min(100, int(page_size)))}
        if keyword:
            query["domainName"] = keyword
        resp = self._request("GET", f"/v2/regions/{self.REGION}/domain", query)
        result = resp.get("result") if isinstance(resp, dict) else {}
        rows = (result or {}).get("dataList") or (result or {}).get("domains") or resp.get("dataList") or []
        zones = []
        for z in rows if isinstance(rows, list) else []:
            if not isinstance(z, dict):
                continue
            zid = str(z.get("id") or z.get("domainId") or "")
            name = str(z.get("domainName") or z.get("name") or "")
            zones.append(_norm_zone(zid or name, name, z.get("status") or "active", z.get("recordCount")))
        total = int((result or {}).get("totalCount") or len(zones))
        return {"zones": zones, "total": total}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        resp = self._request("GET", f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}")
        z = resp.get("result") if isinstance(resp, dict) else resp
        if not isinstance(z, dict):
            z = {}
        return _norm_zone(z.get("id") or zone_id, z.get("domainName") or z.get("name") or zone_id, z.get("status") or "active")

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        self._request("POST", f"/v2/regions/{self.REGION}/domain", body={"domainName": str(domain or "").strip()})
        result = self.list_zones(1, 50, domain)
        for z in result.get("zones") or []:
            if str(z.get("name") or "").lower() == str(domain).lower():
                return z
        return _norm_zone(domain, domain, "active")

    def delete_zone(self, zone_id: str) -> bool:
        self._request("DELETE", f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}")
        return True

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        filters = filters or {}
        query: Dict[str, Any] = {"pageNumber": max(1, int(page)), "pageSize": max(1, min(100, int(page_size)))}
        if filters.get("type"):
            query["type"] = str(filters.get("type")).upper()
        name = filters.get("name") or filters.get("subDomain")
        if name:
            query["search"] = name
        resp = self._request("GET", f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}/ResourceRecord", query)
        result = resp.get("result") if isinstance(resp, dict) else {}
        rows = (result or {}).get("dataList") or (result or {}).get("records") or []
        zone = self.get_zone(zone_id)
        domain = str(zone.get("name") or zone_id)
        records = []
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            host = str(r.get("hostRecord") or r.get("host") or r.get("name") or "")
            records.append(
                _norm_record(
                    r.get("id") or r.get("recordId"),
                    to_fqdn(host, domain),
                    r.get("type") or r.get("hostType"),
                    r.get("hostValue") or r.get("value"),
                    ttl=r.get("ttl"),
                    line=r.get("viewValue") or r.get("line"),
                    weight=r.get("weight"),
                    priority=r.get("mxPriority") or r.get("priority"),
                    status="1" if str(r.get("status") or "1") in {"1", "enable", "active"} else "0",
                )
            )
        return {"records": records, "total": int((result or {}).get("totalCount") or len(records))}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        for r in (self.list_records(zone_id, 1, 500).get("records") or []):
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        zone = self.get_zone(zone_id)
        domain = str(zone.get("name") or zone_id)
        body = {
            "hostRecord": to_rr(str(params.get("name") or ""), domain),
            "hostType": str(params.get("type") or "").upper(),
            "hostValue": str(params.get("value") or ""),
            "ttl": int(params.get("ttl") or 300),
            "viewValue": -1,
        }
        if params.get("priority") is not None:
            body["mxPriority"] = int(params.get("priority"))
        if params.get("weight") is not None:
            body["weight"] = int(params.get("weight"))
        resp = self._request(
            "POST",
            f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}/ResourceRecord",
            body=body,
        )
        rid = str((resp.get("result") or {}).get("id") if isinstance(resp.get("result"), dict) else resp.get("id") or "")
        if rid:
            try:
                return self.get_record(zone_id, rid)
            except Exception:
                pass
        return _norm_record(rid, to_fqdn(body["hostRecord"], domain), body["hostType"], body["hostValue"], ttl=body["ttl"])

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        zone = self.get_zone(zone_id)
        domain = str(zone.get("name") or zone_id)
        old = self.get_record(zone_id, record_id)
        body = {
            "hostRecord": to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain),
            "hostType": str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper(),
            "hostValue": str(params.get("value") if params.get("value") is not None else old.get("value") or ""),
            "ttl": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 300),
            "viewValue": -1,
        }
        self._request(
            "PUT",
            f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}/ResourceRecord/{quote(str(record_id), safe='')}",
            body=body,
        )
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request(
            "DELETE",
            f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}/ResourceRecord/{quote(str(record_id), safe='')}",
        )
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        self._request(
            "PUT",
            f"/v2/regions/{self.REGION}/domain/{quote(str(zone_id), safe='')}/ResourceRecord/{quote(str(record_id), safe='')}/status",
            body={"status": 1 if enabled else 0},
        )
        return True


# ── DNSLA ──────────────────────────────────────────────────────────────


class DnslaDnsApi(DnsProviderApi):
    provider = "dnsla"
    supports_status = True
    supports_line = True
    BASE = "https://api.dns.la"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.api_id = str(secrets.get("apiId") or "").strip()
        self.api_secret = str(secrets.get("apiSecret") or "").strip()
        if not self.api_id or not self.api_secret:
            raise DnsProviderApiError("缺少 DNSLA apiId / apiSecret", 400)
        token = base64.b64encode(f"{self.api_id}:{self.api_secret}".encode("utf-8")).decode("ascii")
        self._auth = f"Basic {token}"
        self._domain_map: Dict[str, str] = {}

    def _request(self, method: str, path: str, query: Dict[str, Any] | None = None, body: Any = None) -> Any:
        qp = {str(k): str(v) for k, v in (query or {}).items() if v is not None and v != ""}
        url = f"{self.BASE}{path}"
        if qp:
            url += "?" + urllib.parse.urlencode(qp)
        headers = {"Authorization": self._auth, "Content-Type": "application/json"}
        try:
            payload = _http_json(method, url, headers=headers, body=body)
        except DnsProviderApiError as e:
            raise DnsProviderApiError(f"DNSLA: {e}", e.status) from e
        if not isinstance(payload, dict):
            raise DnsProviderApiError("DNSLA 返回格式错误", 502)
        code = payload.get("code")
        if code not in (None, 200, 0, "200", "0"):
            raise DnsProviderApiError(str(payload.get("msg") or payload.get("message") or f"DNSLA 错误 {code}"), 400)
        return payload.get("data") if "data" in payload else payload

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        data = self._request("GET", "/api/domainList", {"pageIndex": max(1, int(page)), "pageSize": max(1, min(100, int(page_size)))})
        rows = []
        total = 0
        if isinstance(data, dict):
            rows = data.get("results") or data.get("list") or data.get("domains") or []
            total = int(data.get("total") or data.get("totalCount") or 0)
        elif isinstance(data, list):
            rows = data
            total = len(rows)
        zones = []
        for z in rows if isinstance(rows, list) else []:
            if not isinstance(z, dict):
                continue
            zid = str(z.get("id") or z.get("domainId") or "")
            name = str(z.get("displayDomain") or z.get("domain") or z.get("name") or "")
            if zid:
                self._domain_map[zid] = name
            zones.append(_norm_zone(zid or name, name, z.get("state") or "active", z.get("recordCount")))
        if keyword:
            zones = _filter_keyword(zones, keyword, ["name"])
        return {"zones": zones, "total": total or len(zones)}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        data = self._request("GET", f"/api/domain/{quote(str(zone_id), safe='')}")
        if not isinstance(data, dict):
            name = self._domain_map.get(str(zone_id), str(zone_id))
            return _norm_zone(zone_id, name, "active")
        name = str(data.get("displayDomain") or data.get("domain") or data.get("name") or zone_id)
        self._domain_map[str(zone_id)] = name
        return _norm_zone(data.get("id") or zone_id, name, data.get("state") or "active", data.get("recordCount"))

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        data = self._request("POST", "/api/domain", body={"domain": str(domain or "").strip()})
        if isinstance(data, dict):
            zid = str(data.get("id") or "")
            name = str(data.get("displayDomain") or data.get("domain") or domain)
            return _norm_zone(zid or name, name, "active")
        return _norm_zone(domain, domain, "active")

    def delete_zone(self, zone_id: str) -> bool:
        self._request("DELETE", f"/api/domain/{quote(str(zone_id), safe='')}")
        return True

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        filters = filters or {}
        query: Dict[str, Any] = {
            "domainId": str(zone_id),
            "pageIndex": max(1, int(page)),
            "pageSize": max(1, min(100, int(page_size))),
        }
        if filters.get("type"):
            query["type"] = str(filters.get("type")).upper()
        name = filters.get("name") or filters.get("subDomain")
        if name:
            query["host"] = name
        data = self._request("GET", "/api/recordList", query)
        rows = []
        total = 0
        if isinstance(data, dict):
            rows = data.get("results") or data.get("list") or data.get("records") or []
            total = int(data.get("total") or 0)
        domain = self._domain_map.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        records = []
        for r in rows if isinstance(rows, list) else []:
            if not isinstance(r, dict):
                continue
            host = str(r.get("host") or r.get("displayHost") or r.get("name") or "")
            records.append(
                _norm_record(
                    r.get("id"),
                    to_fqdn(host, domain),
                    r.get("type"),
                    r.get("data") or r.get("value"),
                    ttl=r.get("ttl"),
                    line=r.get("lineId") or r.get("line"),
                    weight=r.get("weight"),
                    priority=r.get("preference") or r.get("priority") or r.get("mx"),
                    status="1" if str(r.get("enabled") if r.get("enabled") is not None else r.get("status") or "1") in {"1", "True", "true", "enable"} else "0",
                    remark=r.get("remark"),
                )
            )
        if filters.get("keyword"):
            records = _filter_keyword(records, str(filters.get("keyword")), ["name", "value", "type"])
        return {"records": records, "total": total or len(records)}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        data = self._request("GET", f"/api/record/{quote(str(record_id), safe='')}")
        if not isinstance(data, dict):
            raise DnsProviderApiError("记录不存在", 404)
        domain = self._domain_map.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        host = str(data.get("host") or data.get("displayHost") or "")
        return _norm_record(
            data.get("id") or record_id,
            to_fqdn(host, domain),
            data.get("type"),
            data.get("data") or data.get("value"),
            ttl=data.get("ttl"),
            line=data.get("lineId") or data.get("line"),
            weight=data.get("weight"),
            priority=data.get("preference") or data.get("priority"),
            status="1" if str(data.get("enabled") if data.get("enabled") is not None else "1") in {"1", "True", "true"} else "0",
            remark=data.get("remark"),
        )

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._domain_map.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        body: Dict[str, Any] = {
            "domainId": str(zone_id),
            "type": str(params.get("type") or "").upper(),
            "host": to_rr(str(params.get("name") or ""), domain),
            "data": str(params.get("value") or ""),
            "ttl": int(params.get("ttl") or 600),
        }
        if params.get("line"):
            body["lineId"] = params.get("line")
        if params.get("priority") is not None:
            body["preference"] = int(params.get("priority"))
        if params.get("weight") is not None:
            body["weight"] = int(params.get("weight"))
        data = self._request("POST", "/api/record", body=body)
        rid = str((data or {}).get("id") if isinstance(data, dict) else data or "")
        if rid:
            try:
                return self.get_record(zone_id, rid)
            except Exception:
                pass
        return _norm_record(rid, to_fqdn(body["host"], domain), body["type"], body["data"], ttl=body["ttl"])

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = self._domain_map.get(str(zone_id)) or str(self.get_zone(zone_id).get("name") or "")
        old = self.get_record(zone_id, record_id)
        body: Dict[str, Any] = {
            "id": str(record_id),
            "domainId": str(zone_id),
            "type": str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper(),
            "host": to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain),
            "data": str(params.get("value") if params.get("value") is not None else old.get("value") or ""),
            "ttl": int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 600),
        }
        if params.get("line") is not None or old.get("line"):
            body["lineId"] = params.get("line") if params.get("line") is not None else old.get("line")
        if params.get("priority") is not None or old.get("priority") is not None:
            body["preference"] = int(params.get("priority") if params.get("priority") is not None else old.get("priority") or 0)
        self._request("PUT", "/api/record", body=body)
        return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request("DELETE", f"/api/record/{quote(str(record_id), safe='')}")
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        self._request("PUT", "/api/recordDisable", body={"id": str(record_id), "disable": not enabled})
        return True


# ── Spaceship ──────────────────────────────────────────────────────────


class SpaceshipDnsApi(DnsProviderApi):
    provider = "spaceship"
    supports_status = False
    supports_line = False
    BASE = "https://spaceship.dev/api/v1"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        self.api_key = str(secrets.get("apiKey") or "").strip()
        self.api_secret = str(secrets.get("apiSecret") or "").strip()
        if not self.api_key or not self.api_secret:
            raise DnsProviderApiError("缺少 Spaceship apiKey / apiSecret", 400)

    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "X-API-Secret": self.api_secret,
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, query: Dict[str, Any] | None = None, body: Any = None) -> Any:
        qp = {str(k): str(v) for k, v in (query or {}).items() if v is not None and v != ""}
        url = f"{self.BASE}{path}"
        if qp:
            url += "?" + urllib.parse.urlencode(qp)
        try:
            return _http_json(method, url, headers=self._headers(), body=body)
        except DnsProviderApiError as e:
            raise DnsProviderApiError(f"Spaceship: {e}", e.status) from e

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        # Spaceship domains endpoint
        data = self._request("GET", "/domains", {"take": int(page_size), "skip": (max(1, int(page)) - 1) * int(page_size)})
        rows = []
        total = 0
        if isinstance(data, dict):
            rows = data.get("items") or data.get("domains") or data.get("results") or []
            total = int(data.get("total") or data.get("totalCount") or 0)
        elif isinstance(data, list):
            rows = data
            total = len(rows)
        zones = []
        for z in rows if isinstance(rows, list) else []:
            if isinstance(z, str):
                zones.append(_norm_zone(z, z, "active"))
            elif isinstance(z, dict):
                name = str(z.get("unicodeName") or z.get("name") or z.get("domain") or "")
                if name:
                    zones.append(_norm_zone(name, name, z.get("status") or "active"))
        if keyword:
            zones = _filter_keyword(zones, keyword, ["name"])
        return {"zones": zones, "total": total or len(zones)}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        return _norm_zone(zone_id, zone_id, "active")

    def create_zone(self, domain: str, **kwargs: Any) -> Dict[str, Any]:
        raise DnsProviderApiError("Spaceship 不支持通过 API 添加域名（请先在控制台购买/转入）", 400)

    def delete_zone(self, zone_id: str) -> bool:
        raise DnsProviderApiError("Spaceship 不支持通过 API 删除域名", 400)

    def list_records(
        self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None
    ) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        data = self._request("GET", f"/dns/records/{quote(domain, safe='')}", {"take": 500, "skip": 0})
        rows = []
        if isinstance(data, dict):
            rows = data.get("items") or data.get("records") or data.get("dnsRecords") or []
        elif isinstance(data, list):
            rows = data
        records = []
        for idx, r in enumerate(rows if isinstance(rows, list) else []):
            if not isinstance(r, dict):
                continue
            rtype = str(r.get("type") or "").upper()
            name = str(r.get("name") or r.get("host") or "@")
            fqdn = to_fqdn(name, domain)
            # address / value fields vary by type
            value = (
                r.get("address")
                or r.get("value")
                or r.get("cname")
                or r.get("exchange")
                or r.get("pointer")
                or r.get("text")
                or r.get("nameserver")
                or ""
            )
            if isinstance(value, list):
                value = " ".join(str(x) for x in value)
            priority = r.get("priority") or r.get("preference")
            rid = str(r.get("id") or f"{name}|{rtype}|{value}|{idx}")
            records.append(
                _norm_record(rid, fqdn, rtype, value, ttl=r.get("ttl"), priority=priority)
            )
        filters = filters or {}
        if filters.get("type"):
            t = str(filters.get("type")).upper()
            records = [x for x in records if x.get("type") == t]
        name_f = filters.get("name") or filters.get("subDomain")
        if name_f:
            target = to_fqdn(str(name_f), domain).lower()
            records = [x for x in records if str(x.get("name") or "").lower() == target]
        if filters.get("keyword"):
            records = _filter_keyword(records, str(filters.get("keyword")), ["name", "value", "type"])
        page_items, total = _paginate_client(records, page, page_size)
        return {"records": page_items, "total": total}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        for r in (self.list_records(zone_id, 1, 500).get("records") or []):
            if str(r.get("id")) == str(record_id):
                return r
        raise DnsProviderApiError("记录不存在", 404)

    def _record_body(self, domain: str, params: Dict[str, Any], old: Dict[str, Any] | None = None) -> Dict[str, Any]:
        old = old or {}
        rtype = str(params.get("type") if params.get("type") is not None else old.get("type") or "").upper()
        name = to_rr(str(params.get("name") if params.get("name") is not None else old.get("name") or ""), domain)
        value = str(params.get("value") if params.get("value") is not None else old.get("value") or "")
        ttl = int(params.get("ttl") if params.get("ttl") is not None else old.get("ttl") or 3600)
        body: Dict[str, Any] = {"type": rtype, "name": "" if name == "@" else name, "ttl": ttl}
        if rtype in {"A", "AAAA"}:
            body["address"] = value
        elif rtype == "CNAME":
            body["cname"] = value
        elif rtype == "MX":
            body["exchange"] = value
            body["preference"] = int(params.get("priority") if params.get("priority") is not None else old.get("priority") or 10)
        elif rtype == "TXT":
            body["value"] = value
        elif rtype == "NS":
            body["nameserver"] = value
        elif rtype == "PTR":
            body["pointer"] = value
        else:
            body["value"] = value
        return body

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        body = self._record_body(domain, params)
        # Spaceship uses PUT to replace/add force list — try POST first
        try:
            self._request("POST", f"/dns/records/{quote(domain, safe='')}", body=[body])
        except DnsProviderApiError:
            self._request("PUT", f"/dns/records/{quote(domain, safe='')}", body={"force": False, "items": [body]})
        result = self.list_records(zone_id, 1, 500, {"name": params.get("name"), "type": params.get("type")})
        for r in result.get("records") or []:
            if str(r.get("value") or "") == str(params.get("value") or ""):
                return r
        records = result.get("records") or []
        return records[-1] if records else _norm_record("", to_fqdn(str(params.get("name") or ""), domain), params.get("type"), params.get("value"), ttl=params.get("ttl"))

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        domain = str(zone_id or "").strip()
        old = self.get_record(zone_id, record_id)
        # delete old + create new (Spaceship often lacks per-id update)
        try:
            self.delete_record(zone_id, record_id)
        except Exception:
            pass
        return self.create_record(zone_id, {
            "name": params.get("name") if params.get("name") is not None else old.get("name"),
            "type": params.get("type") if params.get("type") is not None else old.get("type"),
            "value": params.get("value") if params.get("value") is not None else old.get("value"),
            "ttl": params.get("ttl") if params.get("ttl") is not None else old.get("ttl"),
            "priority": params.get("priority") if params.get("priority") is not None else old.get("priority"),
        })

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        domain = str(zone_id or "").strip()
        old = self.get_record(zone_id, record_id)
        body = self._record_body(domain, {
            "name": old.get("name"),
            "type": old.get("type"),
            "value": old.get("value"),
            "ttl": old.get("ttl"),
            "priority": old.get("priority"),
        })
        try:
            self._request("DELETE", f"/dns/records/{quote(domain, safe='')}", body=[body])
        except DnsProviderApiError:
            # some APIs use POST with delete action
            self._request("PUT", f"/dns/records/{quote(domain, safe='')}", body={"force": True, "items": []})
            # re-add others except deleted
            result = self.list_records(zone_id, 1, 500)
            keep = []
            for r in result.get("records") or []:
                if str(r.get("id")) == str(record_id):
                    continue
                keep.append(self._record_body(domain, r))
            if keep:
                self._request("PUT", f"/dns/records/{quote(domain, safe='')}", body={"force": True, "items": keep})
        return True

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        return 60


# ── Factory ────────────────────────────────────────────────────────────


_PROVIDER_BUILDERS = {
    "cloudflare": lambda s: CloudflareDnsApi(s),
    "dnspod": lambda s: DnspodDnsApi(s, "dnspod"),
    "dnspod_token": lambda s: DnspodDnsApi(s, "dnspod_token"),
    "aliyun": lambda s: AliyunDnsApi(s),
    "huawei": lambda s: HuaweiDnsApi(s),
    "baidu": lambda s: BaiduDnsApi(s),
    "west": lambda s: WestDnsApi(s),
    "huoshan": lambda s: HuoshanDnsApi(s),
    "jdcloud": lambda s: JdcloudDnsApi(s),
    "dnsla": lambda s: DnslaDnsApi(s),
    "namesilo": lambda s: NamesiloDnsApi(s),
    "powerdns": lambda s: PowerDnsApi(s),
    "spaceship": lambda s: SpaceshipDnsApi(s),
}


def build_dns_provider_api(provider: str, secrets: dict) -> DnsProviderApi:
    p = str(provider or "").strip().lower()
    builder = _PROVIDER_BUILDERS.get(p)
    if not builder:
        raise DnsProviderApiError(f"当前不支持提供商 {provider} 的 DNS 记录操作", 400)
    try:
        return builder(secrets or {})
    except DnsProviderApiError:
        raise
    except Exception as e:
        raise DnsProviderApiError(str(e) or f"初始化 {provider} 客户端失败", 400) from e
