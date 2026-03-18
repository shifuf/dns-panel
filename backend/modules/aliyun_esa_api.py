from __future__ import annotations

import hashlib
import hmac
import json
import random
import socket
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Tuple


ESA_VERSION = "2024-09-10"
DEFAULT_REGION = "cn-hangzhou"


class AliyunEsaError(Exception):
    def __init__(self, message: str, code: str = "", http_status: int = 400, meta: Dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.http_status = http_status
        self.meta = meta or {}


def _iso8601_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _percent_encode(value: str) -> str:
    return urllib.parse.quote(str(value or ""), safe="~")


def _canonical_query(params: Dict[str, str]) -> str:
    keys = sorted(params.keys())
    return "&".join(f"{_percent_encode(k)}={_percent_encode(params[k])}" for k in keys)


def _sign_v2(access_key_secret: str, method: str, canonicalized_query: str) -> str:
    string_to_sign = f"{method}&%2F&{_percent_encode(canonicalized_query)}"
    key = f"{access_key_secret}&".encode("utf-8")
    digest = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha1).digest()
    import base64

    return base64.b64encode(digest).decode("ascii")


def _build_signed_params(
    access_key_id: str,
    access_key_secret: str,
    action: str,
    extra_params: Dict[str, Any],
    version: str = ESA_VERSION,
    method: str = "GET",
) -> Dict[str, str]:
    params: Dict[str, str] = {
        "Action": action,
        "Version": version,
        "Format": "JSON",
        "AccessKeyId": str(access_key_id),
        "SignatureMethod": "HMAC-SHA1",
        "SignatureVersion": "1.0",
        "SignatureNonce": "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24)),
        "Timestamp": _iso8601_now(),
    }
    for k, v in extra_params.items():
        if v is None:
            continue
        params[str(k)] = str(v)
    canonical = _canonical_query(params)
    params["Signature"] = _sign_v2(access_key_secret, method, canonical)
    return params


def _endpoint(region: str | None) -> str:
    r = str(region or DEFAULT_REGION).strip() or DEFAULT_REGION
    return f"esa.{r}.aliyuncs.com"


def _normalize_msg(code: str, message: str) -> str:
    c = str(code or "").strip()
    m = str(message or "").strip()
    if c and m:
        return f"{c}: {m}"
    if c:
        return c
    return m or "ESA 请求失败"


def request_esa(
    access_key_id: str,
    access_key_secret: str,
    action: str,
    extra_params: Dict[str, Any],
    region: str | None = None,
) -> Dict[str, Any]:
    host = _endpoint(region)

    def call(method: str) -> Dict[str, Any]:
        signed = _build_signed_params(access_key_id, access_key_secret, action, extra_params, ESA_VERSION, method)
        query = _canonical_query(signed)
        url = f"https://{host}/?{query}" if method == "GET" else f"https://{host}/"
        data = query.encode("utf-8") if method == "POST" else None
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"} if method == "POST" else {}
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                status = int(resp.getcode() or 200)
                raw = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status = int(e.code or 400)
            raw = e.read().decode("utf-8", errors="ignore") if e.fp else ""
        except Exception as e:
            raise AliyunEsaError(f"ESA 网络请求失败: {e}", "NETWORK_ERROR", 503)

        try:
            payload = json.loads(raw) if raw else {}
        except Exception:
            raise AliyunEsaError("ESA 返回非 JSON 响应", "INVALID_JSON", status)

        if not isinstance(payload, dict):
            raise AliyunEsaError("ESA 返回格式错误", "INVALID_PAYLOAD", status)

        code = str(payload.get("Code") or payload.get("code") or "").strip()
        msg = str(payload.get("Message") or payload.get("message") or "").strip()
        if code:
            raise AliyunEsaError(_normalize_msg(code, msg), code, status, payload)
        if status >= 400:
            raise AliyunEsaError(msg or f"HTTP 错误: {status}", "HTTP_ERROR", status, payload)
        return payload

    try:
        return call("POST")
    except AliyunEsaError as e:
        if e.code == "UnsupportedHTTPMethod":
            return call("GET")
        raise


def list_sites(access_key_id: str, access_key_secret: str, region: str | None, page_number: int, page_size: int, keyword: str | None) -> Dict[str, Any]:
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "ListSites",
        {
            "PageNumber": max(1, int(page_number)),
            "PageSize": max(1, min(500, int(page_size))),
            "SiteName": str(keyword or "").strip() or None,
            "SiteSearchType": "fuzzy" if str(keyword or "").strip() else None,
        },
        region,
    )
    raw_sites = payload.get("Sites")
    sites = []
    if isinstance(raw_sites, list):
        for s in raw_sites:
            if not isinstance(s, dict):
                continue
            site_id = s.get("SiteId")
            site_name = str(s.get("SiteName") or "").strip()
            if site_id in (None, "") or not site_name:
                continue
            sites.append(
                {
                    "siteId": str(site_id),
                    "siteName": site_name,
                    "status": s.get("Status"),
                    "accessType": s.get("AccessType"),
                    "coverage": s.get("Coverage"),
                    "cnameZone": s.get("CnameZone"),
                    "nameServerList": s.get("NameServerList"),
                    "verifyCode": s.get("VerifyCode"),
                    "instanceId": s.get("InstanceId"),
                    "planName": s.get("PlanName"),
                    "planSpecName": s.get("PlanSpecName"),
                    "resourceGroupId": s.get("ResourceGroupId"),
                    "createTime": s.get("CreateTime"),
                    "updateTime": s.get("UpdateTime"),
                    "visitTime": s.get("VisitTime"),
                    "offlineReason": s.get("OfflineReason"),
                    "tags": s.get("Tags") if isinstance(s.get("Tags"), dict) else None,
                }
            )
    return {
        "sites": sites,
        "total": int(payload.get("TotalCount") or len(sites)),
        "pageNumber": int(payload.get("PageNumber") or page_number),
        "pageSize": int(payload.get("PageSize") or page_size),
        "requestId": payload.get("RequestId"),
    }


def list_instances(
    access_key_id: str,
    access_key_secret: str,
    region: str | None,
    page_number: int,
    page_size: int,
    status: str | None,
    check_remaining_site_quota: bool,
) -> Dict[str, Any]:
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "ListUserRatePlanInstances",
        {
            "PageNumber": max(1, int(page_number)),
            "PageSize": max(1, min(500, int(page_size))),
            "Status": str(status or "").strip() or None,
            "CheckRemainingSiteQuota": "true" if check_remaining_site_quota else None,
        },
        region,
    )
    raw_instances = payload.get("InstanceInfo")
    instances = []
    if isinstance(raw_instances, list):
        for it in raw_instances:
            if not isinstance(it, dict):
                continue
            instance_id = str(it.get("InstanceId") or "").strip()
            if not instance_id:
                continue
            site_quota = it.get("SiteQuota")
            used_sites = it.get("Sites")
            instances.append(
                {
                    "instanceId": instance_id,
                    "planName": it.get("PlanName"),
                    "planType": it.get("PlanType"),
                    "siteQuota": int(site_quota) if isinstance(site_quota, (int, str)) and str(site_quota).isdigit() else None,
                    "usedSiteCount": len(used_sites) if isinstance(used_sites, list) else None,
                    "expireTime": it.get("ExpireTime"),
                    "duration": int(it.get("Duration")) if isinstance(it.get("Duration"), (int, str)) and str(it.get("Duration")).isdigit() else None,
                    "createTime": it.get("CreateTime"),
                    "status": it.get("Status"),
                    "coverages": it.get("Coverages"),
                    "billingMode": it.get("BillingMode"),
                }
            )
    return {
        "instances": instances,
        "total": int(payload.get("TotalCount") or len(instances)),
        "pageNumber": int(payload.get("PageNumber") or page_number),
        "pageSize": int(payload.get("PageSize") or page_size),
        "requestId": payload.get("RequestId"),
    }


def create_site(access_key_id: str, access_key_secret: str, region: str | None, site_name: str, coverage: str, access_type: str, instance_id: str) -> Dict[str, Any]:
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "CreateSite",
        {
            "SiteName": site_name,
            "Coverage": coverage,
            "AccessType": access_type,
            "InstanceId": instance_id,
        },
        region,
    )
    return {
        "siteId": str(payload.get("SiteId") or ""),
        "verifyCode": payload.get("VerifyCode"),
        "nameServerList": payload.get("NameServerList"),
        "requestId": payload.get("RequestId"),
    }


def verify_site(access_key_id: str, access_key_secret: str, region: str | None, site_id: str) -> Dict[str, Any]:
    payload = request_esa(access_key_id, access_key_secret, "VerifySite", {"SiteId": site_id}, region)
    return {"passed": bool(payload.get("Passed")), "requestId": payload.get("RequestId")}


def delete_site(access_key_id: str, access_key_secret: str, region: str | None, site_id: str) -> Dict[str, Any]:
    payload = request_esa(access_key_id, access_key_secret, "DeleteSite", {"SiteId": site_id}, region)
    return {"deleted": True, "requestId": payload.get("RequestId")}


def update_site_pause(access_key_id: str, access_key_secret: str, region: str | None, site_id: str, paused: bool) -> Dict[str, Any]:
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "UpdateSitePause",
        {"SiteId": site_id, "Paused": "true" if paused else "false", "RegionId": str(region or DEFAULT_REGION)},
        region,
    )
    return {"updated": True, "requestId": payload.get("RequestId")}


def list_site_tags(access_key_id: str, access_key_secret: str, region_id: str | None, site_id: str) -> Dict[str, Any]:
    region = str(region_id or DEFAULT_REGION).strip() or DEFAULT_REGION
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "ListTagResources",
        {
            "RegionId": region,
            "ResourceType": "site",
            "ResourceId.1": site_id,
        },
        region,
    )
    tags: Dict[str, str] = {}
    raw = payload.get("TagResources")
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            k = str(item.get("TagKey") or "").strip()
            if not k:
                continue
            tags[k] = "" if item.get("TagValue") is None else str(item.get("TagValue"))
    return {"tags": tags, "requestId": payload.get("RequestId")}


def update_site_tags(access_key_id: str, access_key_secret: str, region_id: str | None, site_id: str, tags: Dict[str, Any]) -> Dict[str, Any]:
    region = str(region_id or DEFAULT_REGION).strip() or DEFAULT_REGION
    normalized: Dict[str, str] = {}
    for k, v in (tags or {}).items():
        kk = str(k or "").strip()
        if not kk:
            continue
        normalized[kk] = "" if v is None else str(v)

    if not normalized:
        payload = request_esa(
            access_key_id,
            access_key_secret,
            "UntagResources",
            {
                "RegionId": region,
                "ResourceType": "site",
                "ResourceId.1": site_id,
                "All": "true",
            },
            region,
        )
        return {"updated": True, "requestId": payload.get("RequestId")}

    # Replace strategy: clear all then set all.
    request_esa(
        access_key_id,
        access_key_secret,
        "UntagResources",
        {
            "RegionId": region,
            "ResourceType": "site",
            "ResourceId.1": site_id,
            "All": "true",
        },
        region,
    )

    params: Dict[str, Any] = {
        "RegionId": region,
        "ResourceType": "site",
        "ResourceId.1": site_id,
    }
    i = 1
    for k, v in normalized.items():
        params[f"Tag.{i}.Key"] = k
        params[f"Tag.{i}.Value"] = v
        i += 1
    payload = request_esa(access_key_id, access_key_secret, "TagResources", params, region)
    return {"updated": True, "requestId": payload.get("RequestId")}


def list_records(
    access_key_id: str,
    access_key_secret: str,
    region: str | None,
    site_id: str,
    page_number: int,
    page_size: int,
    record_name: str | None = None,
    record_match_type: str | None = None,
    rtype: str | None = None,
    proxied: str | bool | None = None,
) -> Dict[str, Any]:
    proxied_value = None
    if isinstance(proxied, bool):
        proxied_value = "true" if proxied else "false"
    elif isinstance(proxied, str) and proxied.strip():
        proxied_value = proxied.strip()
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "ListRecords",
        {
            "SiteId": site_id,
            "RecordName": str(record_name or "").strip() or None,
            "RecordMatchType": str(record_match_type or "").strip() or None,
            "Type": str(rtype or "").strip() or None,
            "Proxied": proxied_value,
            "PageNumber": max(1, int(page_number)),
            "PageSize": max(1, min(500, int(page_size))),
        },
        region,
    )
    items = []
    raw = payload.get("Records")
    if isinstance(raw, list):
        for r in raw:
            if not isinstance(r, dict):
                continue
            record_id = r.get("RecordId")
            record_name_val = str(r.get("RecordName") or "").strip()
            if record_id in (None, "") or not record_name_val:
                continue
            items.append(
                {
                    "recordId": str(record_id),
                    "recordName": record_name_val,
                    "type": str(r.get("RecordType") or r.get("Type") or "").strip(),
                    "ttl": int(r["Ttl"]) if isinstance(r.get("Ttl"), int) else None,
                    "proxied": bool(r.get("Proxied")) if isinstance(r.get("Proxied"), bool) else str(r.get("Proxied") or "").strip().lower() == "true",
                    "comment": r.get("Comment"),
                    "createTime": r.get("CreateTime"),
                    "updateTime": r.get("UpdateTime"),
                    "recordCname": r.get("RecordCname"),
                    "sourceType": r.get("RecordSourceType"),
                    "bizName": r.get("BizName"),
                    "hostPolicy": r.get("HostPolicy"),
                    "data": r.get("Data") if isinstance(r.get("Data"), dict) else None,
                    "authConf": r.get("AuthConf") if isinstance(r.get("AuthConf"), dict) else None,
                    "siteId": str(r.get("SiteId")) if r.get("SiteId") is not None else None,
                    "siteName": r.get("SiteName"),
                }
            )
    return {
        "records": items,
        "total": int(payload.get("TotalCount") or len(items)),
        "pageNumber": int(payload.get("PageNumber") or page_number),
        "pageSize": int(payload.get("PageSize") or page_size),
        "requestId": payload.get("RequestId"),
    }


def get_record(access_key_id: str, access_key_secret: str, region: str | None, record_id: str) -> Dict[str, Any]:
    payload = request_esa(access_key_id, access_key_secret, "GetRecord", {"RecordId": record_id}, region)
    model = payload.get("RecordModel") if isinstance(payload.get("RecordModel"), dict) else payload
    if not isinstance(model, dict):
        raise AliyunEsaError("ESA 返回记录信息不完整", "INVALID_RECORD", 502)
    rec_id = str(model.get("RecordId") or "").strip()
    rec_name = str(model.get("RecordName") or "").strip()
    if not rec_id or not rec_name:
        raise AliyunEsaError("ESA 返回记录信息不完整", "INVALID_RECORD", 502)
    return {
        "record": {
            "recordId": rec_id,
            "recordName": rec_name,
            "type": str(model.get("RecordType") or model.get("Type") or "").strip(),
            "ttl": int(model["Ttl"]) if isinstance(model.get("Ttl"), int) else None,
            "proxied": bool(model.get("Proxied")) if isinstance(model.get("Proxied"), bool) else str(model.get("Proxied") or "").strip().lower() == "true",
            "comment": model.get("Comment"),
            "createTime": model.get("CreateTime"),
            "updateTime": model.get("UpdateTime"),
            "recordCname": model.get("RecordCname"),
            "sourceType": model.get("RecordSourceType"),
            "bizName": model.get("BizName"),
            "hostPolicy": model.get("HostPolicy"),
            "data": model.get("Data") if isinstance(model.get("Data"), dict) else None,
            "authConf": model.get("AuthConf") if isinstance(model.get("AuthConf"), dict) else None,
            "siteId": str(model.get("SiteId")) if model.get("SiteId") is not None else None,
            "siteName": model.get("SiteName"),
        },
        "requestId": payload.get("RequestId"),
    }


def create_record(access_key_id: str, access_key_secret: str, region: str | None, payload_in: Dict[str, Any]) -> Dict[str, Any]:
    data = payload_in.get("data")
    if not isinstance(data, dict):
        raise AliyunEsaError("缺少参数: data(object)", "INVALID_PARAMS", 400)
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "CreateRecord",
        {
            "SiteId": payload_in.get("siteId"),
            "RecordName": payload_in.get("recordName"),
            "Type": payload_in.get("type"),
            "Proxied": "true" if payload_in.get("proxied") is True else ("false" if payload_in.get("proxied") is False else None),
            "SourceType": payload_in.get("sourceType"),
            "BizName": payload_in.get("bizName"),
            "Ttl": payload_in.get("ttl"),
            "Comment": payload_in.get("comment"),
            "HostPolicy": payload_in.get("hostPolicy"),
            "Data": json.dumps(data, ensure_ascii=False),
            "AuthConf": json.dumps(payload_in.get("authConf"), ensure_ascii=False) if isinstance(payload_in.get("authConf"), dict) else None,
        },
        region,
    )
    return {"recordId": str(payload.get("RecordId") or ""), "requestId": payload.get("RequestId")}


def update_record(access_key_id: str, access_key_secret: str, region: str | None, payload_in: Dict[str, Any]) -> Dict[str, Any]:
    data = payload_in.get("data")
    if not isinstance(data, dict):
        raise AliyunEsaError("缺少参数: data(object)", "INVALID_PARAMS", 400)
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "UpdateRecord",
        {
            "RecordId": payload_in.get("recordId"),
            "Proxied": "true" if payload_in.get("proxied") is True else ("false" if payload_in.get("proxied") is False else None),
            "SourceType": payload_in.get("sourceType"),
            "BizName": payload_in.get("bizName"),
            "Ttl": payload_in.get("ttl"),
            "Comment": payload_in.get("comment"),
            "HostPolicy": payload_in.get("hostPolicy"),
            "Data": json.dumps(data, ensure_ascii=False),
            "AuthConf": json.dumps(payload_in.get("authConf"), ensure_ascii=False) if isinstance(payload_in.get("authConf"), dict) else None,
        },
        region,
    )
    return {"updated": True, "requestId": payload.get("RequestId")}


def delete_record(access_key_id: str, access_key_secret: str, region: str | None, record_id: str) -> Dict[str, Any]:
    payload = request_esa(access_key_id, access_key_secret, "DeleteRecord", {"RecordId": record_id}, region)
    return {"deleted": True, "requestId": payload.get("RequestId")}


def list_certificates_by_record(
    access_key_id: str,
    access_key_secret: str,
    region: str | None,
    site_id: str,
    record_names: List[str],
    valid_only: bool,
    detail: bool,
) -> Dict[str, Any]:
    normalized = [str(x).strip() for x in record_names if str(x).strip()]
    if not normalized:
        raise AliyunEsaError("recordNames 为空", "INVALID_PARAMS", 400)
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "ListCertificatesByRecord",
        {
            "SiteId": site_id,
            "RecordName": ",".join(dict.fromkeys(normalized)),
            "ValidOnly": "true" if valid_only else None,
            "Detail": "true" if detail else None,
        },
        region,
    )
    results = []
    raw = payload.get("Result")
    if isinstance(raw, list):
        for r in raw:
            if not isinstance(r, dict):
                continue
            rn = str(r.get("RecordName") or "").strip()
            if not rn:
                continue
            certs = []
            raw_certs = r.get("Certificates")
            if isinstance(raw_certs, list):
                for c in raw_certs:
                    if not isinstance(c, dict):
                        continue
                    cid = str(c.get("Id") or "").strip()
                    if not cid:
                        continue
                    certs.append(
                        {
                            "id": cid,
                            "casId": str(c.get("CasId")) if c.get("CasId") is not None else None,
                            "name": c.get("Name"),
                            "region": c.get("Region"),
                            "status": c.get("Status"),
                            "type": c.get("Type"),
                            "commonName": c.get("CommonName"),
                            "notBefore": c.get("NotBefore"),
                            "notAfter": c.get("NotAfter"),
                            "issuer": c.get("Issuer"),
                            "issuerCN": c.get("IssuerCN"),
                            "san": c.get("SAN"),
                            "sigAlg": c.get("SigAlg"),
                            "pubAlg": c.get("PubAlg"),
                            "createTime": c.get("CreateTime"),
                            "updateTime": c.get("UpdateTime"),
                            "serialNumber": c.get("SerialNumber"),
                            "fingerprintSha256": c.get("FingerprintSha256"),
                        }
                    )
            results.append(
                {
                    "recordName": rn,
                    "count": int(r["Count"]) if isinstance(r.get("Count"), int) else int(r["Count"]) if isinstance(r.get("Count"), str) and r["Count"].isdigit() else None,
                    "applyingCount": int(r["ApplyingCount"]) if isinstance(r.get("ApplyingCount"), int) else int(r["ApplyingCount"]) if isinstance(r.get("ApplyingCount"), str) and r["ApplyingCount"].isdigit() else None,
                    "status": r.get("Status"),
                    "certificates": certs if certs else None,
                }
            )
    return {
        "records": results,
        "total": int(payload.get("TotalCount") or len(results)),
        "siteId": str(payload.get("SiteId") or site_id),
        "siteName": payload.get("SiteName"),
        "requestId": payload.get("RequestId"),
    }


def apply_certificate(access_key_id: str, access_key_secret: str, region: str | None, site_id: str, domains: List[str], cert_type: str) -> Dict[str, Any]:
    normalized = [str(x).strip() for x in domains if str(x).strip()]
    if not normalized:
        return {"results": []}
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "ApplyCertificate",
        {
            "SiteId": site_id,
            "Domains": ",".join(dict.fromkeys(normalized)),
            "Type": cert_type or "lets_encrypt",
        },
        region,
    )
    out = []
    raw = payload.get("Result")
    if isinstance(raw, list):
        for r in raw:
            if not isinstance(r, dict):
                continue
            dm = str(r.get("Domain") or "").strip()
            if not dm:
                continue
            out.append({"domain": dm, "status": r.get("Status"), "certificateId": str(r.get("Id")) if r.get("Id") is not None else None})
    return {"results": out, "requestId": payload.get("RequestId")}


def get_certificate(access_key_id: str, access_key_secret: str, region: str | None, site_id: str, certificate_id: str) -> Dict[str, Any]:
    payload = request_esa(
        access_key_id,
        access_key_secret,
        "GetCertificate",
        {"SiteId": site_id, "Id": certificate_id},
        region,
    )
    c = payload.get("Result") if isinstance(payload.get("Result"), dict) else {}
    cert = {
        "id": str(c.get("Id") or certificate_id or "").strip(),
        "casId": str(c.get("CasId")) if c.get("CasId") is not None else None,
        "name": c.get("Name"),
        "region": c.get("Region"),
        "status": c.get("Status"),
        "type": c.get("Type"),
        "commonName": c.get("CommonName"),
        "notBefore": c.get("NotBefore"),
        "notAfter": c.get("NotAfter"),
        "issuer": c.get("Issuer"),
        "issuerCN": c.get("IssuerCN"),
        "san": c.get("SAN"),
        "sigAlg": c.get("SigAlg"),
        "pubAlg": c.get("PubAlg"),
        "createTime": c.get("CreateTime"),
        "updateTime": c.get("UpdateTime"),
        "serialNumber": c.get("SerialNumber"),
        "fingerprintSha256": c.get("FingerprintSha256"),
        "applyCode": c.get("ApplyCode") if isinstance(c.get("ApplyCode"), int) else None,
        "applyMessage": c.get("ApplyMessage"),
        "dcv": c.get("DCV") if isinstance(c.get("DCV"), list) else None,
    }
    return {"certificate": cert, "requestId": payload.get("RequestId")}


def check_cname_status(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    pairs = []
    for r in records or []:
        if not isinstance(r, dict):
            continue
        rn = str(r.get("recordName") or "").strip().rstrip(".").lower()
        rc = str(r.get("recordCname") or "").strip().rstrip(".").lower()
        if not rn or not rc:
            continue
        pairs.append((rn, rc))

    if not pairs:
        raise AliyunEsaError("records 为空或缺少 recordName/recordCname", "INVALID_PARAMS", 400)

    out = []
    for record_name, record_cname in pairs[:100]:
        status = "unknown"
        try:
            ips_name = {x[4][0] for x in socket.getaddrinfo(record_name, None, proto=socket.IPPROTO_TCP)}
        except Exception:
            ips_name = set()
        try:
            ips_cname = {x[4][0] for x in socket.getaddrinfo(record_cname, None, proto=socket.IPPROTO_TCP)}
        except Exception:
            ips_cname = set()

        if ips_name and ips_cname and ips_name.intersection(ips_cname):
            status = "configured"
        elif not ips_name:
            status = "unconfigured"
        else:
            status = "unconfigured"
        out.append({"recordName": record_name, "status": status})
    return {"results": out}
