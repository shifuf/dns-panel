from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List


class TencentEdgeOneApiError(Exception):
    def __init__(self, message: str, status: int = 400, errors: list | None = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.errors = errors or []


class TencentEdgeOneApi:
    HOST = "teo.tencentcloudapi.com"
    SERVICE = "teo"
    DEFAULT_VERSION = "2022-09-01"

    def __init__(
        self,
        secret_id: str,
        secret_key: str,
        plan_id: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        self._secret_id = str(secret_id or "").strip()
        self._secret_key = str(secret_key or "").strip()
        self._plan_id = str(plan_id or "").strip()
        self._host = str(endpoint or self.HOST).strip() or self.HOST
        if not self._secret_id or not self._secret_key:
            raise TencentEdgeOneApiError("缺少腾讯云 SecretId / SecretKey")

    @staticmethod
    def _sha256_hex(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _hmac_sha256(key: bytes, data: str) -> bytes:
        return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()

    @staticmethod
    def normalize_zone_name(zone_name: str) -> str:
        value = str(zone_name or "").strip().lower().rstrip(".")
        if value.startswith("*."):
            value = value[2:]
        return value

    @staticmethod
    def normalize_domain_name(domain_name: str) -> str:
        return TencentEdgeOneApi.normalize_zone_name(domain_name)

    def _tc3_request(self, action: str, payload: Dict[str, Any], version: str | None = None) -> Dict[str, Any]:
        payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        timestamp = int(time.time())
        date = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
        content_type = "application/json; charset=utf-8"
        hashed_payload = self._sha256_hex(payload_json)
        canonical = (
            "POST\n/\n\n"
            f"content-type:{content_type}\n"
            f"host:{self._host}\n\n"
            "content-type;host\n"
            f"{hashed_payload}"
        )

        credential_scope = f"{date}/{self.SERVICE}/tc3_request"
        string_to_sign = (
            "TC3-HMAC-SHA256\n"
            f"{timestamp}\n"
            f"{credential_scope}\n"
            f"{self._sha256_hex(canonical)}"
        )

        secret_date = self._hmac_sha256(f"TC3{self._secret_key}".encode("utf-8"), date)
        secret_service = self._hmac_sha256(secret_date, self.SERVICE)
        secret_signing = self._hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (
            "TC3-HMAC-SHA256 "
            f"Credential={self._secret_id}/{credential_scope}, "
            "SignedHeaders=content-type;host, "
            f"Signature={signature}"
        )

        headers = {
            "Host": self._host,
            "Content-Type": content_type,
            "Authorization": authorization,
            "X-TC-Action": action,
            "X-TC-Version": version or self.DEFAULT_VERSION,
            "X-TC-Timestamp": str(timestamp),
            "User-Agent": "dns-panel-python-v2/1.0",
        }

        req = urllib.request.Request(
            f"https://{self._host}/",
            method="POST",
            data=payload_json.encode("utf-8"),
            headers=headers,
        )

        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                raw = resp.read().decode("utf-8")
                payload_out = json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw_body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
            try:
                err_data = json.loads(raw_body) if raw_body else {}
            except Exception:
                err_data = {}
            err_resp = err_data.get("Response", {}) if isinstance(err_data, dict) else {}
            err_obj = err_resp.get("Error", {}) if isinstance(err_resp, dict) else {}
            code = str(err_obj.get("Code") or "").strip() if isinstance(err_obj, dict) else ""
            msg = str((err_obj.get("Message") if isinstance(err_obj, dict) else None) or exc.reason or "EdgeOne API 请求失败")
            if code and code not in msg:
                msg = f"{code}: {msg}"
            raise TencentEdgeOneApiError(msg, int(exc.code or 400), errors=[err_obj] if isinstance(err_obj, dict) else None)
        except Exception as exc:
            raise TencentEdgeOneApiError(f"EdgeOne 网络请求失败: {exc}", 503)

        response = payload_out.get("Response", {}) if isinstance(payload_out, dict) else {}
        if not isinstance(response, dict):
            raise TencentEdgeOneApiError("EdgeOne 返回格式错误", 502)

        err = response.get("Error")
        if isinstance(err, dict) and err.get("Code"):
            code = str(err.get("Code") or "").strip()
            msg = str(err.get("Message") or code or "EdgeOne API 错误")
            if code and code not in msg:
                msg = f"{code}: {msg}"
            raise TencentEdgeOneApiError(msg, 400, errors=[err])

        return response

    def list_zones(self, offset: int = 0, limit: int = 100) -> Dict[str, Any]:
        payload = {"Offset": max(0, int(offset)), "Limit": max(1, min(int(limit), 100))}
        resp = self._tc3_request("DescribeZones", payload)
        raw_zones = resp.get("Zones") or resp.get("ZoneSet") or []
        zones = [self._normalize_zone(item) for item in raw_zones if isinstance(item, dict)]
        return {
            "zones": zones,
            "totalCount": int(resp.get("TotalCount") or len(zones)),
            "requestId": resp.get("RequestId"),
        }

    def find_zone_by_name(self, zone_name: str) -> Dict[str, Any] | None:
        target = self.normalize_zone_name(zone_name)
        if not target:
            return None
        offset = 0
        limit = 100
        for _ in range(20):
            data = self.list_zones(offset=offset, limit=limit)
            zones = data.get("zones") or []
            for item in zones:
                if self.normalize_zone_name(item.get("zoneName")) == target:
                    return item
            if len(zones) < limit:
                break
            offset += limit
        return None

    def create_zone(
        self,
        zone_name: str,
        plan_id: str | None = None,
        area: str = "global",
        zone_type: str = "partial",
    ) -> Dict[str, Any]:
        name = self.normalize_zone_name(zone_name)
        if not name:
            raise TencentEdgeOneApiError("缺少域名", 400)
        payload: Dict[str, Any] = {
            "ZoneName": name,
            "Type": str(zone_type or "partial"),
            "Area": str(area or "global"),
        }
        final_plan_id = str(plan_id or self._plan_id or "").strip()
        if final_plan_id:
            payload["PlanId"] = final_plan_id
        resp = self._tc3_request("CreateZone", payload)
        return {
            "siteId": str(resp.get("ZoneId") or ""),
            "zoneId": str(resp.get("ZoneId") or ""),
            "zoneName": name,
            "verification": self._normalize_verification(resp),
            "requestId": resp.get("RequestId"),
            "area": payload["Area"],
            "type": payload["Type"],
            "planId": final_plan_id or None,
        }

    def identify_zone(self, zone_name: str) -> Dict[str, Any]:
        name = self.normalize_zone_name(zone_name)
        if not name:
            raise TencentEdgeOneApiError("缺少域名", 400)
        resp = self._tc3_request("IdentifyZone", {"ZoneName": name})
        zone = self.find_zone_by_name(name)
        return {
            "zoneName": name,
            "zone": zone,
            "verification": self._normalize_verification(resp),
            "requestId": resp.get("RequestId"),
        }

    def describe_zone(self, zone_name: str, zone_id: str | None = None) -> Dict[str, Any]:
        matched = None
        if zone_id:
            offset = 0
            limit = 100
            for _ in range(20):
                data = self.list_zones(offset=offset, limit=limit)
                zones = data.get("zones") or []
                for item in zones:
                    if str(item.get("siteId") or "") == str(zone_id or ""):
                        matched = item
                        break
                if matched or len(zones) < limit:
                    break
                offset += limit
        if matched is None:
            matched = self.find_zone_by_name(zone_name)
        if matched is None:
            raise TencentEdgeOneApiError("未找到 EdgeOne 站点", 404)
        return matched

    def list_acceleration_domains(self, zone_id: str, domain_name: str | None = None) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        if not zid:
            raise TencentEdgeOneApiError("缺少站点 ID", 400)
        payload: Dict[str, Any] = {"ZoneId": zid}
        if domain_name:
            payload["Filters"] = [{
                "Name": "domain-name",
                "Values": [self.normalize_domain_name(domain_name)],
            }]
        resp = self._tc3_request("DescribeAccelerationDomains", payload)
        raw_items = resp.get("AccelerationDomains") or resp.get("AccelerationDomainInfos") or []
        items = [self._normalize_acceleration_domain(item) for item in raw_items if isinstance(item, dict)]
        return {
            "items": items,
            "requestId": resp.get("RequestId"),
        }

    def get_acceleration_domain(self, zone_id: str, domain_name: str) -> Dict[str, Any] | None:
        target = self.normalize_domain_name(domain_name)
        if not target:
            return None
        items = self.list_acceleration_domains(zone_id, target).get("items") or []
        for item in items:
            if self.normalize_domain_name(item.get("domainName")) == target:
                return item
        return None

    def create_acceleration_domain(self, zone_id: str, domain_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        target_domain = self.normalize_domain_name(domain_name)
        if not zid or not target_domain:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        payload: Dict[str, Any] = {
            "ZoneId": zid,
            "DomainName": target_domain,
            "OriginInfo": self._build_origin_info(config),
        }
        ipv6_status = self._normalize_ipv6_status(config.get("ipv6Status"))
        if ipv6_status:
            payload["Ipv6Status"] = ipv6_status
        resp = self._request_acceleration_domain_with_port_fallback("CreateAccelerationDomain", payload)
        verification = self._normalize_verification(resp)
        current = self.get_acceleration_domain(zid, target_domain) or {
            "domainName": target_domain,
            "raw": {},
        }
        current["verifyRecordName"] = str(verification.get("recordName") or current.get("verifyRecordName") or "")
        current["verifyRecordType"] = str(verification.get("recordType") or current.get("verifyRecordType") or "TXT")
        current["verifyRecordValue"] = str(verification.get("recordValue") or current.get("verifyRecordValue") or "")
        return current

    def modify_acceleration_domain(self, zone_id: str, domain_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        target_domain = self.normalize_domain_name(domain_name)
        if not zid or not target_domain:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        payload: Dict[str, Any] = {
            "ZoneId": zid,
            "DomainName": target_domain,
            "OriginInfo": self._build_origin_info(config),
        }
        ipv6_status = self._normalize_ipv6_status(config.get("ipv6Status"))
        if ipv6_status:
            payload["Ipv6Status"] = ipv6_status
        self._request_acceleration_domain_with_port_fallback("ModifyAccelerationDomain", payload)
        return self.get_acceleration_domain(zid, target_domain) or {
            "domainName": target_domain,
            "raw": {},
        }

    def upsert_acceleration_domain(self, zone_id: str, domain_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.get_acceleration_domain(zone_id, domain_name)
        if existing:
            return self.modify_acceleration_domain(zone_id, domain_name, config)
        return self.create_acceleration_domain(zone_id, domain_name, config)

    def modify_acceleration_domain_statuses(self, zone_id: str, domain_names: List[str], enabled: bool) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        normalized = [self.normalize_domain_name(item) for item in domain_names if self.normalize_domain_name(item)]
        if not zid or not normalized:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        self._tc3_request(
            "ModifyAccelerationDomainStatuses",
            {
                "ZoneId": zid,
                "DomainNames": normalized,
                "Status": "online" if enabled else "offline",
            },
        )
        return {"zoneId": zid, "domainNames": normalized, "enabled": bool(enabled)}

    def delete_acceleration_domains(self, zone_id: str, domain_names: List[str]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        normalized = [self.normalize_domain_name(item) for item in domain_names if self.normalize_domain_name(item)]
        if not zid or not normalized:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        resp = self._tc3_request(
            "DeleteAccelerationDomains",
            {
                "ZoneId": zid,
                "DomainNames": normalized,
            },
        )
        return {"zoneId": zid, "domainNames": normalized, "requestId": resp.get("RequestId")}

    def modify_zone_status(self, zone_id: str, enabled: bool) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        if not zid:
            raise TencentEdgeOneApiError("缺少站点 ID", 400)
        self._tc3_request("ModifyZoneStatus", {"ZoneId": zid, "Paused": False if enabled else True})
        return {"siteId": zid, "enabled": bool(enabled)}

    def delete_zone(self, zone_id: str) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        if not zid:
            raise TencentEdgeOneApiError("缺少站点 ID", 400)
        resp = self._tc3_request("DeleteZone", {"ZoneId": zid})
        return {"siteId": zid, "requestId": resp.get("RequestId")}

    def _request_acceleration_domain_with_port_fallback(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return self._tc3_request(action, payload)
        except TencentEdgeOneApiError as exc:
            message = str(exc)
            if "OriginInfo.HttpOriginPort" not in message and "OriginInfo.HttpsOriginPort" not in message:
                raise
            retry_payload = json.loads(json.dumps(payload, ensure_ascii=False))
            origin_info = retry_payload.get("OriginInfo")
            if isinstance(origin_info, dict):
                origin_info.pop("HttpOriginPort", None)
                origin_info.pop("HttpsOriginPort", None)
            return self._tc3_request(action, retry_payload)

    @staticmethod
    def _safe_port(value: Any, default: int) -> int:
        try:
            port = int(value)
            return port if port > 0 else default
        except Exception:
            return default

    @staticmethod
    def _normalize_verification(raw: Dict[str, Any]) -> Dict[str, Any]:
        verification = raw.get("OwnershipVerification") or raw.get("Identification")
        if isinstance(verification, list) and verification:
            first = verification[0] if isinstance(verification[0], dict) else {}
            return {
                "recordType": str(first.get("RecordType") or first.get("Type") or "TXT"),
                "recordName": str(first.get("RecordName") or first.get("Name") or ""),
                "recordValue": str(first.get("RecordValue") or first.get("Value") or ""),
                "raw": verification,
            }
        if isinstance(verification, dict):
            candidates: List[Dict[str, Any]] = [verification]
            dns_verification = verification.get("DnsVerification") or verification.get("DNSVerification")
            if isinstance(dns_verification, dict):
                candidates.insert(0, dns_verification)
            elif isinstance(dns_verification, list):
                candidates = [item for item in dns_verification if isinstance(item, dict)] + candidates
            for item in candidates:
                record_name = str(item.get("RecordName") or item.get("Name") or item.get("Host") or "")
                record_value = str(item.get("RecordValue") or item.get("Value") or item.get("Content") or "")
                if not record_name and not record_value:
                    continue
                return {
                    "recordType": str(item.get("RecordType") or item.get("Type") or "TXT"),
                    "recordName": record_name,
                    "recordValue": record_value,
                    "raw": verification,
                }
        return {"recordType": "TXT", "recordName": "", "recordValue": ""}

    @staticmethod
    def _normalize_zone(raw: Dict[str, Any]) -> Dict[str, Any]:
        status = str(raw.get("Status") or raw.get("ZoneStatus") or raw.get("State") or "unknown")
        cname_status = str(
            raw.get("CnameStatus")
            or raw.get("OwnershipVerificationStatus")
            or raw.get("VerificationStatus")
            or raw.get("AscriptionStatus")
            or ""
        ).strip()
        paused_raw = raw.get("Paused")
        if isinstance(paused_raw, str):
            paused = paused_raw.strip().lower() in {"1", "true", "yes", "on"}
        else:
            paused = bool(paused_raw)
        if paused_raw is None:
            paused = status.strip().lower() in {"offline", "paused", "disabled", "suspended"}
        verify_status_lower = (cname_status or status or "").strip().lower()
        return {
            "siteId": str(raw.get("ZoneId") or raw.get("Id") or ""),
            "zoneName": str(raw.get("ZoneName") or raw.get("Name") or ""),
            "status": status or "unknown",
            "verifyStatus": cname_status or status or "unknown",
            "verified": status.lower() in {"active", "online", "enabled", "success", "verified"}
            or verify_status_lower in {"finished", "active", "verified", "success", "completed"},
            "paused": paused,
            "type": str(raw.get("Type") or raw.get("AccessType") or ""),
            "area": str(raw.get("Area") or raw.get("Region") or ""),
            "planId": str(raw.get("PlanId") or ""),
            "createdAt": raw.get("CreatedOn") or raw.get("CreateTime"),
            "updatedAt": raw.get("ModifiedOn") or raw.get("UpdateTime"),
            "raw": raw,
        }

    @staticmethod
    def _normalize_ipv6_status(value: Any) -> str:
        text = str(value or "").strip().lower()
        mapping = {
            "on": "follow",
            "enable": "follow",
            "enabled": "follow",
            "follow": "follow",
            "off": "close",
            "disable": "close",
            "disabled": "close",
            "close": "close",
        }
        return mapping.get(text, "")

    @staticmethod
    def _build_origin_info(config: Dict[str, Any]) -> Dict[str, Any]:
        origin_type = str(config.get("originType") or "IP_DOMAIN").strip().upper() or "IP_DOMAIN"
        origin_value = str(config.get("originValue") or "").strip()
        if not origin_value:
            raise TencentEdgeOneApiError("缺少源站地址", 400)
        info: Dict[str, Any] = {
            "OriginType": origin_type,
            "Origin": origin_value,
        }
        backup_origin = str(config.get("backupOriginValue") or "").strip()
        if backup_origin:
            info["BackupOrigin"] = backup_origin
        host_header = str(config.get("hostHeader") or "").strip()
        if host_header:
            info["HostHeader"] = host_header
        try:
            http_port = int(config.get("httpOriginPort") or config.get("originPort") or 80)
        except Exception:
            http_port = 80
        try:
            https_port = int(config.get("httpsOriginPort") or config.get("originPort") or 443)
        except Exception:
            https_port = 443
        info["HttpOriginPort"] = http_port
        info["HttpsOriginPort"] = https_port
        return info

    @staticmethod
    def _normalize_acceleration_domain(raw: Dict[str, Any]) -> Dict[str, Any]:
        origin_detail = raw.get("OriginDetail") if isinstance(raw.get("OriginDetail"), dict) else {}
        domain_status = str(raw.get("DomainStatus") or raw.get("Status") or "unknown")
        identification_status = str(raw.get("IdentificationStatus") or raw.get("VerifyStatus") or "")
        verify_lower = identification_status.strip().lower()
        status_lower = domain_status.strip().lower()
        return {
            "domainName": str(raw.get("DomainName") or raw.get("Name") or ""),
            "domainStatus": domain_status or "unknown",
            "siteId": str(raw.get("ZoneId") or ""),
            "identificationStatus": identification_status or domain_status or "unknown",
            "verified": verify_lower in {"finished", "verified", "success", "completed"}
            or status_lower in {"online", "active"},
            "paused": status_lower in {"offline", "paused", "disabled"},
            "cnameTarget": str(raw.get("Cname") or raw.get("CNAME") or ""),
            "cnameStatus": str(raw.get("CnameStatus") or identification_status or domain_status or "unknown"),
            "originType": str(origin_detail.get("OriginType") or ""),
            "originValue": str(origin_detail.get("Origin") or ""),
            "backupOriginValue": str(origin_detail.get("BackupOrigin") or ""),
            "hostHeader": str(origin_detail.get("HostHeader") or ""),
            "originProtocol": str(origin_detail.get("OriginProtocol") or raw.get("OriginProtocol") or "FOLLOW"),
            "httpOriginPort": TencentEdgeOneApi._safe_port(origin_detail.get("HttpOriginPort") or raw.get("HttpOriginPort"), 80),
            "httpsOriginPort": TencentEdgeOneApi._safe_port(origin_detail.get("HttpsOriginPort") or raw.get("HttpsOriginPort"), 443),
            "ipv6Status": str(raw.get("Ipv6Status") or raw.get("IPv6Status") or "follow"),
            "verifyRecordName": "",
            "verifyRecordType": "",
            "verifyRecordValue": "",
            "createdAt": raw.get("CreatedOn") or raw.get("CreateTime"),
            "updatedAt": raw.get("ModifiedOn") or raw.get("UpdateTime"),
            "raw": raw,
        }
