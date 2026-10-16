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

    def __init__(self, secret_id: str, secret_key: str, plan_id: str | None = None, endpoint: str | None = None) -> None:
        self._secret_id = str(secret_id or "").strip()
        self._secret_key = str(secret_key or "").strip()
        self._plan_id = str(plan_id or "").strip()
        resolved_host = str(endpoint or self.HOST).strip() or self.HOST
        # SSRF guard: requests carry a TC3 signature, so a user-supplied
        # endpoint could probe internal hosts with signed requests. Restrict
        # to Tencent Cloud API hostnames.
        host_lower = resolved_host.lower().split("/")[0].split(":")[0]
        if not (host_lower == self.HOST or host_lower.endswith(".tencentcloudapi.com") or host_lower.endswith(".tencentcloud.com")):
            raise TencentEdgeOneApiError("自定义 endpoint 仅允许腾讯云 API 域名（*.tencentcloudapi.com）", 400)
        self._host = resolved_host
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

    # Transient failures worth retrying with backoff (matches the declared
    # capabilities: retryableErrors/maxRetries). Rate limiting is the common
    # one — full-zone traversals can easily hit TEO's 20 req/s ceiling.
    _RETRYABLE_CODES = (
        "RequestLimitExceeded",
        "InternalError",
        "ServiceUnavailable",
        "ResourceUnavailable",
        "FailedOperation",
    )
    _MAX_RETRIES = 2

    def _tc3_request_once(self, action: str, payload: Dict[str, Any], version: str | None = None) -> Dict[str, Any]:
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
            f"TC3-HMAC-SHA256 Credential={self._secret_id}/{credential_scope}, "
            f"SignedHeaders=content-type;host, Signature={signature}"
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
            error = TencentEdgeOneApiError(msg, 400, errors=[err])
            error.code = code  # used by the retry classifier below
            raise error
        return response

    def _tc3_request(self, action: str, payload: Dict[str, Any], version: str | None = None) -> Dict[str, Any]:
        """TC3 request with bounded exponential backoff on transient errors."""
        attempt = 0
        while True:
            try:
                return self._tc3_request_once(action, payload, version)
            except TencentEdgeOneApiError as exc:
                code = str(getattr(exc, "code", "") or "")
                retryable = (
                    code in self._RETRYABLE_CODES
                    or (exc.status or 0) >= 500
                    or "RequestLimitExceeded" in str(exc)
                    or "网络请求失败" in str(exc)
                )
                if not retryable or attempt >= self._MAX_RETRIES:
                    raise
                time.sleep(0.8 * (2 ** attempt) + (attempt * 0.37))
                attempt += 1

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

    # Instance-level TTL cache for zone pages. find_zone_by_name / describe_zone
    # can walk up to 20 DescribeZones pages PER CALL; repeated calls in one
    # request chain (auto-CNAME + finalize + status) are the main source of
    # rate-limit pressure. A short TTL collapses them into one traversal.
    _ZONE_CACHE_TTL = 30.0

    def _cached_zone_page(self, offset: int, limit: int) -> Dict[str, Any]:
        cache = getattr(self, "_zone_page_cache", None)
        if cache is None:
            cache = {}
            self._zone_page_cache = cache
        key = (int(offset), int(limit))
        hit = cache.get(key)
        if hit is not None and (time.time() - hit[0]) < self._ZONE_CACHE_TTL:
            return hit[1]
        data = self.list_zones(offset=offset, limit=limit)
        cache[key] = (time.time(), data)
        return data

    def invalidate_zone_cache(self) -> None:
        self._zone_page_cache = {}

    def find_zone_by_name(self, zone_name: str) -> Dict[str, Any] | None:
        target = self.normalize_zone_name(zone_name)
        if not target:
            return None
        offset = 0
        limit = 100
        for _ in range(20):
            data = self._cached_zone_page(offset=offset, limit=limit)
            zones = data.get("zones") or []
            for item in zones:
                if self.normalize_zone_name(item.get("zoneName")) == target:
                    return item
            if len(zones) < limit:
                return None
            offset += limit
        return None

    def create_zone(self, zone_name: str, plan_id: str | None = None, area: str = "global", zone_type: str = "partial") -> Dict[str, Any]:
        name = self.normalize_zone_name(zone_name)
        if not name:
            raise TencentEdgeOneApiError("缺少域名", 400)
        payload = {"ZoneName": name, "Type": str(zone_type or "partial"), "Area": str(area or "global")}
        final_plan_id = str(plan_id or self._plan_id or "").strip()
        if final_plan_id:
            payload["PlanId"] = final_plan_id
        resp = self._tc3_request("CreateZone", payload)
        self.invalidate_zone_cache()
        data = {
            "siteId": str(resp.get("ZoneId") or ""),
            "zoneId": str(resp.get("ZoneId") or ""),
            "zoneName": name,
            "verification": self._normalize_verification(resp),
            "requestId": resp.get("RequestId"),
            "area": payload["Area"],
            "type": payload["Type"],
            "planId": final_plan_id or None,
        }
        if not data["verification"].get("recordName"):
            # A verification value without a record NAME cannot be added to DNS
            # — fetch the full identification info (old condition required BOTH
            # to be missing, so a value-only response silently skipped this).
            try:
                verification = self.create_ownership_verification(name, data["siteId"] or None)
                if isinstance(verification, dict):
                    filled = verification.get("verification") or {}
                    if filled.get("recordName"):
                        data["verification"] = filled
            except Exception:
                pass
        return data

    def create_ownership_verification(self, domain_name: str, zone_id: str | None = None) -> Dict[str, Any]:
        name = self.normalize_zone_name(domain_name)
        if not name:
            raise TencentEdgeOneApiError("缺少域名", 400)
        try:
            identified = self.describe_identifications(name, zone_id)
            verification = identified.get("verification") if isinstance(identified, dict) else {}
            if isinstance(verification, dict) and (verification.get("recordName") or verification.get("recordValue")):
                return identified
        except TencentEdgeOneApiError:
            pass

        # TEO has no CreateOwnershipVerification action; ownership records are
        # obtained via IdentifyZone (or read back through DescribeIdentifications).
        resp = self._tc3_request("IdentifyZone", {"ZoneName": name})
        zone = None
        try:
            zone = self.describe_zone(name, zone_id)
        except Exception:
            zone = self.find_zone_by_name(name)
        return {
            "zoneName": name,
            "zone": zone,
            "verification": self._normalize_verification(resp),
            "requestId": resp.get("RequestId"),
        }

    def describe_identifications(self, domain_name: str, zone_id: str | None = None) -> Dict[str, Any]:
        name = self.normalize_zone_name(domain_name)
        if not name:
            raise TencentEdgeOneApiError("缺少域名", 400)
        payload: Dict[str, Any] = {
            "Filters": [
                {"Name": "zone-name", "Values": [name]},
            ],
        }
        resp = self._tc3_request("DescribeIdentifications", payload)
        raw_items = resp.get("Identifications") if isinstance(resp.get("Identifications"), list) else []
        matched: Dict[str, Any] | None = None
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            item_zone_name = self.normalize_zone_name(item.get("ZoneName") or item.get("Domain") or "")
            item_zone_id = str(item.get("ZoneId") or item.get("Id") or "").strip()
            if zone_id and item_zone_id and item_zone_id != str(zone_id).strip():
                continue
            if item_zone_name == name:
                matched = item
                break
        # NOTE: deliberately no "take the first item" fallback — showing another
        # zone's verification TXT would send users chasing a record that can
        # never validate. Unmatched simply reports empty verification.
        raw_verification = dict(matched or {})
        raw_verification.setdefault("ZoneName", name)
        zone = None
        try:
            zone = self.describe_zone(name, zone_id)
        except Exception:
            zone = self.find_zone_by_name(name)
        return {
            "zoneName": name,
            "zone": zone,
            "status": str((matched or {}).get("Status") or "").strip() if matched else "",
            "verification": self._normalize_verification(raw_verification),
            "requestId": resp.get("RequestId"),
            "raw": matched or resp,
        }

    def describe_zone(self, zone_name: str, zone_id: str | None = None) -> Dict[str, Any]:
        matched = None
        if zone_id:
            offset = 0
            limit = 100
            for _ in range(20):
                data = self._cached_zone_page(offset=offset, limit=limit)
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

    def identify_zone(self, zone_name: str) -> Dict[str, Any]:
        return self.describe_identifications(zone_name)

    def verify_ownership(self, zone_name: str, verification_code: str, site_id: str | None = None) -> Dict[str, Any]:
        name = self.normalize_zone_name(zone_name)
        if not name:
            raise TencentEdgeOneApiError("缺少域名", 400)
        try:
            resp = self._tc3_request("VerifyOwnership", {"Domain": name})
        except TencentEdgeOneApiError as exc:
            message = str(exc)
            if "UnknownParameter" not in message and "MissingParameter" not in message:
                raise
            fallback_payload: Dict[str, Any] = {"DomainName": name}
            code = str(verification_code or "").strip()
            if code:
                fallback_payload["VerificationCode"] = code
            resp = self._tc3_request("VerifyOwnership", fallback_payload)
        site = None
        try:
            site = self.describe_zone(name, site_id)
        except Exception:
            site = None
        status = str(resp.get("Status") or resp.get("VerificationStatus") or (site or {}).get("verifyStatus") or "success")
        return {
            "zoneName": name,
            "site": site,
            "status": status,
            "passed": str(status).strip().lower() in {"success", "verified", "active", "online", "finished", "completed"},
            "requestId": resp.get("RequestId"),
            "raw": resp,
        }

    def list_acceleration_domains(self, zone_id: str, domain_name: str | None = None) -> Dict[str, Any]:
        """List ALL acceleration domains under a zone (auto-paginated).

        DescribeAccelerationDomains defaults to Limit=20; without paging the
        UI silently hid domains past the 20th (and `total` lied too).
        """
        zid = str(zone_id or "").strip()
        if not zid:
            raise TencentEdgeOneApiError("缺少站点 ID", 400)
        base_payload: Dict[str, Any] = {"ZoneId": zid}
        if domain_name:
            base_payload["Filters"] = [{"Name": "domain-name", "Values": [self.normalize_domain_name(domain_name)]}]
        items: List[Dict[str, Any]] = []
        offset = 0
        limit = 100
        total = None
        request_id = None
        for _ in range(100):  # hard stop; 100 * 100 = 10k domains
            payload = dict(base_payload, Offset=offset, Limit=limit)
            resp = self._tc3_request("DescribeAccelerationDomains", payload)
            request_id = resp.get("RequestId") or request_id
            raw_items = resp.get("AccelerationDomains") or resp.get("AccelerationDomainInfos") or []
            batch = [self._normalize_acceleration_domain(item) for item in raw_items if isinstance(item, dict)]
            items.extend(batch)
            try:
                total = int(resp.get("TotalCount") or 0) or total
            except Exception:
                pass
            if len(batch) < limit or (total is not None and len(items) >= total):
                break
            offset += limit
        return {"items": items, "requestId": request_id, "total": total if total is not None else len(items)}

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
        payload: Dict[str, Any] = {"ZoneId": zid, "DomainName": target_domain, "OriginInfo": self._build_origin_info(config)}
        self._apply_origin_transport_params(payload, config)
        resp = self._request_acceleration_domain_with_port_fallback("CreateAccelerationDomain", payload)
        verification = self._normalize_verification(resp)
        current = self.get_acceleration_domain(zid, target_domain) or {"domainName": target_domain, "raw": {}}
        current["verifyRecordName"] = str(verification.get("recordName") or current.get("verifyRecordName") or "")
        current["verifyRecordType"] = str(verification.get("recordType") or current.get("verifyRecordType") or "TXT")
        current["verifyRecordValue"] = str(verification.get("recordValue") or current.get("verifyRecordValue") or "")
        if verification.get("verificationCode"):
            current["verificationCode"] = str(verification.get("verificationCode") or "")
        # Surface params the API rejected and the compatibility retry dropped,
        # so callers/UI can warn instead of silently losing user config.
        if isinstance(resp, dict) and resp.get("_strippedParams"):
            current["strippedParams"] = list(resp["_strippedParams"])
        return current

    def modify_acceleration_domain(self, zone_id: str, domain_name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        target_domain = self.normalize_domain_name(domain_name)
        if not zid or not target_domain:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        payload: Dict[str, Any] = {"ZoneId": zid, "DomainName": target_domain, "OriginInfo": self._build_origin_info(config)}
        self._apply_origin_transport_params(payload, config)
        resp = self._request_acceleration_domain_with_port_fallback("ModifyAccelerationDomain", payload)
        result = self.get_acceleration_domain(zid, target_domain) or {"domainName": target_domain, "raw": {}}
        if isinstance(resp, dict) and resp.get("_strippedParams"):
            result["strippedParams"] = list(resp["_strippedParams"])
        return result

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
            {"ZoneId": zid, "DomainNames": normalized, "Status": "online" if enabled else "offline"},
        )
        return {"zoneId": zid, "domainNames": normalized, "enabled": bool(enabled)}

    def delete_acceleration_domains(self, zone_id: str, domain_names: List[str]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        normalized = [self.normalize_domain_name(item) for item in domain_names if self.normalize_domain_name(item)]
        if not zid or not normalized:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        resp = self._tc3_request("DeleteAccelerationDomains", {"ZoneId": zid, "DomainNames": normalized})
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
        self.invalidate_zone_cache()
        return {"siteId": zid, "requestId": resp.get("RequestId")}

    def check_cname_status(self, zone_id: str, domain_names: List[str]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        normalized = [self.normalize_domain_name(item) for item in domain_names if self.normalize_domain_name(item)]
        if not zid or not normalized:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        resp = self._tc3_request("CheckCnameStatus", {"ZoneId": zid, "RecordNames": normalized})
        raw_items = resp.get("CnameStatus") if isinstance(resp.get("CnameStatus"), list) else []
        items: List[Dict[str, Any]] = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            items.append({
                "domainName": self.normalize_domain_name(raw.get("RecordName") or raw.get("DomainName") or ""),
                "recordName": str(raw.get("RecordName") or raw.get("DomainName") or "").strip(),
                "cnameTarget": str(raw.get("Cname") or raw.get("CNAME") or "").strip(),
                "status": str(raw.get("Status") or raw.get("CnameStatus") or "").strip() or "unknown",
                "message": str(raw.get("Message") or raw.get("StatusMessage") or "").strip(),
                "raw": raw,
            })
        return {"items": items, "requestId": resp.get("RequestId"), "zoneId": zid}

    def describe_domain_status(self, zone_id: str, domain_name: str) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        target_domain = self.normalize_domain_name(domain_name)
        if not zid or not target_domain:
            raise TencentEdgeOneApiError("缺少站点 ID 或加速域名", 400)
        domain = self.get_acceleration_domain(zid, target_domain)
        if not domain:
            raise TencentEdgeOneApiError("加速域名不存在", 404)
        raw_domain = domain.get("raw") if isinstance(domain.get("raw"), dict) else {}
        status = str(domain.get("domainStatus") or raw_domain.get("DomainStatus") or raw_domain.get("Status") or "").strip() or "unknown"
        message_parts: List[str] = []
        identification_status = str(domain.get("identificationStatus") or raw_domain.get("IdentificationStatus") or raw_domain.get("VerifyStatus") or "").strip()
        if identification_status and identification_status.lower() != status.lower():
            message_parts.append(f"归属验证: {identification_status}")
        cname_info: Dict[str, Any] | None = None
        cname_request_id = None
        try:
            cname_data = self.check_cname_status(zid, [target_domain])
            cname_request_id = cname_data.get("requestId")
            for item in cname_data.get("items") or []:
                if self.normalize_domain_name(item.get("domainName")) == target_domain:
                    cname_info = item
                    break
        except TencentEdgeOneApiError:
            cname_info = None
        if cname_info:
            cname_status = str(cname_info.get("status") or "").strip()
            if cname_status and cname_status.lower() != status.lower():
                message_parts.append(f"CNAME: {cname_status}")
            cname_message = str(cname_info.get("message") or "").strip()
            if cname_message:
                message_parts.append(cname_message)
        message = "；".join(part for part in message_parts if part)
        ui_state = self._compute_ui_state(
            domain_status=status,
            identification_status=identification_status,
            cname_status=(cname_info.get("status") if isinstance(cname_info, dict) else None),
            paused=bool(domain.get("paused")),
        )
        return {
            "zoneId": zid,
            "domainName": target_domain,
            "status": status,
            "uiState": ui_state,
            "message": message,
            "requestId": cname_request_id or raw_domain.get("RequestId"),
            "domain": domain,
            "cnameStatus": cname_info,
            "raw": {
                "domain": raw_domain,
                "cnameStatus": cname_info.get("raw") if isinstance(cname_info, dict) else None,
            },
        }

    def create_certificate(self, zone_id: str, domain_name: str, alternative_names: List[str] | None = None) -> Dict[str, Any]:
        """Compatibility shim: apply for EdgeOne free certs via the real API.

        Kept because older callers (QuickAddForm) reference this method name;
        it now delegates to ApplyFreeCertificate, which actually exists.
        """
        names = [domain_name] + [str(x) for x in (alternative_names or [])]
        return self.apply_free_certificate(zone_id, names)

    def modify_hosts_certificate(
        self,
        zone_id: str,
        hosts: List[str],
        cert_type: str,
        cert_id: str | None = None,
        cert_info: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        normalized_hosts = [self.normalize_domain_name(item) for item in hosts if self.normalize_domain_name(item)]
        if not zid or not normalized_hosts:
            raise TencentEdgeOneApiError("缺少站点 ID 或域名列表", 400)
        resolved_cert_id = str(cert_id or (cert_info or {}).get("CertId") or "").strip()
        if not resolved_cert_id:
            raise TencentEdgeOneApiError("缺少证书 ID", 400)
        cert_mode = str(cert_type or "").strip().lower() or "managed"
        if cert_mode not in {"managed", "sslcert", "upload", "custom"}:
            cert_mode = "managed"
        if cert_mode == "custom" and isinstance(cert_info, dict) and (
            str(cert_info.get("CertContent") or "").strip() or str(cert_info.get("PrivateKey") or "").strip()
        ):
            raise TencentEdgeOneApiError("EdgeOne 绑定不支持直接提交 PEM 内容，请先在 SSL 证书页面上传后再通过证书 ID 绑定", 400)
        payload: Dict[str, Any] = {
            "ZoneId": zid,
            "Hosts": normalized_hosts,
            "Mode": "sslcert",
            "ServerCertInfo": [{"CertId": resolved_cert_id}],
        }
        resp = self._tc3_request("ModifyHostsCertificate", payload)
        data: Dict[str, Any] = {
            "zoneId": zid,
            "hosts": normalized_hosts,
            "certId": resolved_cert_id,
            "requestId": resp.get("RequestId"),
            "raw": resp,
        }
        try:
            current = self.describe_host_certificates(zid, normalized_hosts)
            data["items"] = current.get("items") or []
            data["certificates"] = current.get("certificates") or current.get("items") or []
        except Exception:
            pass
        return data

    def apply_free_certificate(self, zone_id: str, domain_names: List[str]) -> Dict[str, Any]:
        """Request EdgeOne-managed FREE certificates for the given domains.

        Uses the real TEO API (ApplyFreeCertificate + CheckFreeCertificateVerification).
        The old ``CreateCertificate`` action does not exist in the TEO API and
        always failed with InvalidAction — callers got a confusing hard error.
        """
        zid = str(zone_id or "").strip()
        normalized = [self.normalize_domain_name(item) for item in (domain_names or []) if self.normalize_domain_name(item)]
        if not zid or not normalized:
            raise TencentEdgeOneApiError("缺少站点 ID 或域名", 400)
        resp = self._tc3_request("ApplyFreeCertificate", {"ZoneId": zid, "DomainNames": normalized})
        # Verification of DNS ownership may be required before issuance; try a
        # best-effort immediate check so single-shot callers see the state.
        check: Dict[str, Any] = {}
        try:
            check = self.check_free_certificate_verification(zid, normalized)
        except TencentEdgeOneApiError:
            check = {}
        return {
            "zoneId": zid,
            "domainNames": normalized,
            "applied": True,
            "check": check,
            "requestId": resp.get("RequestId"),
            "raw": resp,
        }

    def check_free_certificate_verification(self, zone_id: str, domain_names: List[str]) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        normalized = [self.normalize_domain_name(item) for item in (domain_names or []) if self.normalize_domain_name(item)]
        if not zid or not normalized:
            raise TencentEdgeOneApiError("缺少站点 ID 或域名", 400)
        resp = self._tc3_request("CheckFreeCertificateVerification", {"ZoneId": zid, "DomainNames": normalized})
        raw_items = resp.get("VerificationInfos") if isinstance(resp.get("VerificationInfos"), list) else []
        items = []
        for raw in raw_items:
            if not isinstance(raw, dict):
                continue
            record_name = str(raw.get("RecordName") or "").strip()
            sub = str(raw.get("Subdomain") or "").strip()
            if not record_name and sub:
                record_name = sub
            items.append({
                "domainName": self.normalize_domain_name(raw.get("DomainName") or ""),
                "recordType": str(raw.get("RecordType") or "TXT"),
                "recordName": record_name,
                "recordValue": str(raw.get("RecordValue") or "").strip(),
                "status": str(raw.get("Status") or "").strip(),
                "raw": raw,
            })
        return {"items": items, "requestId": resp.get("RequestId"), "zoneId": zid}

    def describe_host_certificates(self, zone_id: str, hosts: List[str] | None = None) -> Dict[str, Any]:
        zid = str(zone_id or "").strip()
        if not zid:
            raise TencentEdgeOneApiError("缺少站点 ID", 400)
        normalized_hosts = [self.normalize_domain_name(item) for item in (hosts or []) if self.normalize_domain_name(item)]
        # Auto-paginate: DescribeHostCertificates also defaults to a small page.
        all_raw: List[Dict[str, Any]] = []
        request_id = None
        offset = 0
        limit = 100
        total = None
        for _ in range(100):
            payload: Dict[str, Any] = {"ZoneId": zid, "Offset": offset, "Limit": limit}
            resp = self._tc3_request("DescribeHostCertificates", payload)
            request_id = resp.get("RequestId") or request_id
            raw_items = resp.get("HostCertificates") if isinstance(resp.get("HostCertificates"), list) else []
            if not raw_items and isinstance(resp.get("Certificates"), list):
                raw_items = resp.get("Certificates") or []
            if not raw_items and isinstance(resp.get("Items"), list):
                raw_items = resp.get("Items") or []
            batch = [item for item in raw_items if isinstance(item, dict)]
            all_raw.extend(batch)
            try:
                total = int(resp.get("TotalCount") or 0) or total
            except Exception:
                pass
            if len(batch) < limit or (total is not None and len(all_raw) >= total):
                break
            offset += limit
        items = [self._normalize_host_certificate(item) for item in all_raw]
        if normalized_hosts:
            wanted = set(normalized_hosts)
            items = [
                item for item in items
                if any(self.normalize_domain_name(host) in wanted for host in (item.get("hosts") or [item.get("host")]))
            ]
        return {"items": items, "certificates": items, "requestId": request_id, "zoneId": zid}

    @staticmethod
    def _safe_port(value: Any, default: int) -> int:
        try:
            port = int(value)
            return port if port > 0 else default
        except Exception:
            return default

    @staticmethod
    def _compute_ui_state(
        domain_status: Any = None,
        identification_status: Any = None,
        cname_status: Any = None,
        paused: Any = False,
    ) -> str:
        """Map API statuses to the UI state enum.

        Official DomainStatus values: online / process / offline / forbidden /
        init. `forbidden` (blocked by the platform) used to fall through to
        "deploying", hiding a state the user must act on.
        """
        ds = str(domain_status or "").strip().lower()
        idents = str(identification_status or "").strip().lower()
        cns = str(cname_status or "").strip().lower()
        if paused or ds in {"disabled", "suspended"}:
            return "paused"
        if ds == "forbidden":
            return "error"
        if ds in {"error", "failed", "fail"}:
            return "error"
        if ds in {"pending", "deploying", "process", "processing", "configuring", "init", "initializing", "pendingverify"}:
            return "deploying"
        ident_ok = idents in {"verified", "completed", "finished", "success", "active", "online"} or ds == "online"
        cname_ok = (not cns) or cns in {"success", "active", "online", "completed", "finished", "ok", "verified", "pass", "passed"}
        if ds == "online" and ident_ok and cname_ok:
            return "active"
        if not ident_ok or (cns and not cname_ok):
            return "cname_pending"
        if ds == "offline":
            # Offline without a paused request may mean disabled on the cloud
            # console — surface as paused rather than pretending it deploys.
            return "paused"
        return "deploying"

    @staticmethod
    def _normalize_verification(raw: Dict[str, Any]) -> Dict[str, Any]:
        verification = raw.get("OwnershipVerification") or raw.get("Identification")
        ascription = raw.get("Ascription")
        if isinstance(ascription, dict):
            zone_name = TencentEdgeOneApi.normalize_zone_name(raw.get("ZoneName") or raw.get("Domain") or raw.get("DomainName") or "")
            subdomain = str(ascription.get("Subdomain") or ascription.get("RecordName") or ascription.get("Name") or "").strip()
            record_name = TencentEdgeOneApi._normalize_verification_record_name(zone_name, subdomain)
            return {
                "recordType": str(ascription.get("RecordType") or ascription.get("Type") or "TXT"),
                "recordName": record_name,
                "recordValue": str(ascription.get("RecordValue") or ascription.get("Value") or "").strip(),
                "verificationCode": str(ascription.get("VerificationCode") or raw.get("VerificationCode") or "").strip(),
                "raw": raw,
            }
        if isinstance(verification, list) and verification:
            first = verification[0] if isinstance(verification[0], dict) else {}
            return {
                "recordType": str(first.get("RecordType") or first.get("Type") or "TXT"),
                "recordName": str(first.get("RecordName") or first.get("Name") or ""),
                "recordValue": str(first.get("RecordValue") or first.get("Value") or ""),
                "verificationCode": str(first.get("VerificationCode") or first.get("Code") or ""),
                "raw": verification,
            }
        if isinstance(verification, dict):
            candidates = [verification]
            dns_verification = verification.get("DnsVerification") or verification.get("DNSVerification")
            if isinstance(dns_verification, dict):
                candidates.insert(0, dns_verification)
            elif isinstance(dns_verification, list):
                candidates = [item for item in dns_verification if isinstance(item, dict)] + candidates
            zone_name = TencentEdgeOneApi.normalize_zone_name(
                raw.get("ZoneName") or raw.get("Domain") or raw.get("DomainName") or verification.get("ZoneName") or ""
            )
            for item in candidates:
                # The DnsVerification structure uses Subdomain (host part);
                # without it the record name ended up empty and automatic TXT
                # creation silently skipped.
                sub = str(item.get("Subdomain") or item.get("SubDomain") or "").strip()
                record_name = str(item.get("RecordName") or item.get("Name") or item.get("Host") or "")
                if not record_name and sub:
                    record_name = TencentEdgeOneApi._normalize_verification_record_name(zone_name, sub)
                record_value = str(item.get("RecordValue") or item.get("Value") or item.get("Content") or "")
                if not record_name and not record_value:
                    continue
                return {
                    "recordType": str(item.get("RecordType") or item.get("Type") or "TXT"),
                    "recordName": record_name,
                    "recordValue": record_value,
                    "verificationCode": str(item.get("VerificationCode") or item.get("Code") or verification.get("VerificationCode") or verification.get("Code") or ""),
                    "raw": verification,
                }
        return {"recordType": "TXT", "recordName": "", "recordValue": "", "verificationCode": ""}

    @staticmethod
    def _normalize_ipv6_status(value: Any) -> str:
        """Map UI values to the official IPv6Status enum: follow / on / off."""
        text = str(value or "").strip().lower()
        mapping = {
            "on": "on",
            "enable": "on",
            "enabled": "on",
            "follow": "follow",
            "off": "off",
            "disable": "off",
            "disabled": "off",
            "close": "off",     # legacy UI value
            "closed": "off",
        }
        return mapping.get(text, "")

    @staticmethod
    def _build_origin_info(config: Dict[str, Any]) -> Dict[str, Any]:
        """Origin server block only — OriginType/Origin/BackupOrigin/HostHeader.

        Transport settings (protocol/ports) are TOP-LEVEL parameters on
        CreateAccelerationDomain / ModifyAccelerationDomain and must not be
        nested inside OriginInfo; see _apply_origin_transport_params.
        """
        origin_type = str(config.get("originType") or "IP_DOMAIN").strip().upper() or "IP_DOMAIN"
        origin_value = str(config.get("originValue") or "").strip()
        if not origin_value:
            raise TencentEdgeOneApiError("缺少源站地址", 400)
        info: Dict[str, Any] = {"OriginType": origin_type, "Origin": origin_value}
        backup_origin = str(config.get("backupOriginValue") or "").strip()
        if backup_origin:
            info["BackupOrigin"] = backup_origin
        host_header = str(config.get("hostHeader") or "").strip()
        if host_header:
            info["HostHeader"] = host_header
        return info

    @classmethod
    def _apply_origin_transport_params(cls, payload: Dict[str, Any], config: Dict[str, Any]) -> None:
        """Add protocol / ports / IPv6 as TOP-LEVEL API parameters.

        Per the official schema these live on the request root:
          IPv6Status (follow|on|off), OriginProtocol (HTTP|HTTPS|FOLLOW),
          HttpOriginPort, HttpsOriginPort.
        Previously they were sent inside OriginInfo (rejected) and then
        silently stripped by the fallback retry, discarding the user's config.
        """
        ipv6_status = cls._normalize_ipv6_status(config.get("ipv6Status"))
        if ipv6_status:
            payload["IPv6Status"] = ipv6_status
        origin_protocol = str(config.get("originProtocol") or "").strip()
        if origin_protocol:
            payload["OriginProtocol"] = origin_protocol.upper()
        try:
            http_port = int(config.get("httpOriginPort") or config.get("originPort") or 0)
        except Exception:
            http_port = 0
        try:
            https_port = int(config.get("httpsOriginPort") or config.get("originPort") or 0)
        except Exception:
            https_port = 0
        if http_port > 0:
            payload["HttpOriginPort"] = http_port
        if https_port > 0:
            payload["HttpsOriginPort"] = https_port

    def _request_acceleration_domain_with_port_fallback(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Retry without transport params ONLY when the API rejects them.

        The old code nested ports/protocol under OriginInfo, which newer API
        versions rejected — and the fallback then silently dropped the user's
        settings. Params now go to the correct top level; this stripped retry
        remains solely as compatibility for older API versions, and the strip
        is flagged via the returned payload so callers can surface a warning.
        """
        retry_payload = json.loads(json.dumps(payload, ensure_ascii=False))
        stripped: List[str] = []
        while True:
            try:
                result = self._tc3_request(action, retry_payload)
                if stripped and isinstance(result, dict):
                    result["_strippedParams"] = list(stripped)
                return result
            except TencentEdgeOneApiError as exc:
                message = str(exc)
                unknown = "UnknownParameter" in message or "not recognized" in message
                if not unknown:
                    raise
                if "IPv6Status" in message and "IPv6Status" in retry_payload and "IPv6Status" not in stripped:
                    retry_payload.pop("IPv6Status", None)
                    stripped.append("IPv6Status")
                    continue
                if "IPv6Status" in message and "IPv6Status" in retry_payload:
                    retry_payload.pop("IPv6Status", None)
                    continue
                if "OriginProtocol" in message and "OriginProtocol" in retry_payload:
                    retry_payload.pop("OriginProtocol", None)
                    stripped.append("OriginProtocol")
                    continue
                if ("HttpOriginPort" in message or "HttpsOriginPort" in message):
                    popped = False
                    if "HttpOriginPort" in retry_payload:
                        retry_payload.pop("HttpOriginPort", None)
                        stripped.append("HttpOriginPort")
                        popped = True
                    if "HttpsOriginPort" in retry_payload:
                        retry_payload.pop("HttpsOriginPort", None)
                        stripped.append("HttpsOriginPort")
                        popped = True
                    if popped:
                        continue
                raise

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
            paused = paused_raw.strip().lower() in {"1", "true", "on", "yes"}
        else:
            paused = bool(paused_raw)
        if paused_raw is None:
            paused = status.strip().lower() in {"paused", "disabled", "suspended", "offline"}
        verify_status_lower = (cname_status or status or "").strip().lower()
        return {
            "siteId": str(raw.get("ZoneId") or raw.get("Id") or ""),
            "zoneId": str(raw.get("ZoneId") or raw.get("Id") or ""),
            "zoneName": str(raw.get("ZoneName") or raw.get("Name") or ""),
            "siteName": str(raw.get("ZoneName") or raw.get("Name") or ""),
            "status": status or "unknown",
            "verifyStatus": cname_status or status or "unknown",
            "verified": status.lower() in {"success", "active", "online", "enabled", "verified"} or verify_status_lower in {"success", "completed", "finished", "verified", "active"},
            "paused": paused,
            "type": str(raw.get("Type") or raw.get("AccessType") or ""),
            "area": str(raw.get("Area") or raw.get("Region") or ""),
            "planId": str(raw.get("PlanId") or ""),
            "createdAt": raw.get("CreatedOn") or raw.get("CreateTime"),
            "updatedAt": raw.get("ModifiedOn") or raw.get("UpdateTime"),
            "raw": raw,
        }

    @staticmethod
    def _normalize_acceleration_domain(raw: Dict[str, Any]) -> Dict[str, Any]:
        origin_detail = raw.get("OriginDetail") if isinstance(raw.get("OriginDetail"), dict) else {}
        certificate_info = raw.get("Certificate") if isinstance(raw.get("Certificate"), dict) else {}
        certificate_list = certificate_info.get("List") if isinstance(certificate_info.get("List"), list) else []
        first_certificate = certificate_list[0] if certificate_list and isinstance(certificate_list[0], dict) else {}
        certificate_mode = str(certificate_info.get("Mode") or "").strip()
        certificate_mode_lower = certificate_mode.lower()
        domain_status = str(raw.get("DomainStatus") or raw.get("Status") or "unknown")
        identification_status = str(raw.get("IdentificationStatus") or raw.get("VerifyStatus") or "")
        verify_lower = identification_status.strip().lower()
        status_lower = domain_status.strip().lower()
        data = {
            "domainName": str(raw.get("DomainName") or raw.get("Name") or ""),
            "domainStatus": domain_status or "unknown",
            "siteId": str(raw.get("ZoneId") or ""),
            "identificationStatus": identification_status or domain_status or "unknown",
            "verified": verify_lower in {"verified", "completed", "finished", "success"} or status_lower in {"active", "online"},
            "paused": status_lower in {"paused", "disabled", "offline"},
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
            "certificateMode": certificate_mode,
            "certificateId": str(first_certificate.get("CertId") or first_certificate.get("CertificateId") or "").strip(),
            "certificateIds": [
                str(item.get("CertId") or item.get("CertificateId") or "").strip()
                for item in certificate_list
                if isinstance(item, dict) and str(item.get("CertId") or item.get("CertificateId") or "").strip()
            ],
            "certificateStatus": str(first_certificate.get("Status") or "").strip(),
            "certificateIssuer": str(first_certificate.get("Issuer") or "").strip(),
            "certificateEffectiveTime": first_certificate.get("EffectiveTime") or first_certificate.get("NotBefore"),
            "certificateExpireTime": first_certificate.get("ExpireTime") or first_certificate.get("NotAfter"),
            "certificateSignAlgo": str(first_certificate.get("SignAlgo") or "").strip(),
            "certificateBound": bool(first_certificate or (certificate_mode and certificate_mode_lower not in {"disable", "disabled", "off", "none"})),
            "createdAt": raw.get("CreatedOn") or raw.get("CreateTime"),
            "updatedAt": raw.get("ModifiedOn") or raw.get("UpdateTime"),
            "raw": raw,
        }
        verification = TencentEdgeOneApi._normalize_verification(raw)
        if verification.get("recordName") or verification.get("recordValue"):
            data["verifyRecordName"] = str(verification.get("recordName") or "")
            data["verifyRecordType"] = str(verification.get("recordType") or "")
            data["verifyRecordValue"] = str(verification.get("recordValue") or "")
            if verification.get("verificationCode"):
                data["verificationCode"] = str(verification.get("verificationCode") or "")
        data["uiState"] = TencentEdgeOneApi._compute_ui_state(
            domain_status=data.get("domainStatus"),
            identification_status=data.get("identificationStatus"),
            cname_status=data.get("cnameStatus"),
            paused=bool(data.get("paused")),
        )
        return data

    @staticmethod
    def _normalize_host_certificate(raw: Dict[str, Any]) -> Dict[str, Any]:
        cert_info = raw.get("CertInfo") if isinstance(raw.get("CertInfo"), dict) else {}
        server_cert_info = raw.get("ServerCertInfo") if isinstance(raw.get("ServerCertInfo"), dict) else {}
        host_cert_info = raw.get("HostCertInfo")
        if isinstance(host_cert_info, list):
            host_cert_info = host_cert_info[0] if host_cert_info and isinstance(host_cert_info[0], dict) else {}
        elif not isinstance(host_cert_info, dict):
            host_cert_info = {}
        if not server_cert_info:
            infos = raw.get("ServerCertInfos") if isinstance(raw.get("ServerCertInfos"), list) else []
            if infos and isinstance(infos[0], dict):
                server_cert_info = infos[0]
        if not server_cert_info and host_cert_info:
            server_cert_info = host_cert_info
        hosts_raw = raw.get("Hosts")
        hosts: List[str] = []
        if isinstance(hosts_raw, list):
            hosts = [str(item).strip() for item in hosts_raw if str(item).strip()]
        else:
            for candidate in (
                raw.get("Host"),
                raw.get("Hostname"),
                raw.get("DomainName"),
                raw.get("Domain"),
                cert_info.get("DomainName"),
            ):
                text = str(candidate or "").strip()
                if text:
                    hosts = [text]
                    break
        certificate_id = str(
            raw.get("CertificateId")
            or raw.get("CertId")
            or raw.get("Id")
            or raw.get("Certificate")
            or server_cert_info.get("CertificateId")
            or server_cert_info.get("CertId")
            or host_cert_info.get("CertificateId")
            or host_cert_info.get("CertId")
            or cert_info.get("CertificateId")
            or cert_info.get("CertId")
            or ""
        ).strip()
        status = str(
            raw.get("Status")
            or raw.get("CertStatus")
            or server_cert_info.get("Status")
            or server_cert_info.get("CertStatus")
            or host_cert_info.get("Status")
            or host_cert_info.get("CertStatus")
            or cert_info.get("Status")
            or cert_info.get("CertStatus")
            or ""
        ).strip() or "unknown"
        cert_type = str(
            raw.get("Mode")
            or raw.get("CertType")
            or server_cert_info.get("Mode")
            or server_cert_info.get("CertType")
            or host_cert_info.get("Mode")
            or host_cert_info.get("Type")
            or cert_info.get("Mode")
            or cert_info.get("CertType")
            or ""
        ).strip() or "managed"
        return {
            "hosts": hosts,
            "host": hosts[0] if hosts else "",
            "certificateId": certificate_id,
            "certId": certificate_id,
            "certType": cert_type,
            "status": status,
            "issuer": str(raw.get("Issuer") or server_cert_info.get("Issuer") or host_cert_info.get("Issuer") or cert_info.get("Issuer") or "").strip() or None,
            "subject": str(raw.get("Subject") or server_cert_info.get("Subject") or host_cert_info.get("Subject") or cert_info.get("Subject") or "").strip() or None,
            "signAlgo": str(raw.get("SignAlgo") or server_cert_info.get("SignAlgo") or host_cert_info.get("SignAlgo") or cert_info.get("SignAlgo") or "").strip() or None,
            "expireTime": raw.get("ExpireTime") or raw.get("NotAfter") or server_cert_info.get("ExpireTime") or server_cert_info.get("NotAfter") or host_cert_info.get("ExpireTime") or host_cert_info.get("NotAfter") or cert_info.get("ExpireTime") or cert_info.get("NotAfter"),
            "effectiveTime": raw.get("EffectiveTime") or raw.get("NotBefore") or server_cert_info.get("EffectiveTime") or server_cert_info.get("NotBefore") or server_cert_info.get("DeployTime") or host_cert_info.get("EffectiveTime") or host_cert_info.get("NotBefore") or host_cert_info.get("DeployTime") or cert_info.get("EffectiveTime") or cert_info.get("NotBefore"),
            "requestId": raw.get("RequestId"),
            "raw": raw,
        }

    @staticmethod
    def _normalize_verification_record_name(zone_name: str, subdomain: str) -> str:
        zone = TencentEdgeOneApi.normalize_zone_name(zone_name)
        sub = str(subdomain or "").strip().rstrip(".")
        if not sub or sub == "@":
            return zone
        normalized_sub = TencentEdgeOneApi.normalize_zone_name(sub)
        if not zone:
            return normalized_sub
        if normalized_sub == zone or normalized_sub.endswith(f".{zone}"):
            return normalized_sub
        return f"{normalized_sub}.{zone}"
