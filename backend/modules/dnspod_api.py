from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List


class DnspodApiError(Exception):
    def __init__(self, message: str, status: int = 400, errors: list | None = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.errors = errors or []


# ── Record type mappings ────────────────────────────────────────────

_TC3_TO_GENERIC_TYPE: Dict[str, str] = {
    "\u663e\u6027URL": "REDIRECT_URL",
    "\u9690\u6027URL": "FORWARD_URL",
}
_GENERIC_TO_TC3_TYPE: Dict[str, str] = {v: k for k, v in _TC3_TO_GENERIC_TYPE.items()}

_TOKEN_TO_GENERIC_TYPE: Dict[str, str] = {"URL": "REDIRECT_URL"}
_GENERIC_TO_TOKEN_TYPE: Dict[str, str] = {"REDIRECT_URL": "URL", "FORWARD_URL": "URL"}

# ── Line mappings ───────────────────────────────────────────────────

# TC3: generic code <-> Chinese display name
_GENERIC_TO_DNSPOD_LINE: Dict[str, str] = {
    "default": "\u9ed8\u8ba4",
    "telecom": "\u7535\u4fe1",
    "unicom": "\u8054\u901a",
    "mobile": "\u79fb\u52a8",
    "oversea": "\u5883\u5916",
    "edu": "\u6559\u80b2\u7f51",
    "drpeng": "\u957f\u57ce\u5bbd\u5e26",
    "cernet": "CERNET",
}
_DNSPOD_LINE_TO_GENERIC: Dict[str, str] = {v: k for k, v in _GENERIC_TO_DNSPOD_LINE.items()}

# Token: generic code <-> numeric line ID
_GENERIC_TO_LINE_ID: Dict[str, str] = {
    "default": "0",
    "telecom": "10=0",
    "unicom": "10=1",
    "mobile": "10=3",
    "edu": "10=2",
    "oversea": "3=0",
    "btvn": "10=22",
    "search": "80=0",
    "internal": "7=0",
}
_LINE_ID_TO_GENERIC: Dict[str, str] = {v: k for k, v in _GENERIC_TO_LINE_ID.items()}

_DEFAULT_LINES: List[Dict[str, str]] = [
    {"code": k, "name": v} for k, v in _GENERIC_TO_DNSPOD_LINE.items()
]


# ── SRV value parser ───────────────────────────────────────────────

def _parse_srv_value(raw: str) -> Dict[str, Any]:
    """Parse SRV value string: ``priority weight port target``."""
    tokens = raw.split()

    def _num(v: str):
        try:
            n = int(v)
            return n
        except ValueError:
            try:
                f = float(v)
                return None if f != f else int(f)
            except ValueError:
                return None

    if len(tokens) >= 4 and _num(tokens[0]) is not None and _num(tokens[1]) is not None and _num(tokens[2]) is not None:
        return {"priority": _num(tokens[0]), "weight": _num(tokens[1]), "port": _num(tokens[2]), "target": " ".join(tokens[3:])}

    if len(tokens) >= 3 and _num(tokens[0]) is not None and _num(tokens[1]) is not None:
        remainder = " ".join(tokens[2:])
        if _num(remainder) is not None:
            return {}
        return {"weight": _num(tokens[0]), "port": _num(tokens[1]), "target": remainder}

    if len(tokens) >= 2 and _num(tokens[0]) is not None:
        remainder = " ".join(tokens[1:])
        if _num(remainder) is not None:
            return {}
        return {"port": _num(tokens[0]), "target": remainder}

    return {}


# ── Main API class ──────────────────────────────────────────────────

class DnspodApi:
    HOST = "dnspod.tencentcloudapi.com"
    SERVICE = "dnspod"
    VERSION = "2021-03-23"
    TOKEN_HOST = "dnsapi.cn"

    def __init__(self, secrets: Dict[str, Any]) -> None:
        secret_id = str(secrets.get("secretId") or "").strip()
        secret_key = str(secrets.get("secretKey") or "").strip()
        token_id = str(secrets.get("tokenId") or "").strip()
        token = str(secrets.get("token") or "").strip()

        has_tc3 = bool(secret_id and secret_key)
        has_legacy_pair = bool(token_id and token)
        has_legacy_combined = bool(token and "," in token and not token_id)

        if has_tc3:
            self._mode = "tc3"
            self._secret_id = secret_id
            self._secret_key = secret_key
        elif has_legacy_pair:
            self._mode = "token"
            self._login_token = f"{token_id},{token}"
        elif has_legacy_combined:
            self._mode = "token"
            self._login_token = token
        else:
            raise DnspodApiError("\u7f3a\u5c11 DNSPod \u8ba4\u8bc1\u51ed\u8bc1\uff08SecretId/SecretKey \u6216 Token\uff09", 400)

        self._domain_cache: Dict[str, Dict[str, str]] = {}
        self._line_name_map: Dict[str, Dict[str, str]] = {}
        self._line_id_map: Dict[str, Dict[str, str]] = {}
        self._zone_meta: Dict[str, Dict[str, Any]] = {}

    # ── TC3-HMAC-SHA256 signing ─────────────────────────────────────

    @staticmethod
    def _sha256_hex(data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _hmac_sha256(key: bytes, data: str) -> bytes:
        return hmac.new(key, data.encode("utf-8"), hashlib.sha256).digest()

    def _tc3_request(self, action: str, payload: Dict[str, Any]) -> Any:
        payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        timestamp = int(time.time())
        date = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d")
        content_type = "application/json; charset=utf-8"

        # Canonical Request
        hashed_payload = self._sha256_hex(payload_json)
        canonical = (
            f"POST\n/\n\n"
            f"content-type:{content_type}\n"
            f"host:{self.HOST}\n\n"
            f"content-type;host\n"
            f"{hashed_payload}"
        )

        # String to Sign
        credential_scope = f"{date}/{self.SERVICE}/tc3_request"
        string_to_sign = (
            f"TC3-HMAC-SHA256\n{timestamp}\n"
            f"{credential_scope}\n"
            f"{self._sha256_hex(canonical)}"
        )

        # Signing Key chain
        secret_date = self._hmac_sha256(f"TC3{self._secret_key}".encode("utf-8"), date)
        secret_service = self._hmac_sha256(secret_date, self.SERVICE)
        secret_signing = self._hmac_sha256(secret_service, "tc3_request")
        signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        authorization = (
            f"TC3-HMAC-SHA256 "
            f"Credential={self._secret_id}/{credential_scope}, "
            f"SignedHeaders=content-type;host, "
            f"Signature={signature}"
        )

        headers = {
            "Host": self.HOST,
            "Content-Type": content_type,
            "Authorization": authorization,
            "X-TC-Action": action,
            "X-TC-Version": self.VERSION,
            "X-TC-Timestamp": str(timestamp),
            "User-Agent": "dns-panel-python-v2/1.0",
        }

        data = payload_json.encode("utf-8")
        req = urllib.request.Request(f"https://{self.HOST}/", method="POST", data=data, headers=headers)

        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                raw = resp.read().decode("utf-8")
                result = json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw_body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            try:
                err_data = json.loads(raw_body) if raw_body else {}
            except Exception:
                err_data = {}
            err_resp = err_data.get("Response", {}) if isinstance(err_data, dict) else {}
            err_obj = err_resp.get("Error", {}) if isinstance(err_resp, dict) else {}
            msg = str(err_obj.get("Message") or e.reason or "DNSPod TC3 API \u8bf7\u6c42\u5931\u8d25")
            raise DnspodApiError(msg, int(e.code or 400))
        except Exception as e:
            raise DnspodApiError(f"DNSPod \u7f51\u7edc\u8bf7\u6c42\u5931\u8d25: {e}", 503)

        response = result.get("Response", {}) if isinstance(result, dict) else {}
        if not isinstance(response, dict):
            raise DnspodApiError("DNSPod \u8fd4\u56de\u683c\u5f0f\u9519\u8bef", 502)

        err = response.get("Error")
        if isinstance(err, dict) and err.get("Code"):
            raise DnspodApiError(str(err.get("Message") or err.get("Code") or "DNSPod API \u9519\u8bef"), 400)

        return response

    # ── Token request ───────────────────────────────────────────────

    def _token_request(self, action: str, params: Dict[str, Any] | None = None) -> Any:
        form: Dict[str, str] = {"login_token": self._login_token, "format": "json"}
        for k, v in (params or {}).items():
            if v is None:
                continue
            form[str(k)] = str(v)

        data = urllib.parse.urlencode(form).encode("utf-8")
        req = urllib.request.Request(
            f"https://{self.TOKEN_HOST}/{action}",
            method="POST",
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "dns-panel-python-v2/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                result = json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw_body = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            try:
                err_data = json.loads(raw_body) if raw_body else {}
            except Exception:
                err_data = {}
            status_obj = err_data.get("status", {}) if isinstance(err_data, dict) else {}
            msg = str(status_obj.get("message") or e.reason or "DNSPod Token API \u8bf7\u6c42\u5931\u8d25") if isinstance(status_obj, dict) else str(e.reason)
            raise DnspodApiError(msg, int(e.code or 400))
        except Exception as e:
            raise DnspodApiError(f"DNSPod \u7f51\u7edc\u8bf7\u6c42\u5931\u8d25: {e}", 503)

        if not isinstance(result, dict):
            raise DnspodApiError("DNSPod \u8fd4\u56de\u683c\u5f0f\u9519\u8bef", 502)

        status = result.get("status", {})
        code = str(status.get("code") or "") if isinstance(status, dict) else ""
        if code != "1":
            msg = str(status.get("message") or "DNSPod API \u9519\u8bef") if isinstance(status, dict) else "DNSPod API \u9519\u8bef"
            raise DnspodApiError(msg, 400)

        return result

    # ── Internal helpers ────────────────────────────────────────────

    def _resolve_zone(self, zone_id: str) -> Dict[str, str]:
        zid = str(zone_id or "").strip()
        if zid in self._domain_cache:
            return self._domain_cache[zid]

        if self._mode == "tc3":
            try:
                zid_int = int(zid)
            except ValueError:
                raise DnspodApiError("\u65e0\u6548\u7684\u57df\u540d ID", 400)
            for page_num in range(50):
                resp = self._tc3_request("DescribeDomainList", {"Offset": page_num * 100, "Limit": 100})
                domains = resp.get("DomainList") or []
                if not isinstance(domains, list):
                    break
                for d in domains:
                    if not isinstance(d, dict):
                        continue
                    did = str(d.get("DomainId") or "")
                    dname = str(d.get("Name") or "")
                    if did:
                        self._domain_cache[did] = {"id": did, "name": dname}
                    if did == zid:
                        return self._domain_cache[zid]
                if len(domains) < 100:
                    break
            raise DnspodApiError("\u57df\u540d\u4e0d\u5b58\u5728", 404)
        else:
            resp = self._token_request("Domain.Info", {"domain_id": zid})
            domain = resp.get("domain", {}) if isinstance(resp, dict) else {}
            if not isinstance(domain, dict):
                raise DnspodApiError("\u57df\u540d\u4e0d\u5b58\u5728", 404)
            did = str(domain.get("id") or zid)
            dname = str(domain.get("name") or domain.get("domain") or "")
            self._domain_cache[did] = {"id": did, "name": dname}
            grade = str(domain.get("grade") or domain.get("domain_grade") or "DP_Free")
            ttl = domain.get("ttl")
            self._zone_meta[did] = {"grade": grade, "ttl": ttl}
            return self._domain_cache[did]

    @staticmethod
    def _to_fqdn(rr: str, domain: str) -> str:
        rr = str(rr or "").strip()
        domain = str(domain or "").strip()
        if not rr or rr == "@":
            return domain
        if rr.endswith(f".{domain}"):
            return rr
        return f"{rr}.{domain}"

    @staticmethod
    def _to_rr(name: str, domain: str) -> str:
        name = str(name or "").strip()
        domain = str(domain or "").strip()
        if not name or name == domain:
            return "@"
        suffix = f".{domain}"
        if name.endswith(suffix):
            return name[: -len(suffix)]
        return name

    # Record type conversion
    @staticmethod
    def _from_tc3_type(t: str) -> str:
        return _TC3_TO_GENERIC_TYPE.get(t, t)

    @staticmethod
    def _to_tc3_type(t: str) -> str:
        return _GENERIC_TO_TC3_TYPE.get(t, t)

    @staticmethod
    def _from_token_type(t: str) -> str:
        return _TOKEN_TO_GENERIC_TYPE.get(t, t)

    @staticmethod
    def _to_token_type(t: str) -> str:
        return _GENERIC_TO_TOKEN_TYPE.get(t, t)

    # Line conversion
    @staticmethod
    def _from_line_name(name: str) -> str:
        return _DNSPOD_LINE_TO_GENERIC.get(name, name)

    @staticmethod
    def _from_line_id(lid: str) -> str:
        return _LINE_ID_TO_GENERIC.get(lid, lid)

    def _resolve_line_tc3(self, zone_id: str, line: str | None) -> Dict[str, str]:
        if not line or line == "default":
            return {"recordLine": "\u9ed8\u8ba4", "recordLineId": "0"}
        line_name = _GENERIC_TO_DNSPOD_LINE.get(line)
        if line_name:
            return {"recordLine": line_name, "recordLineId": _GENERIC_TO_LINE_ID.get(line, "0")}
        zone_map = self._line_name_map.get(zone_id, {})
        if line in zone_map:
            return {"recordLine": zone_map[line], "recordLineId": _GENERIC_TO_LINE_ID.get(line, "0")}
        if line in _DNSPOD_LINE_TO_GENERIC:
            return {"recordLine": line, "recordLineId": _GENERIC_TO_LINE_ID.get(_DNSPOD_LINE_TO_GENERIC[line], "0")}
        return {"recordLine": line, "recordLineId": "0"}

    def _resolve_line_token(self, zone_id: str, line: str | None) -> str:
        if not line or line == "default":
            return "0"
        lid = _GENERIC_TO_LINE_ID.get(line)
        if lid:
            return lid
        zone_map = self._line_id_map.get(zone_id, {})
        if line in zone_map:
            return zone_map[line]
        generic = _DNSPOD_LINE_TO_GENERIC.get(line)
        if generic:
            return _GENERIC_TO_LINE_ID.get(generic, "0")
        if line in _LINE_ID_TO_GENERIC:
            return line
        return "0"

    # ── Public API methods ──────────────────────────────────────────

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        if self._mode == "tc3":
            payload: Dict[str, Any] = {"Offset": (page - 1) * page_size, "Limit": page_size}
            if keyword:
                payload["Keyword"] = keyword
            resp = self._tc3_request("DescribeDomainList", payload)
            domains = resp.get("DomainList") or []
            total_info = resp.get("DomainCountInfo", {})
            total = int(total_info.get("AllTotal") or 0) if isinstance(total_info, dict) else 0
            zones = []
            for d in (domains if isinstance(domains, list) else []):
                if not isinstance(d, dict):
                    continue
                did = str(d.get("DomainId") or "")
                dname = str(d.get("Name") or "")
                if did:
                    self._domain_cache[did] = {"id": did, "name": dname}
                zones.append({
                    "id": did,
                    "name": dname,
                    "status": str(d.get("Status") or "ENABLE"),
                    "recordCount": d.get("RecordCount"),
                    "updatedAt": d.get("UpdatedOn"),
                })
            return {"zones": zones, "total": total or len(zones)}
        else:
            params: Dict[str, Any] = {"offset": (page - 1) * page_size, "length": page_size}
            if keyword:
                params["keyword"] = keyword
            resp = self._token_request("Domain.List", params)
            info = resp.get("info", {}) if isinstance(resp, dict) else {}
            total = int(info.get("domain_total") or 0) if isinstance(info, dict) else 0
            domains = resp.get("domains") or []
            zones = []
            for d in (domains if isinstance(domains, list) else []):
                if not isinstance(d, dict):
                    continue
                did = str(d.get("id") or "")
                dname = str(d.get("name") or "")
                if did:
                    self._domain_cache[did] = {"id": did, "name": dname}
                zones.append({
                    "id": did,
                    "name": dname,
                    "status": str(d.get("status") or "enable"),
                    "recordCount": d.get("records"),
                    "updatedAt": d.get("updated_on"),
                })
            return {"zones": zones, "total": total or len(zones)}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        zone = self._resolve_zone(zone_id)
        if self._mode == "tc3":
            return {"id": zone["id"], "name": zone["name"], "status": "ENABLE", "recordCount": None, "updatedAt": None}
        else:
            resp = self._token_request("Domain.Info", {"domain_id": zone_id})
            domain = resp.get("domain", {}) if isinstance(resp, dict) else {}
            if not isinstance(domain, dict):
                raise DnspodApiError("\u57df\u540d\u4e0d\u5b58\u5728", 404)
            grade = str(domain.get("grade") or domain.get("domain_grade") or "DP_Free")
            ttl = domain.get("ttl")
            self._zone_meta[str(domain.get("id") or zone_id)] = {"grade": grade, "ttl": ttl}
            return {
                "id": str(domain.get("id") or zone_id),
                "name": str(domain.get("name") or ""),
                "status": str(domain.get("status") or "enable"),
                "recordCount": domain.get("records"),
                "updatedAt": domain.get("updated_on"),
            }

    def create_zone(self, domain: str) -> Dict[str, Any]:
        domain = str(domain or "").strip()
        if self._mode == "tc3":
            try:
                self._tc3_request("CreateDomain", {"Domain": domain})
            except DnspodApiError:
                pass
            resp = self._tc3_request("DescribeDomainList", {"Offset": 0, "Limit": 100, "Keyword": domain})
            for d in (resp.get("DomainList") or []):
                if not isinstance(d, dict):
                    continue
                if str(d.get("Name") or "").lower() == domain.lower():
                    did = str(d.get("DomainId") or "")
                    self._domain_cache[did] = {"id": did, "name": domain}
                    return {"id": did, "name": str(d.get("Name") or domain), "status": str(d.get("Status") or "ENABLE"), "recordCount": d.get("RecordCount"), "updatedAt": d.get("UpdatedOn")}
            raise DnspodApiError("\u521b\u5efa\u57df\u540d\u540e\u672a\u80fd\u627e\u5230\u8be5\u57df\u540d", 400)
        else:
            try:
                self._token_request("Domain.Create", {"domain": domain})
            except DnspodApiError as e:
                if "\u5df2\u6dfb\u52a0" not in str(e) and "already" not in str(e).lower():
                    raise
            try:
                resp = self._token_request("Domain.Info", {"domain": domain})
                d = resp.get("domain", {}) if isinstance(resp, dict) else {}
                if isinstance(d, dict):
                    did = str(d.get("id") or "")
                    return {"id": did, "name": str(d.get("name") or domain), "status": str(d.get("status") or "enable"), "recordCount": d.get("records"), "updatedAt": d.get("updated_on")}
            except Exception:
                pass
            raise DnspodApiError("\u521b\u5efa\u57df\u540d\u540e\u672a\u80fd\u627e\u5230\u8be5\u57df\u540d", 400)

    def delete_zone(self, zone_id: str) -> bool:
        zid = str(zone_id or "").strip()
        if self._mode == "tc3":
            try:
                self._tc3_request("DeleteDomain", {"DomainId": int(zid)})
            except ValueError:
                self._tc3_request("DeleteDomain", {"Domain": zid})
        else:
            try:
                int(zid)
                self._token_request("Domain.Remove", {"domain_id": zid})
            except ValueError:
                self._token_request("Domain.Remove", {"domain": zid})
        self._domain_cache.pop(zid, None)
        return True

    def list_records(self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None) -> Dict[str, Any]:
        zone = self._resolve_zone(zone_id)
        domain_name = zone["name"]
        filters = filters or {}

        sub_domain = filters.get("subDomain") or filters.get("name")
        rtype = filters.get("type")
        value = filters.get("value") or filters.get("content")
        keyword = filters.get("keyword")
        line = filters.get("line")
        status_filter = filters.get("status")

        if self._mode == "tc3":
            use_filter_api = bool(value or status_filter)
            if use_filter_api:
                payload: Dict[str, Any] = {"Domain": domain_name, "DomainId": int(zone_id), "Offset": (page - 1) * page_size, "Limit": page_size}
                if sub_domain:
                    payload["SubDomain"] = self._to_rr(sub_domain, domain_name)
                if rtype:
                    payload["RecordType"] = [self._to_tc3_type(rtype)]
                if line:
                    rl = self._resolve_line_tc3(zone_id, line)
                    payload["RecordLine"] = [rl["recordLine"]]
                if status_filter:
                    if status_filter in ("1", "ENABLE", "enable"):
                        payload["RecordStatus"] = ["ENABLE"]
                    elif status_filter in ("0", "DISABLE", "disable"):
                        payload["RecordStatus"] = ["DISABLE"]
                if value:
                    payload["Keyword"] = value
                resp = self._tc3_request("DescribeRecordFilterList", payload)
            else:
                payload = {"Domain": domain_name, "DomainId": int(zone_id), "Offset": (page - 1) * page_size, "Limit": page_size}
                if sub_domain:
                    payload["Subdomain"] = self._to_rr(sub_domain, domain_name)
                if rtype:
                    payload["RecordType"] = self._to_tc3_type(rtype)
                if line:
                    rl = self._resolve_line_tc3(zone_id, line)
                    payload["RecordLine"] = rl["recordLine"]
                    payload["RecordLineId"] = rl["recordLineId"]
                if keyword:
                    payload["Keyword"] = keyword
                resp = self._tc3_request("DescribeRecordList", payload)

            records_raw = resp.get("RecordList") or []
            count_info = resp.get("RecordCountInfo", {})
            total = int(count_info.get("TotalCount") or 0) if isinstance(count_info, dict) else 0
            records = []
            for r in (records_raw if isinstance(records_raw, list) else []):
                if not isinstance(r, dict):
                    continue
                rec_type = self._from_tc3_type(str(r.get("Type") or ""))
                rec_value = str(r.get("Value") or "")
                rec_weight = r.get("Weight")
                rec_priority = r.get("MX")
                rec_line_id = str(r.get("LineId") or "")
                rec_line_name = str(r.get("Line") or "")
                if rec_type == "SRV":
                    parsed = _parse_srv_value(rec_value)
                    if parsed.get("weight") is not None:
                        rec_weight = parsed["weight"]
                    if parsed.get("priority") is not None:
                        rec_priority = parsed["priority"]
                line_code = self._from_line_id(rec_line_id) if rec_line_id else self._from_line_name(rec_line_name)
                raw_status = str(r.get("Status") or "")
                rec_status = "1" if raw_status == "ENABLE" else ("0" if raw_status == "DISABLE" else raw_status)
                records.append({
                    "id": str(r.get("RecordId") or ""),
                    "name": self._to_fqdn(str(r.get("Name") or ""), domain_name),
                    "type": rec_type, "value": rec_value, "ttl": r.get("TTL"),
                    "line": line_code, "weight": rec_weight, "priority": rec_priority,
                    "status": rec_status, "remark": r.get("Remark"), "updatedAt": r.get("UpdatedOn"),
                })
            return {"records": records, "total": total or len(records)}
        else:
            params: Dict[str, Any] = {"domain_id": zone_id, "offset": (page - 1) * page_size, "length": page_size}
            if sub_domain:
                params["sub_domain"] = self._to_rr(sub_domain, domain_name)
            if rtype:
                params["record_type"] = self._to_token_type(rtype)
            resp = self._token_request("Record.List", params)
            info = resp.get("info", {}) if isinstance(resp, dict) else {}
            total = int(info.get("record_total") or 0) if isinstance(info, dict) else 0
            domain_info = resp.get("domain", {}) if isinstance(resp, dict) else {}
            if isinstance(domain_info, dict):
                self._zone_meta[zone_id] = {"grade": str(domain_info.get("grade") or "DP_Free"), "ttl": domain_info.get("ttl")}
            records = []
            for r in (resp.get("records") or [] if isinstance(resp.get("records"), list) else []):
                if not isinstance(r, dict):
                    continue
                rec_type = self._from_token_type(str(r.get("type") or ""))
                rec_value = str(r.get("value") or "")
                rec_weight = r.get("weight")
                rec_priority = r.get("mx")
                rec_line_id = str(r.get("line_id") or "")
                if rec_type == "SRV":
                    parsed = _parse_srv_value(rec_value)
                    if parsed.get("weight") is not None:
                        rec_weight = parsed["weight"]
                    if parsed.get("priority") is not None:
                        rec_priority = parsed["priority"]
                line_code = self._from_line_id(rec_line_id) if rec_line_id else "default"
                raw_enabled = str(r.get("enabled") or "1")
                rec_status = "1" if raw_enabled == "1" else "0"
                records.append({
                    "id": str(r.get("id") or ""),
                    "name": self._to_fqdn(str(r.get("name") or ""), domain_name),
                    "type": rec_type, "value": rec_value, "ttl": r.get("ttl"),
                    "line": line_code, "weight": rec_weight if rec_weight is not None else None,
                    "priority": rec_priority, "status": rec_status,
                    "remark": r.get("remark"), "updatedAt": r.get("updated_on"),
                })
            if keyword:
                kw = keyword.lower()
                records = [r for r in records if kw in str(r.get("name") or "").lower() or kw in str(r.get("value") or "").lower()]
            if value:
                vl = value.lower()
                records = [r for r in records if vl in str(r.get("value") or "").lower()]
            if status_filter:
                records = [r for r in records if r.get("status") == status_filter]
            return {"records": records, "total": total or len(records)}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        zone = self._resolve_zone(zone_id)
        domain_name = zone["name"]

        if self._mode == "tc3":
            resp = self._tc3_request("DescribeRecord", {"Domain": domain_name, "DomainId": int(zone_id), "RecordId": int(record_id)})
            info = resp.get("RecordInfo", {})
            if not isinstance(info, dict):
                raise DnspodApiError("\u8bb0\u5f55\u4e0d\u5b58\u5728", 404)
            rid = str(info.get("RecordId") or info.get("Id") or record_id)
            name = str(info.get("SubDomain") or info.get("Name") or "")
            rec_type = self._from_tc3_type(str(info.get("RecordType") or info.get("Type") or ""))
            rec_value = str(info.get("Value") or "")
            rec_line = str(info.get("RecordLine") or info.get("Line") or "")
            rec_line_id = str(info.get("RecordLineId") or info.get("LineId") or "")
            raw_enabled = info.get("Enabled")
            if raw_enabled is not None:
                rec_status = "1" if int(raw_enabled) == 1 else "0"
            else:
                s = str(info.get("Status") or "")
                rec_status = "1" if s == "ENABLE" else "0"
            line_code = self._from_line_id(rec_line_id) if rec_line_id else self._from_line_name(rec_line)
            rec_weight = info.get("Weight")
            rec_priority = info.get("MX")
            if rec_type == "SRV":
                parsed = _parse_srv_value(rec_value)
                if parsed.get("weight") is not None:
                    rec_weight = parsed["weight"]
                if parsed.get("priority") is not None:
                    rec_priority = parsed["priority"]
            return {
                "id": rid, "name": self._to_fqdn(name, domain_name), "type": rec_type,
                "value": rec_value, "ttl": info.get("TTL"), "line": line_code,
                "weight": rec_weight, "priority": rec_priority, "status": rec_status,
                "remark": info.get("Remark"), "updatedAt": info.get("UpdatedOn"),
            }
        else:
            resp = self._token_request("Record.Info", {"domain_id": zone_id, "record_id": record_id})
            record = resp.get("record", {}) if isinstance(resp, dict) else {}
            if not isinstance(record, dict):
                raise DnspodApiError("\u8bb0\u5f55\u4e0d\u5b58\u5728", 404)
            rec_type = self._from_token_type(str(record.get("record_type") or record.get("type") or ""))
            rec_value = str(record.get("value") or "")
            rec_line_id = str(record.get("record_line_id") or record.get("line_id") or "")
            raw_enabled = str(record.get("enabled") or "1")
            rec_status = "1" if raw_enabled == "1" else "0"
            rec_weight = record.get("weight")
            rec_priority = record.get("mx")
            if rec_type == "SRV":
                parsed = _parse_srv_value(rec_value)
                if parsed.get("weight") is not None:
                    rec_weight = parsed["weight"]
                if parsed.get("priority") is not None:
                    rec_priority = parsed["priority"]
            line_code = self._from_line_id(rec_line_id) if rec_line_id else "default"
            return {
                "id": str(record.get("id") or record_id),
                "name": self._to_fqdn(str(record.get("sub_domain") or record.get("name") or ""), domain_name),
                "type": rec_type, "value": rec_value, "ttl": record.get("ttl"),
                "line": line_code, "weight": rec_weight if rec_weight is not None else None,
                "priority": rec_priority, "status": rec_status,
                "remark": record.get("remark"), "updatedAt": record.get("updated_on"),
            }

    def create_record(self, zone_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        zone = self._resolve_zone(zone_id)
        domain_name = zone["name"]
        name = str(params.get("name") or "").strip()
        rtype = str(params.get("type") or "").strip().upper()
        value = str(params.get("value") or "")
        ttl = params.get("ttl")
        priority = params.get("priority")
        weight = params.get("weight")
        line = params.get("line")
        remark = params.get("remark")
        rr = self._to_rr(name, domain_name)
        ttl_val = int(ttl) if isinstance(ttl, (int, float)) and int(ttl) > 1 else 600

        if self._mode == "tc3":
            api_type = self._to_tc3_type(rtype)
            resolved = self._resolve_line_tc3(zone_id, line)
            rec_value = value
            if rtype == "SRV":
                p = int(priority) if isinstance(priority, (int, float)) else 0
                w = int(weight) if isinstance(weight, (int, float)) else 0
                rec_value = f"{p} {w} {value}"
            payload: Dict[str, Any] = {
                "Domain": domain_name, "DomainId": int(zone_id), "SubDomain": rr,
                "RecordType": api_type, "RecordLine": resolved["recordLine"],
                "RecordLineId": resolved["recordLineId"], "Value": rec_value, "TTL": ttl_val,
            }
            if rtype == "MX" and priority is not None:
                payload["MX"] = int(priority)
            if rtype != "SRV" and weight is not None:
                payload["Weight"] = int(weight)
            resp = self._tc3_request("CreateRecord", payload)
            new_id = str(resp.get("RecordId") or "")
            if remark and new_id:
                try:
                    self._tc3_request("ModifyRecordRemark", {"Domain": domain_name, "DomainId": int(zone_id), "RecordId": int(new_id), "Remark": str(remark)})
                except Exception:
                    pass
            return self.get_record(zone_id, new_id)
        else:
            api_type = self._to_token_type(rtype)
            line_id = self._resolve_line_token(zone_id, line)
            params_req: Dict[str, Any] = {
                "domain_id": zone_id, "sub_domain": rr, "record_type": api_type,
                "record_line_id": line_id, "value": value, "ttl": ttl_val,
            }
            if rtype == "MX" and priority is not None:
                params_req["mx"] = int(priority)
            if weight is not None:
                params_req["weight"] = int(weight)
            resp = self._token_request("Record.Create", params_req)
            record = resp.get("record", {}) if isinstance(resp, dict) else {}
            new_id = str(record.get("id") or "") if isinstance(record, dict) else ""
            if remark and new_id:
                try:
                    self._token_request("Record.Remark", {"domain_id": zone_id, "record_id": new_id, "remark": str(remark)})
                except Exception:
                    pass
            return self.get_record(zone_id, new_id)

    def update_record(self, zone_id: str, record_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        zone = self._resolve_zone(zone_id)
        domain_name = zone["name"]
        old = None
        try:
            old = self.get_record(zone_id, record_id)
        except Exception:
            pass

        name = params.get("name")
        rtype = params.get("type")
        value = params.get("value")
        ttl = params.get("ttl")
        priority = params.get("priority")
        weight = params.get("weight")
        line = params.get("line")
        remark = params.get("remark")

        if old and isinstance(old, dict):
            if name is None:
                name = old.get("name", "")
            if rtype is None:
                rtype = old.get("type", "")
            if value is None:
                value = old.get("value", "")
            if ttl is None:
                ttl = old.get("ttl")
            if priority is None:
                priority = old.get("priority")
            if weight is None:
                weight = old.get("weight")
            if line is None:
                line = old.get("line")

        name = str(name or "").strip()
        rtype = str(rtype or "").strip().upper()
        value = str(value or "")
        rr = self._to_rr(name, domain_name)
        ttl_val = int(ttl) if isinstance(ttl, (int, float)) and int(ttl) > 1 else 600

        if self._mode == "tc3":
            api_type = self._to_tc3_type(rtype)
            resolved = self._resolve_line_tc3(zone_id, line)
            rec_value = value
            if rtype == "SRV":
                p = int(priority) if isinstance(priority, (int, float)) else 0
                w = int(weight) if isinstance(weight, (int, float)) else 0
                rec_value = f"{p} {w} {value}"
            payload: Dict[str, Any] = {
                "Domain": domain_name, "DomainId": int(zone_id), "RecordId": int(record_id),
                "SubDomain": rr, "RecordType": api_type,
                "RecordLine": resolved["recordLine"], "RecordLineId": resolved["recordLineId"],
                "Value": rec_value, "TTL": ttl_val,
            }
            if rtype == "MX" and priority is not None:
                payload["MX"] = int(priority)
            if rtype != "SRV" and weight is not None:
                payload["Weight"] = int(weight)
            self._tc3_request("ModifyRecord", payload)
            if remark is not None:
                try:
                    self._tc3_request("ModifyRecordRemark", {"Domain": domain_name, "DomainId": int(zone_id), "RecordId": int(record_id), "Remark": str(remark)})
                except Exception:
                    pass
            return self.get_record(zone_id, record_id)
        else:
            api_type = self._to_token_type(rtype)
            line_id = self._resolve_line_token(zone_id, line)
            params_req: Dict[str, Any] = {
                "domain_id": zone_id, "record_id": record_id, "sub_domain": rr,
                "record_type": api_type, "record_line_id": line_id, "value": value, "ttl": ttl_val,
            }
            if rtype == "MX" and priority is not None:
                params_req["mx"] = int(priority)
            if weight is not None:
                params_req["weight"] = int(weight)
            self._token_request("Record.Modify", params_req)
            if remark is not None:
                try:
                    self._token_request("Record.Remark", {"domain_id": zone_id, "record_id": record_id, "remark": str(remark)})
                except Exception:
                    pass
            return self.get_record(zone_id, record_id)

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        zone = self._resolve_zone(zone_id)
        if self._mode == "tc3":
            self._tc3_request("DeleteRecord", {"Domain": zone["name"], "DomainId": int(zone_id), "RecordId": int(record_id)})
        else:
            self._token_request("Record.Remove", {"domain_id": zone_id, "record_id": record_id})
        return True

    def set_record_status(self, zone_id: str, record_id: str, enabled: bool) -> bool:
        zone = self._resolve_zone(zone_id)
        if self._mode == "tc3":
            self._tc3_request("ModifyRecordStatus", {
                "Domain": zone["name"], "DomainId": int(zone_id),
                "RecordId": int(record_id), "Status": "ENABLE" if enabled else "DISABLE",
            })
        else:
            self._token_request("Record.Status", {
                "domain_id": zone_id, "record_id": record_id,
                "status": "enable" if enabled else "disable",
            })
        return True

    def get_lines(self, zone_id: str | None = None) -> List[Dict[str, str]]:
        if not zone_id:
            return list(_DEFAULT_LINES)
        zone = self._resolve_zone(zone_id)

        if self._mode == "tc3":
            try:
                resp = self._tc3_request("DescribeRecordLineCategoryList", {"Domain": zone["name"], "DomainId": int(zone_id)})
                line_list = resp.get("LineList") or []
                lines: List[Dict[str, str]] = []
                name_map: Dict[str, str] = {}
                seen_codes: set[str] = set()
                for item in (line_list if isinstance(line_list, list) else []):
                    if not isinstance(item, dict) or item.get("Useful") is False:
                        continue
                    lid = str(item.get("LineId") or "")
                    lname = str(item.get("LineName") or "")
                    code = self._from_line_id(lid) if lid else self._from_line_name(lname)
                    display = _GENERIC_TO_DNSPOD_LINE.get(code, lname)
                    if code not in seen_codes:
                        lines.append({"code": code, "name": display})
                        seen_codes.add(code)
                    name_map[code] = lname
                    for sub in (item.get("SubGroup") or [] if isinstance(item.get("SubGroup"), list) else []):
                        if not isinstance(sub, dict) or sub.get("Useful") is False:
                            continue
                        sid = str(sub.get("LineId") or "")
                        sname = str(sub.get("LineName") or "")
                        scode = self._from_line_id(sid) if sid else self._from_line_name(sname)
                        sdisplay = _GENERIC_TO_DNSPOD_LINE.get(scode, sname)
                        if scode not in seen_codes:
                            lines.append({"code": scode, "name": sdisplay})
                            seen_codes.add(scode)
                        name_map[scode] = sname
                self._line_name_map[zone_id] = name_map
                if not lines:
                    return list(_DEFAULT_LINES)
                seen = {l["code"] for l in lines}
                for dl in _DEFAULT_LINES:
                    if dl["code"] not in seen:
                        name_map[dl["code"]] = _GENERIC_TO_DNSPOD_LINE.get(dl["code"], dl["name"])
                return lines
            except Exception:
                return list(_DEFAULT_LINES)
        else:
            try:
                grade = "DP_Free"
                meta = self._zone_meta.get(zone_id)
                if meta:
                    grade = str(meta.get("grade") or "DP_Free")
                resp = self._token_request("Record.Line", {"domain_id": zone_id, "domain_grade": grade})
                line_ids = resp.get("line_ids", {}) if isinstance(resp, dict) else {}
                lines = []
                id_map: Dict[str, str] = {}
                if isinstance(line_ids, dict):
                    for name_key, id_val in line_ids.items():
                        lid = str(id_val or "")
                        code = self._from_line_id(lid) if lid else self._from_line_name(name_key)
                        if any(l["code"] == code for l in lines):
                            id_map[code] = lid
                            continue
                        display = _GENERIC_TO_DNSPOD_LINE.get(code, name_key)
                        lines.append({"code": code, "name": display})
                        id_map[code] = lid
                self._line_id_map[zone_id] = id_map
                if not any(l["code"] == "default" for l in lines):
                    lines.insert(0, {"code": "default", "name": "\u9ed8\u8ba4"})
                    id_map["default"] = "0"
                return lines if lines else list(_DEFAULT_LINES)
            except Exception:
                return list(_DEFAULT_LINES)

    def get_min_ttl(self, zone_id: str | None = None) -> int:
        if not zone_id:
            return 600
        if self._mode == "tc3":
            try:
                zone = self._resolve_zone(zone_id)
                resp = self._tc3_request("DescribeDomainPurview", {"Domain": zone["name"], "DomainId": int(zone_id)})
                for item in (resp.get("PurviewList") or [] if isinstance(resp.get("PurviewList"), list) else []):
                    if not isinstance(item, dict):
                        continue
                    pname = str(item.get("Name") or "")
                    if "TTL" in pname and ("\u6700\u4f4e" in pname or "Min" in pname):
                        try:
                            v = int(item.get("Value"))
                            if v > 0:
                                return v
                        except (ValueError, TypeError):
                            pass
                return 600
            except Exception:
                return 600
        else:
            meta = self._zone_meta.get(str(zone_id or ""))
            if meta and meta.get("ttl") is not None:
                try:
                    v = int(meta["ttl"])
                    if v > 0:
                        return v
                except (ValueError, TypeError):
                    pass
            try:
                self._resolve_zone(zone_id)
                meta = self._zone_meta.get(str(zone_id or ""))
                if meta and meta.get("ttl") is not None:
                    v = int(meta["ttl"])
                    if v > 0:
                        return v
            except Exception:
                pass
            return 600
