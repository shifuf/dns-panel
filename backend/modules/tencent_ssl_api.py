from __future__ import annotations

import hashlib
import hmac
import json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
import re


class TencentSslApiError(Exception):
    def __init__(self, message: str, status: int = 400, errors: list | None = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.errors = errors or []


# ── Status mapping: Tencent numeric → generic string ──────────────
# Official enum (DescribeCertificates / Certificates data structure):
#   0 审核中 · 1 已通过(签发) · 2 审核失败 · 3 已过期 · 4 自动添加DNS记录
#   5 企业证书待提交资料 · 6 订单取消中 · 7 已取消 · 8 已提交资料待上传确认函
#   9 证书吊销中 · 10 已吊销 · 11 重颁发中 · 12 待上传吊销确认函
#   13 免费证书待提交资料 · 14 证书已退款 · 15 证书迁移中
# Getting 3 (expired) wrong used to hide genuinely expired certificates from
# the auto-renew scanner, so they were never renewed.
_STATUS_MAP: Dict[int, str] = {
    0: "validating",   # 审核中
    1: "issued",       # 已通过/已签发
    2: "failed",       # 审核失败
    3: "expired",      # 已过期
    4: "validating",   # 自动添加 DNS 记录中
    5: "validating",   # 企业证书，待提交资料
    6: "cancelled",    # 订单取消中
    7: "cancelled",    # 已取消
    8: "applying",     # 已提交资料，待上传确认函
    9: "revoked",      # 证书吊销中
    10: "revoked",     # 已吊销
    11: "applying",    # 重颁发中
    12: "revoked",     # 待上传吊销确认函
    13: "validating",  # 免费证书待提交资料
    14: "cancelled",   # 证书已退款
    15: "applying",    # 证书迁移中
}


def _normalize_status(raw_status: Any) -> str:
    if raw_status is None:
        return "applying"
    try:
        return _STATUS_MAP.get(int(raw_status), "applying")
    except (ValueError, TypeError):
        return "applying"


def parse_certificate_datetime(value: Any) -> Optional[datetime]:
    """Parse Tencent/ISO certificate timestamps into an aware UTC datetime.

    Tencent responses have historically used both ``YYYY-mm-dd HH:MM:SS`` and
    ISO-8601 forms. Never compare those strings lexicographically: doing so
    makes an expiring certificate look expired (or vice versa) around the
    ``T``/space boundary. Naive Tencent timestamps are treated as UTC because
    the API's certificate fields represent an absolute service timestamp.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value).strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        # Tencent occasionally emits a space before an offset.
        raw = re.sub(r"\s+(?=[+-]\d{2}:?\d{2}$)", "", raw)
        dt = None
        for candidate in (raw, raw.replace("/", "-")):
            try:
                dt = datetime.fromisoformat(candidate)
                break
            except ValueError:
                pass
        if dt is None:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d"):
                try:
                    dt = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    pass
        if dt is None:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def certificate_days_remaining(not_after: Any, now: Optional[datetime] = None) -> Optional[int]:
    expires = parse_certificate_datetime(not_after)
    if expires is None:
        return None
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return int((expires - current.astimezone(timezone.utc)).total_seconds() // 86400)


def certificate_is_expired(not_after: Any, now: Optional[datetime] = None) -> bool:
    expires = parse_certificate_datetime(not_after)
    if expires is None:
        return False
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    return expires <= current.astimezone(timezone.utc)


def _format_certificate_datetime(value: Any) -> str:
    parsed = parse_certificate_datetime(value)
    if parsed is None:
        return str(value or "")
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


class TencentSslApi:
    HOST = "ssl.tencentcloudapi.com"
    SERVICE = "ssl"
    VERSION = "2019-12-05"

    def __init__(self, secret_id: str, secret_key: str) -> None:
        self._secret_id = secret_id.strip()
        self._secret_key = secret_key.strip()
        if not self._secret_id or not self._secret_key:
            raise TencentSslApiError("缺少腾讯云 SecretId / SecretKey")

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

        hashed_payload = self._sha256_hex(payload_json)
        canonical = (
            f"POST\n/\n\n"
            f"content-type:{content_type}\n"
            f"host:{self.HOST}\n\n"
            f"content-type;host\n"
            f"{hashed_payload}"
        )

        credential_scope = f"{date}/{self.SERVICE}/tc3_request"
        string_to_sign = (
            f"TC3-HMAC-SHA256\n{timestamp}\n"
            f"{credential_scope}\n"
            f"{self._sha256_hex(canonical)}"
        )

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
            code = str(err_obj.get("Code") or "").strip() if isinstance(err_obj, dict) else ""
            msg = str((err_obj.get("Message") if isinstance(err_obj, dict) else None) or e.reason or "腾讯云 SSL API 请求失败")
            if code and code not in msg:
                msg = f"{code}: {msg}"
            raise TencentSslApiError(msg, int(e.code or 400), errors=[err_obj] if isinstance(err_obj, dict) else None)
        except Exception as e:
            raise TencentSslApiError(f"腾讯云 SSL 网络请求失败: {e}", 503)

        response = result.get("Response", {}) if isinstance(result, dict) else {}
        if not isinstance(response, dict):
            raise TencentSslApiError("腾讯云 SSL 返回格式错误", 502)

        err = response.get("Error")
        if isinstance(err, dict) and err.get("Code"):
            code = str(err.get("Code") or "").strip()
            msg = str(err.get("Message") or code or "腾讯云 SSL API 错误")
            if code and code not in msg:
                msg = f"{code}: {msg}"
            raise TencentSslApiError(msg, 400, errors=[err])

        return response

    # ── Public API ──────────────────────────────────────────────────
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        d = str(domain or "").strip()
        if not d:
            return ""
        d = re.sub(r"^https?://", "", d, flags=re.IGNORECASE)
        d = d.split("/", 1)[0]
        d = d.strip().rstrip(".").lower()
        if not d:
            return ""
        wildcard = d.startswith("*.")
        core = d[2:] if wildcard else d
        core = re.sub(r":\d+$", "", core)
        core = core.strip().rstrip(".").lower()
        try:
            core_idna = core.encode("idna").decode("ascii")
        except Exception:
            core_idna = core
        return ("*." + core_idna) if wildcard else core_idna

    def list_certificates(
        self,
        offset: int = 0,
        limit: int = 20,
        search_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"Offset": offset, "Limit": limit}
        if search_key:
            payload["SearchKey"] = search_key
        resp = self._tc3_request("DescribeCertificates", payload)
        raw_certs = resp.get("Certificates") or []
        total = resp.get("TotalCount", 0)
        certificates: List[Dict[str, Any]] = []
        for c in raw_certs:
            certificates.append(self._normalize_cert(c))
        return {"certificates": certificates, "totalCount": int(total)}

    def get_certificate(self, certificate_id: str) -> Dict[str, Any]:
        resp = self._tc3_request("DescribeCertificateDetail", {"CertificateId": certificate_id})
        return self._normalize_cert_detail(resp)

    def apply_certificate(
        self,
        domain: str,
        dv_auth_method: str = "DNS_AUTO",
        old_certificate_id: Optional[str] = None,
        alias: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_domain = self._normalize_domain(domain)
        if not normalized_domain:
            raise TencentSslApiError("缺少域名", 400)
        payload: Dict[str, Any] = {
            "DvAuthMethod": dv_auth_method,
            "DomainName": normalized_domain,
            "PackageType": "83",  # TrustAsia C1 DV Free
            "ValidityPeriod": "3",
        }
        if old_certificate_id:
            payload["OldCertificateId"] = str(old_certificate_id).strip()
        if alias:
            payload["Alias"] = str(alias).strip()
        resp = self._tc3_request("ApplyCertificate", payload)
        return {"CertificateId": resp.get("CertificateId", "")}

    def complete_certificate(self, certificate_id: str) -> Dict[str, Any]:
        resp = self._tc3_request("CompleteCertificate", {"CertificateId": certificate_id})
        return resp

    def set_auto_renew_flag(self, certificate_id: str, enabled: bool) -> Dict[str, Any]:
        """Toggle Tencent Cloud's own auto-renew flag (SetAutoRenewFlag).

        Note: Tencent only honors this for cloud-issued certificates that are
        still eligible (paid certs / within the allowed window); for free DV
        certs the flag round-trips but renewal is still driven by re-application,
        which is what the panel scheduler does via ApplyCertificate.
        """
        payload = {"CertId": str(certificate_id).strip(), "AutoRenewFlag": 1 if enabled else 0}
        return self._tc3_request("SetAutoRenewFlag", payload)

    def download_certificate(self, certificate_id: str) -> Dict[str, Any]:
        resp = self._tc3_request("DownloadCertificate", {"CertificateId": certificate_id})
        return {
            "Content": resp.get("Content", ""),
            "ContentType": resp.get("ContentType", "application/zip"),
        }

    def upload_certificate(
        self,
        public_key: str,
        private_key: str,
        alias: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "CertificatePublicKey": public_key,
            "CertificatePrivateKey": private_key,
        }
        if alias:
            payload["Alias"] = alias
        resp = self._tc3_request("UploadCertificate", payload)
        return {"CertificateId": resp.get("CertId", "")}

    def delete_certificate(self, certificate_id: str) -> Dict[str, Any]:
        resp = self._tc3_request("DeleteCertificate", {"CertificateId": certificate_id})
        return resp

    # ── Normalization helpers ───────────────────────────────────────

    @staticmethod
    def _normalize_cert(c: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "remoteCertId": c.get("CertificateId", ""),
            "domain": c.get("Domain", ""),
            "alias": c.get("Alias", ""),
            "san": c.get("CertificateExtra", {}).get("DomainNumber") if isinstance(c.get("CertificateExtra"), dict) else None,
            "certType": c.get("CertificateType", ""),
            "productName": c.get("ProductZhName", ""),
            "status": ("expired" if _normalize_status(c.get("Status")) == "issued" and certificate_is_expired(c.get("CertEndTime")) else _normalize_status(c.get("Status"))),
            "statusMsg": c.get("StatusMsg", ""),
            "issuer": c.get("ProductZhName", ""),
            "notBefore": _format_certificate_datetime(c.get("CertBeginTime", "")),
            "notAfter": _format_certificate_datetime(c.get("CertEndTime", "")),
            "daysRemaining": certificate_days_remaining(c.get("CertEndTime", "")),
            "isExpired": certificate_is_expired(c.get("CertEndTime", "")),
            "autoRenew": bool(c.get("AutoRenewFlag") in (1, "1", True)),
            "autoRenewFlag": c.get("AutoRenewFlag"),
            "hostingStatus": c.get("HostingStatus"),
            "isUploaded": c.get("IsUpload", False),
            "remoteCreatedAt": _format_certificate_datetime(c.get("InsertTime", "")),
        }

    @staticmethod
    def _normalize_cert_detail(resp: Dict[str, Any]) -> Dict[str, Any]:
        base = {
            "remoteCertId": resp.get("CertificateId", ""),
            "domain": resp.get("Domain", ""),
            "san": resp.get("SubjectAltName") or [],
            "certType": resp.get("CertificateType", ""),
            "productName": resp.get("ProductZhName", ""),
            "status": ("expired" if _normalize_status(resp.get("Status")) == "issued" and certificate_is_expired(resp.get("CertEndTime")) else _normalize_status(resp.get("Status"))),
            "statusMsg": resp.get("StatusMsg", ""),
            "issuer": resp.get("ProductZhName", ""),
            "notBefore": _format_certificate_datetime(resp.get("CertBeginTime", "")),
            "notAfter": _format_certificate_datetime(resp.get("CertEndTime", "")),
            "daysRemaining": certificate_days_remaining(resp.get("CertEndTime", "")),
            "isExpired": certificate_is_expired(resp.get("CertEndTime", "")),
            "autoRenew": bool(resp.get("AutoRenewFlag") in (1, "1", True)),
            "autoRenewFlag": resp.get("AutoRenewFlag"),
            "hostingStatus": resp.get("HostingStatus"),
            "isUploaded": resp.get("IsUpload", False),
            "remoteCreatedAt": _format_certificate_datetime(resp.get("InsertTime", "")),
        }
        dv_auths = resp.get("DvAuths")
        if isinstance(dv_auths, list):
            base["dvAuths"] = [
                {
                    "domain": d.get("DvAuthDomain", ""),
                    "key": d.get("DvAuthKey", ""),
                    "value": d.get("DvAuthValue", ""),
                    "type": d.get("DvAuthVerifyType", ""),
                }
                for d in dv_auths
            ]
        # DvAuthDetail: single-object form, may contain file verification path
        dv_detail = resp.get("DvAuthDetail")
        if isinstance(dv_detail, dict) and dv_detail.get("DvAuthKey"):
            base["dvAuthDetail"] = {
                "domain": dv_detail.get("DvAuthDomain", ""),
                "key": dv_detail.get("DvAuthKey", ""),
                "value": dv_detail.get("DvAuthValue", ""),
                "type": dv_detail.get("DvAuthVerifyType", ""),
                "path": dv_detail.get("DvAuthPath", ""),
                "subDomain": dv_detail.get("DvAuthKeySubDomain", ""),
            }
            # If dvAuths is empty but dvAuthDetail has data, populate dvAuths from it
            if not base.get("dvAuths"):
                base["dvAuths"] = [{
                    "domain": dv_detail.get("DvAuthDomain", ""),
                    "key": dv_detail.get("DvAuthKey", ""),
                    "value": dv_detail.get("DvAuthValue", ""),
                    "type": dv_detail.get("DvAuthVerifyType", ""),
                }]
        deployed = resp.get("DeployedResources")
        if isinstance(deployed, list):
            base["deployedResources"] = deployed
        return base
