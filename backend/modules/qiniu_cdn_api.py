"""七牛云 CDN SSL 证书管理 API（官方文档 developer.qiniu.com/fusion/13368）。

证书仓库接口走 fusion.qiniuapi.com；CDN 域名绑定走 api.qiniu.com。
鉴权为 QBox 签名：HMAC-SHA1(SecretKey, Path + "\\n" + Body) 后 urlsafe-base64，
Authorization: "QBox <AccessKey>:<Sign>"。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional


class QiniuApiError(Exception):
    def __init__(self, message: str, status: int = 400, code: Any = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.code = code


def _qbox_sign(secret_key: str, data: bytes) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), data, hashlib.sha1).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


class QiniuCdnApi:
    CERT_HOST = "fusion.qiniuapi.com"
    CDN_HOST = "api.qiniu.com"

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        *,
        cert_host: str = "",
        cdn_host: str = "",
        timeout: int = 20,
    ) -> None:
        self.access_key = str(access_key or "").strip()
        self.secret_key = str(secret_key or "").strip()
        self.cert_host = str(cert_host or "").strip() or self.CERT_HOST
        self.cdn_host = str(cdn_host or "").strip() or self.CDN_HOST
        self.timeout = int(timeout or 20)
        if not self.access_key or not self.secret_key:
            raise QiniuApiError("缺少七牛云 AccessKey / SecretKey", 400)

    # ── low level ────────────────────────────────────────────────
    def _request(self, host: str, method: str, path: str, body: Any = None,
                 query: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        qs = ""
        if query:
            qs = "?" + urllib.parse.urlencode(
                {k: v for k, v in query.items() if v is not None}
            )
        # QBox 签名串必须与实际请求行一致：path + query。
        signed_path = path + qs
        raw_body = b""
        if body is not None:
            raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        sign_data = signed_path.encode("utf-8") + b"\n" + raw_body
        token = self.access_key + ":" + _qbox_sign(self.secret_key, sign_data)
        url = f"https://{host}{signed_path}"
        req = urllib.request.Request(url, data=raw_body if raw_body else None, method=method.upper())
        req.add_header("Authorization", "QBox " + token)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as ex:
            detail = ""
            code = None
            try:
                payload = json.loads(ex.read().decode("utf-8", errors="replace"))
                detail = str(payload.get("error") or payload)
                code = payload.get("code")
            except Exception:
                detail = (ex.read().decode("utf-8", errors="replace") if hasattr(ex, "read") else "") or str(ex)
            raise QiniuApiError(f"七牛云 API 错误: {detail or ex}", int(ex.code or 400), code) from ex
        except urllib.error.URLError as ex:
            raise QiniuApiError(f"无法连接七牛云 API: {ex.reason}", 502) from ex
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw)
        except ValueError:
            return {"_raw": raw}
        if isinstance(data, dict):
            # 业务码非 200 视为失败（七牛部分接口 HTTP 200 + {"code": ...}）。
            code = data.get("code")
            if isinstance(code, int) and code not in (200, 200000) and code != 0:
                raise QiniuApiError(f"七牛云 API 错误: {data.get('error') or data}", 400, code)
        return data if isinstance(data, dict) else {"_data": data}

    # ── 证书仓库 ─────────────────────────────────────────────────
    def upload_cert(self, name: str, ca_pem: str, private_pem: str,
                    common_name: str = "") -> Dict[str, Any]:
        if not ca_pem.strip() or not private_pem.strip():
            raise QiniuApiError("缺少证书公钥或私钥", 400)
        payload: Dict[str, Any] = {
            "name": str(name or "").strip() or "dnspanel-cert",
            "ca": ca_pem,
            "pri": private_pem,
        }
        if common_name:
            payload["common_name"] = common_name
        data = self._request(self.cert_host, "POST", "/sslcert", payload)
        cert_id = str(data.get("certID") or data.get("certid") or "").strip()
        if not cert_id:
            raise QiniuApiError("七牛云上传证书未返回 certID", 502, data.get("code"))
        return {"certID": cert_id, "raw": data}

    def list_certs(self, limit: int = 100) -> List[Dict[str, Any]]:
        certs: List[Dict[str, Any]] = []
        marker = ""
        for _ in range(50):
            query: Dict[str, Any] = {"limit": max(1, min(int(limit or 100), 500))}
            if marker:
                query["marker"] = marker
            data = self._request(self.cert_host, "GET", "/sslcert", None, query)
            batch = data.get("certs") or []
            certs.extend(batch if isinstance(batch, list) else [])
            marker = str(data.get("marker") or "").strip()
            if not marker or not batch:
                break
        return certs

    def get_cert(self, cert_id: str) -> Dict[str, Any]:
        cert_id = str(cert_id or "").strip()
        if not cert_id:
            raise QiniuApiError("缺少证书 ID", 400)
        data = self._request(self.cert_host, "GET", f"/sslcert/{urllib.parse.quote(cert_id)}")
        return data.get("cert") if isinstance(data.get("cert"), dict) else data

    def delete_cert(self, cert_id: str) -> None:
        cert_id = str(cert_id or "").strip()
        if not cert_id:
            raise QiniuApiError("缺少证书 ID", 400)
        self._request(self.cert_host, "DELETE", f"/sslcert/{urllib.parse.quote(cert_id)}")

    # ── CDN 域名绑定 ─────────────────────────────────────────────
    def list_domains(self, limit: int = 100) -> List[Dict[str, Any]]:
        domains: List[Dict[str, Any]] = []
        offset = 0
        for _ in range(50):
            data = self._request(
                self.cdn_host, "GET", "/domain", None,
                {"offset": offset, "limit": max(1, min(int(limit or 100), 500))},
            )
            batch = data.get("domains") or []
            domains.extend(batch if isinstance(batch, list) else [])
            if len(batch) < max(1, min(int(limit or 100), 500)):
                break
            offset += len(batch)
        return domains

    def get_domain_httpsconf(self, domain: str) -> Dict[str, Any]:
        domain = str(domain or "").strip().strip(".")
        if not domain:
            raise QiniuApiError("缺少域名", 400)
        return self._request(self.cdn_host, "GET", f"/domain/{urllib.parse.quote(domain, safe='')}/httpsconf")

    def get_binding_status(self, domain: str) -> Dict[str, Any]:
        """查询 CDN 域名当前 HTTPS 配置（实时状态）。"""
        domain = str(domain or "").strip().strip(".")
        if not domain:
            raise QiniuApiError("缺少域名", 400)
        try:
            conf = self.get_domain_httpsconf(domain)
        except QiniuApiError as exc:
            text = str(exc)
            lowered = text.lower()
            # 域名不存在/不在账号下 → 未绑定（不视为检查失败）。
            if any(k in lowered for k in ("no such domain", "not found", "domain is not exists", "forbidden")) or "631302" in text or "631286" in text:
                return {"bound": False, "error": text}
            raise
        https = conf.get("https") if isinstance(conf, dict) else None
        if isinstance(https, dict):
            cert_id = str(https.get("certid") or https.get("certId") or "")
            return {
                "bound": bool(cert_id) or bool(https.get("enable")) or https.get("status") == "on",
                "certificateId": cert_id,
                "forceHttps": bool(https.get("forceHttps") or https.get("http3Enabled")),
                "raw": conf,
            }
        return {"bound": False, "raw": conf}

    def bind_domain(self, domain: str, cert_id: str, force_https: bool = False) -> Dict[str, Any]:
        domain = str(domain or "").strip().strip(".")
        cert_id = str(cert_id or "").strip()
        if not domain or not cert_id:
            raise QiniuApiError("绑定证书需要域名与证书 ID", 400)
        return self._request(
            self.cdn_host, "PUT", f"/domain/{urllib.parse.quote(domain, safe='')}/httpsconf",
            {"certid": cert_id, "forceHttps": bool(force_https)},
        )
