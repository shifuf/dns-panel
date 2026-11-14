"""七牛云 CDN SSL 证书管理 API（官方文档 developer.qiniu.com/fusion/13368）。

证书仓库接口走 fusion.qiniuapi.com；CDN 域名绑定走 api.qiniu.com。
证书接口使用 QBox 路径签名；域名接口使用 Qiniu 请求内容签名。
官方规范：https://developer.qiniu.com/fusion/13360/fusion-api-auth-guide
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class QiniuApiError(Exception):
    def __init__(self, message: str, status: int = 400, code: Any = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.code = code


def _qbox_sign(secret_key: str, data: bytes) -> str:
    digest = hmac.new(secret_key.encode("utf-8"), data, hashlib.sha1).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def _domain_missing(error: QiniuApiError) -> bool:
    if error.status in (401, 403):
        return False
    return str(error.code) in ("404001", "631302", "631286") or any(
        phrase in str(error).lower()
        for phrase in ("no such domain", "not found", "domain is not exists", "域名不存在", "无此域名")
    )


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
            raw_body = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        url = f"https://{host}{signed_path}"
        req = urllib.request.Request(url, data=raw_body if raw_body else None, method=method.upper())
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if host == self.cdn_host:
            # api.qiniu.com 使用 Qiniu v2，JSON 正文必须与发送字节一致。
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            req.add_header("X-Qiniu-Date", timestamp)
            sign_text = f"{req.method} {signed_path}\nHost: {host}"
            if body is not None:
                sign_text += "\nContent-Type: application/json"
            sign_text += f"\nX-Qiniu-Date: {timestamp}\n\n"
            sign_data = sign_text.encode("utf-8") + raw_body
            auth_scheme = "Qiniu"
        else:
            # fusion.qiniuapi.com 的 QBox 签名不包含 JSON 正文。
            sign_data = signed_path.encode("utf-8") + b"\n"
            auth_scheme = "QBox"
        token = self.access_key + ":" + _qbox_sign(self.secret_key, sign_data)
        req.add_header("Authorization", auth_scheme + " " + token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as ex:
            error_body = ex.read().decode("utf-8", errors="replace")
            detail = error_body or str(ex)
            code = None
            try:
                payload = json.loads(error_body)
                if isinstance(payload, dict):
                    detail = str(payload.get("error") or payload)
                    code = payload.get("code")
            except ValueError:
                pass
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
        marker = ""
        for _ in range(50):
            query: Dict[str, Any] = {"limit": max(1, min(int(limit or 100), 500))}
            if marker:
                query["marker"] = marker
            data = self._request(
                self.cdn_host, "GET", "/domain", None, query,
            )
            batch = data.get("domains") or []
            domains.extend(batch if isinstance(batch, list) else [])
            marker = str(data.get("marker") or "").strip()
            if not marker or not batch:
                break
        return domains

    def get_domain_httpsconf(self, domain: str) -> Dict[str, Any]:
        domain = str(domain or "").strip().rstrip(".").lower()
        if not domain:
            raise QiniuApiError("缺少域名", 400)
        # HTTPS 配置包含于域名详情；/httpsconf 只支持 PUT 修改。
        try:
            # 七牛在验签前处理转义字符；通配符必须按原样发送和签名。
            return self._request(self.cdn_host, "GET", f"/domain/{urllib.parse.quote(domain, safe='*')}")
        except QiniuApiError as exc:
            if _domain_missing(exc):
                raise QiniuApiError(
                    f"七牛云账号下未接入 CDN 域名 {domain}；证书覆盖范围不代表已接入的 CDN 域名，请选择该账号已有的目标域名",
                    404, 404001,
                ) from exc
            raise

    def get_binding_status(self, domain: str) -> Dict[str, Any]:
        """查询 CDN 域名当前 HTTPS 配置（实时状态）。"""
        domain = str(domain or "").strip().rstrip(".").lower()
        if not domain:
            raise QiniuApiError("缺少域名", 400)
        try:
            conf = self.get_domain_httpsconf(domain)
        except QiniuApiError as exc:
            # 域名不存在/不在账号下 → 未绑定（不视为检查失败）。
            if _domain_missing(exc):
                return {"bound": False, "domainExists": False, "error": str(exc)}
            raise
        https = conf.get("https") if isinstance(conf, dict) else None
        if isinstance(https, dict):
            cert_id = str(https.get("certid") or https.get("certId") or "")
            return {
                "bound": conf.get("protocol") == "https" and bool(cert_id),
                "domainExists": True,
                "certificateId": cert_id,
                "forceHttps": bool(https.get("forceHttps")),
                "raw": conf,
            }
        return {"bound": False, "domainExists": True, "raw": conf}

    def bind_domain(self, domain: str, cert_id: str, force_https: Optional[bool] = None) -> Dict[str, Any]:
        domain = str(domain or "").strip().rstrip(".").lower()
        cert_id = str(cert_id or "").strip()
        if not domain or not cert_id:
            raise QiniuApiError("绑定证书需要域名与证书 ID", 400)
        conf = self.get_domain_httpsconf(domain)
        https = conf.get("https") if isinstance(conf.get("https"), dict) else {}
        if force_https is None:
            # 自动续期只换证书，保留已有的强制 HTTPS 设置。
            force_https = bool(https.get("forceHttps"))
        payload = {"certId": cert_id, "forceHttps": bool(force_https)}
        action = "httpsconf"
        if conf.get("protocol") == "http":
            # 首次开启 HTTPS 与更换已有 HTTPS 证书使用不同接口。
            action = "sslize"
            payload["http2Enable"] = bool(https.get("http2Enable"))
        return self._request(
            self.cdn_host, "PUT", f"/domain/{urllib.parse.quote(domain, safe='*')}/{action}", payload,
        )
