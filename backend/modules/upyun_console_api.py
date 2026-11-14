"""又拍云 SSL 证书管理（模拟登录控制台通道）。

又拍云没有官方 SSL 证书上传 API（官方文档仅有存储/表单 REST API），
唯一可行方式与 sslmanage 一样：用网站账号+密码登录 console.upyun.com，
再调用控制台内部的 HTTPS 管理接口上传/绑定证书。

这是非官方接口：若又拍云开启验证码 / 两步验证 / 控制台改版，本通道会失败，
失败时会返回明确的错误信息（提示手动到控制台处理）。

接口清单（来自 sslmanage 项目实践）：
  POST /accounts/signin/                 登录（JSON: username/password/from）
  POST /api/https/certificate/           上传证书 {certificate, private_key}
  GET  /api/https/certificate/manager    证书详情 (?certificate_id=)
  POST /api/https/certificate/manager    绑定域名 {certificate_id, domain, https, force_https}
  GET  /api/https/services/manager       查询域名当前证书 (?domain=)
  POST /api/https/migrate/certificate    把旧证书的域名整体迁移到新证书
"""
from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


class UpyunConsoleError(Exception):
    def __init__(self, message: str, status: int = 400, need_manual: bool = False) -> None:
        super().__init__(message)
        self.status = int(status)
        self.need_manual = bool(need_manual)


BASE = "https://console.upyun.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)


class UpyunConsoleApi:
    def __init__(self, username: str, password: str, timeout: int = 20, auto_login: bool = True) -> None:
        self.username = str(username or "").strip()
        self.password = str(password or "")
        self.timeout = int(timeout or 20)
        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._jar))
        self._logged_in = False
        self._domain_cert_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        if auto_login and self.username and self.password:
            self.login()

    # ── low level ────────────────────────────────────────────────
    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                 json_body: Any = None) -> Dict[str, Any]:
        if method.upper() != "GET":
            # 上传、绑定、迁移、解绑（包括写入失败）之后必须重新读取绑定状态。
            self._domain_cert_cache = {}
        url = BASE + path
        if params:
            url += "?" + urllib.parse.urlencode(
                {k: str(v) for k, v in params.items() if v is not None}
            )
        data = None
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": BASE,
            "Referer": BASE + "/",
            "User-Agent": UA,
            "X-Requested-With": "XMLHttpRequest",
        }
        if json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, method=method.upper())
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as ex:
            body_text = ""
            try:
                body_text = ex.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            raise UpyunConsoleError(
                f"又拍云控制台请求失败 (HTTP {ex.code}): {body_text[:300] or ex.reason}",
                int(ex.code or 400),
            ) from ex
        except urllib.error.URLError as ex:
            raise UpyunConsoleError(f"无法连接又拍云控制台: {ex.reason}", 502) from ex
        if not raw.strip():
            return {}
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"_raw": raw}
        if not isinstance(parsed, dict):
            return {"_data": parsed}
        return parsed

    @staticmethod
    def _ok(resp: Dict[str, Any]) -> bool:
        """Console 响应约定（2026 实测）：

        - 成功: data.status 为 true 或 0；或 data.result 存在（dict/list）
        - 失败: data 是 {type, error_code, request, message, ...}（如
          ParseFailedBadCrt / ThisDomianIsNotBelongToYou / InvalidParameter）
        msg.errors 为空数组不代表成功，不能只看它。
        """
        if not isinstance(resp, dict):
            return False
        data = resp.get("data")
        if isinstance(data, dict):
            if data.get("type") or data.get("error_code"):
                return False
            if "status" in data:
                status = data.get("status")
                if isinstance(status, bool):
                    return status
                if isinstance(status, (int, float)):
                    return int(status) == 0
            if "result" in data:
                return True
        if isinstance(data, list):
            return True
        msg = resp.get("msg")
        if isinstance(msg, dict) and isinstance(msg.get("errors"), list) and msg["errors"]:
            return False
        return True

    @staticmethod
    def _error_text(resp: Dict[str, Any]) -> str:
        """只提取真正的错误信息，绝不回显整个响应（内含账号隐私）。"""
        parts: List[str] = []
        data = resp.get("data") if isinstance(resp, dict) else None
        if isinstance(data, dict):
            err_type = str(data.get("type") or "").strip()
            message = str(data.get("message") or "").strip()
            code = str(data.get("error_code") or "").strip()
            if message:
                parts.append(f"{message}（{err_type}/{code}）" if err_type else message)
            elif err_type:
                parts.append(err_type)
        msg = resp.get("msg") if isinstance(resp, dict) else None
        if isinstance(msg, dict):
            errs = msg.get("errors") or []
            if isinstance(errs, list):
                parts.extend(str(e) for e in errs if e)
        if not parts and isinstance(resp, dict) and resp.get("error"):
            parts.append(str(resp.get("error")))
        if not parts:
            # 最后兜底也只返回 data 的摘要键，避免泄露 user 信息。
            return "又拍云返回未知错误"
        return "；".join(parts)

    # ── 登录 ─────────────────────────────────────────────────────
    def login(self) -> None:
        if not self.username or not self.password:
            raise UpyunConsoleError("缺少又拍云登录账号或密码", 400)
        resp = self._request("POST", "/accounts/signin/", json_body={
            "username": self.username,
            "password": self.password,
            "from": "https://www.upyun.com/",
        })
        cookie_names = {c.name for c in self._jar}
        # 登录成功后控制台会种下会话 cookie；验证码 / 2FA 通常返回错误 JSON
        # 或特定提示字段。
        text = json.dumps(resp, ensure_ascii=False)
        lower = text.lower()
        if ("验证码" in text or "captcha" in lower) and not cookie_names:
            raise UpyunConsoleError(
                "又拍云登录需要验证码，面板无法自动登录；请到又拍云控制台手动更新证书",
                409, need_manual=True,
            )
        if ("两步验证" in text or "two_factor" in lower or "totp" in lower) and not cookie_names:
            raise UpyunConsoleError(
                "又拍云账号开启了两步验证，面板无法自动登录；请到又拍云控制台手动更新证书",
                409, need_manual=True,
            )
        if not cookie_names:
            # 无 cookie 且响应无错误结构时按失败处理。
            raise UpyunConsoleError(
                "又拍云登录失败（未获得会话），请检查账号密码或到控制台手动处理",
                401, need_manual=True,
            )
        self._logged_in = True

    def _ensure_login(self) -> None:
        if not self._logged_in:
            self.login()

    # ── 证书上传 / 查询 / 绑定 ───────────────────────────────────
    @staticmethod
    def validate_pem_pair(ca_pem: str, private_pem: str) -> None:
        """上传前本地校验 PEM 配对，避免 21703 ParseFailedBadCrt 之类模糊报错。

        要求：至少一段 CERTIFICATE、一段私钥（RSA/EC/PKCS8）、私钥模数与证书
        公钥一致（用 cryptography 做真实配对校验）。
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
        except ImportError:
            return  # 环境缺库时跳过本地校验，交给云端报错
        cert_blocks = ca_pem.count("-----BEGIN CERTIFICATE-----")
        if cert_blocks < 1:
            raise UpyunConsoleError("证书内容无效：未找到 CERTIFICATE 块（PEM 格式）", 400)
        if "PRIVATE KEY" not in private_pem:
            raise UpyunConsoleError("私钥内容无效：未找到 PRIVATE KEY 块（PEM 格式）", 400)
        try:
            cert = x509.load_pem_x509_certificate(ca_pem.encode("utf-8"))
        except Exception as exc:
            raise UpyunConsoleError(f"证书 PEM 无法解析: {exc}", 400) from exc
        key = None
        try:
            key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
        except Exception as exc:
            raise UpyunConsoleError(f"私钥 PEM 无法解析（可能带密码？）: {exc}", 400) from exc
        cert_pub = cert.public_key()
        try:
            if isinstance(cert_pub, rsa.RSAPublicKey) and isinstance(key, rsa.RSAPrivateKey):
                if cert_pub.public_numbers() != key.public_key().public_numbers():
                    raise UpyunConsoleError("私钥与证书不匹配（模数不一致）", 400)
            elif isinstance(cert_pub, ec.EllipticCurvePublicKey) and isinstance(key, ec.EllipticCurvePrivateKey):
                if cert_pub.public_numbers() != key.public_key().public_numbers():
                    raise UpyunConsoleError("私钥与证书不匹配（曲线点不一致）", 400)
        except UpyunConsoleError:
            raise
        except Exception:
            pass  # 非常规密钥类型时跳过配对校验

    def list_account_domains(self) -> List[Dict[str, Any]]:
        """列出账号下所有 CDN/云服务绑定的域名（含 bucket 名）。"""
        self._ensure_login()
        out: List[Dict[str, Any]] = []
        resp = self._request("GET", "/api/buckets")
        data = resp.get("data") if isinstance(resp, dict) else None
        buckets = data.get("buckets") if isinstance(data, dict) else None
        for bucket in (buckets or []):
            if not isinstance(bucket, dict):
                continue
            bucket_name = str(bucket.get("bucket_name") or "").strip()
            if not bucket_name:
                continue
            resp2 = self._request("GET", "/api/buckets/domains/", params={
                "bucket_name": bucket_name, "page": 1, "limit": 100,
            })
            data2 = resp2.get("data") if isinstance(resp2, dict) else None
            domains = data2.get("domains") if isinstance(data2, dict) else None
            for item in (domains or []):
                if not isinstance(item, dict):
                    continue
                domain = str(item.get("domain") or "").strip().strip(".").lower()
                if not domain or domain.endswith(".test.upcdn.net"):
                    continue  # 跳过又拍云测试域名
                out.append({
                    "domain": domain,
                    "bucket": bucket_name,
                    "status": str(item.get("status") or ""),
                })
        return out

    def upload_cert(self, ca_pem: str, private_pem: str) -> Dict[str, Any]:
        """上传证书到又拍云证书仓库，返回解析出的 certificate_id + 解析信息。"""
        self._ensure_login()
        if not ca_pem.strip() or not private_pem.strip():
            raise UpyunConsoleError("缺少证书公钥或私钥", 400)
        self.validate_pem_pair(ca_pem, private_pem)
        resp = self._request("POST", "/api/https/certificate/", json_body={
            "certificate": ca_pem,
            "private_key": private_pem,
        })
        if not self._ok(resp):
            raise UpyunConsoleError(f"又拍云上传证书失败: {self._error_text(resp)}", 400)
        cert_id = self._extract_cert_id(resp)
        data = resp.get("data") if isinstance(resp, dict) else None
        result = data.get("result") if isinstance(data, dict) else None
        meta: Dict[str, Any] = {}
        if isinstance(result, dict):
            validity = result.get("validity") or {}
            meta = {
                "commonName": result.get("commonName") or "",
                "san": ((result.get("san") or {}).get("dns") or []) if isinstance(result.get("san"), dict) else [],
                "notBefore": upyun_validity_ms_to_iso(validity.get("start")) if isinstance(validity, dict) else "",
                "notAfter": upyun_validity_ms_to_iso(validity.get("end")) if isinstance(validity, dict) else "",
            }
        if not cert_id:
            return {"certificateId": "", "raw": {}, "meta": meta}
        return {"certificateId": cert_id, "raw": {}, "meta": meta}

    @staticmethod
    def _extract_cert_id(resp: Dict[str, Any]) -> str:
        candidates: List[Any] = []
        data = resp.get("data") if isinstance(resp, dict) else None
        if isinstance(data, dict):
            candidates.append(data)
        if isinstance(resp, dict):
            candidates.append(resp)
        for obj in candidates:
            for key in ("certificate_id", "certificateId", "cert_id", "id"):
                val = obj.get(key)
                if isinstance(val, (str, int)) and str(val).strip():
                    return str(val).strip()
        return ""

    def get_cert_detail(self, cert_id: str) -> Dict[str, Any]:
        self._ensure_login()
        cert_id = str(cert_id or "").strip()
        if not cert_id:
            raise UpyunConsoleError("缺少证书 ID", 400)
        return self._request("GET", "/api/https/certificate/manager", params={"certificate_id": cert_id})

    def get_domain_cert(self, domain: str) -> Dict[str, Any]:
        """查询域名当前生效/可选证书列表（含 validity 与 certificate_id）。"""
        self._ensure_login()
        domain = str(domain or "").strip().strip(".").lower()
        if not domain:
            raise UpyunConsoleError("缺少域名", 400)
        cached = self._domain_cert_cache.get(domain)
        if cached and time.monotonic() - cached[0] < 2:
            return cached[1]
        resp = self._request("GET", "/api/https/services/manager", params={"domain": domain})
        data = resp.get("data") if isinstance(resp, dict) else None
        if self._ok(resp) and isinstance(data, dict) and isinstance(data.get("result"), list):
            # 上传 ID 兜底查询与紧接着的绑定共用一次结果，避免控制台 21000 限速。
            self._domain_cert_cache[domain] = (time.monotonic(), resp)
        return resp

    def find_cert_id_by_fingerprint_time(self, domain: str, not_after_ms_hint: int = 0) -> str:
        """从域名证书列表里挑出最新一张自定义证书的 ID（用于上传后兜底解析）。"""
        resp = self.get_domain_cert(domain)
        data = resp.get("data") if isinstance(resp, dict) else None
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list) or not result:
            return ""
        def _end(item: Dict[str, Any]) -> int:
            validity = item.get("validity") if isinstance(item, dict) else None
            end = item.get("end")
            if isinstance(validity, dict) and validity.get("end"):
                end = validity.get("end")
            try:
                return int(end or 0)
            except (TypeError, ValueError):
                return 0
        sorted_items = sorted((i for i in result if isinstance(i, dict)), key=_end, reverse=True)
        if not sorted_items:
            return ""
        best = sorted_items[0]
        if not_after_ms_hint and _end(best) and abs(_end(best) - int(not_after_ms_hint)) > 90_000:
            return ""
        return str(best.get("certificate_id") or "").strip()

    def bind_domain(self, domain: str, cert_id: str, https: bool = True,
                    force_https: bool = False) -> Dict[str, Any]:
        self._ensure_login()
        domain = str(domain or "").strip().strip(".").lower()
        cert_id = str(cert_id or "").strip()
        if not domain or not cert_id:
            raise UpyunConsoleError("绑定证书需要域名与证书 ID", 400)
        if https:
            current = self.get_binding_status(domain)
            if current.get("error"):
                raise UpyunConsoleError(f"又拍云查询绑定失败 ({domain}): {current['error']}", 400)
            if current.get("bound"):
                return self._renew_domain_binding(domain, cert_id, current)
        resp = self._request("POST", "/api/https/certificate/manager", json_body={
            "certificate_id": cert_id,
            "domain": domain,
            "https": bool(https),
            "force_https": bool(force_https),
        })
        if not self._ok(resp):
            data = resp.get("data") if isinstance(resp, dict) else None
            if https and isinstance(data, dict) and (
                str(data.get("error_code")) == "21713"
                or data.get("type") == "YouHaveBindThisDomainsToACertificate"
            ):
                # 查询与写入之间可能已有绑定；重新确认后仍执行相同的迁移保护。
                current = self.get_binding_status(domain)
                if current.get("bound"):
                    return self._renew_domain_binding(domain, cert_id, current)
            raise UpyunConsoleError(f"又拍云绑定证书失败 ({domain}): {self._error_text(resp)}", 400)
        return resp

    def _renew_domain_binding(self, domain: str, cert_id: str,
                              current: Dict[str, Any]) -> Dict[str, Any]:
        old_cert_id = str(current.get("certificateId") or "").strip()
        if old_cert_id == cert_id:
            return {"data": {"status": True}}
        detail = self.get_cert_detail(old_cert_id)
        data = detail.get("data") if isinstance(detail, dict) else None
        domains = data.get("domains") if isinstance(data, dict) else None
        if not self._ok(detail) or not isinstance(domains, list):
            raise UpyunConsoleError(f"无法确认又拍云旧证书绑定域名，未迁移 ({domain})", 409)
        bound_domains = {
            str(item.get("name") or "").strip().strip(".").lower()
            for item in domains if isinstance(item, dict) and item.get("https") is True
        }
        if bound_domains != {domain}:
            raise UpyunConsoleError(
                f"又拍云旧证书并非仅绑定当前域名 ({domain})，需按旧证书批量处理后再换证", 409,
                need_manual=True,
            )
        # 使用整体迁移，不以默认 False 重写原域名的 HTTPS/强制 HTTPS/回源配置。
        ok, resp = self.migrate_cert(old_cert_id, cert_id)
        if not ok:
            raise UpyunConsoleError(f"又拍云迁移证书失败 ({domain}): {self._error_text(resp)}", 400)
        return resp

    def get_binding_status(self, domain: str) -> Dict[str, Any]:
        """查询域名实际绑定的证书（短时复用查询，写操作后刷新）。

        返回 {bound: bool, certificateId, commonName, https, forceHttps,
              notBefore, notAfter, crtType}；未接入/无 HTTPS 时 bound=False。
        """
        self._ensure_login()
        domain = str(domain or "").strip().strip(".").lower()
        if not domain:
            raise UpyunConsoleError("缺少域名", 400)
        resp = self.get_domain_cert(domain)
        data = resp.get("data") if isinstance(resp, dict) else None
        # 域名不属于该账号时 data.type = ThisDomianIsNotBelongToYou
        if isinstance(data, dict) and data.get("type"):
            return {"bound": False, "error": str(data.get("message") or data.get("type"))}
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, list) or not result:
            return {"bound": False, "https": False}
        # services/manager 列的是可选证书，最新有效期并不代表已绑定。
        # 优先使用列表的 https 标记，避免重复请求触发控制台 21000 限速。
        candidates = [item for item in result if isinstance(item, dict) and item.get("certificate_id")]
        active = [item for item in candidates if item.get("https") is True]
        unknown = [item for item in candidates if "https" not in item] if not active else []
        for item in unknown:
            # 兼容不带状态标记的列表，仅此时查询详情中的目标域名配置。
            detail = self.get_cert_detail(str(item["certificate_id"]))
            detail_data = detail.get("data") if isinstance(detail, dict) else None
            domains = detail_data.get("domains") if isinstance(detail_data, dict) else None
            if not self._ok(detail) or not isinstance(domains, list):
                raise UpyunConsoleError(f"无法确认又拍云证书绑定状态 ({domain})", 502)
            for config in domains:
                if (isinstance(config, dict) and config.get("https") is True
                        and str(config.get("name") or "").strip().strip(".").lower() == domain):
                    active.append({**item, "https": True, "force_https": config.get("force_https")})
                    break
        if not active:
            return {"bound": False, "https": False}
        if len(active) != 1:
            raise UpyunConsoleError(f"又拍云返回多个生效证书，无法确认当前绑定 ({domain})", 409)
        best = active[0]
        validity = best.get("validity") or {}
        return {
            "bound": True,
            "certificateId": str(best.get("certificate_id") or ""),
            "commonName": str(best.get("commonName") or ""),
            "https": bool(best.get("https")),
            "forceHttps": bool(best.get("force_https")),
            "crtType": str(best.get("crt_type") or ""),
            "notBefore": upyun_validity_ms_to_iso(validity.get("start")),
            "notAfter": upyun_validity_ms_to_iso(validity.get("end")),
        }

    def migrate_cert(self, old_cert_id: str, new_cert_id: str) -> Tuple[bool, Dict[str, Any]]:
        """把旧证书上绑定的域名整体迁移到新证书（续期替换时使用）。"""
        self._ensure_login()
        old_cert_id = str(old_cert_id or "").strip()
        new_cert_id = str(new_cert_id or "").strip()
        if not old_cert_id or not new_cert_id:
            raise UpyunConsoleError("迁移证书需要新旧证书 ID", 400)
        resp = self._request("POST", "/api/https/migrate/certificate", json_body={
            "old_crt_id": old_cert_id,
            "new_crt_id": new_cert_id,
        })
        msg = resp.get("msg") if isinstance(resp, dict) else None
        errors = msg.get("errors") if isinstance(msg, dict) else None
        ok = isinstance(errors, list) and len(errors) == 0 and self._ok(resp)
        return ok, resp

    def unbind_domain(self, domain: str) -> Dict[str, Any]:
        """关闭某域名的 HTTPS（保留记录用，best-effort）。"""
        self._ensure_login()
        domain = str(domain or "").strip().strip(".")
        if not domain:
            raise UpyunConsoleError("缺少域名", 400)
        resp = self._request("POST", "/api/https/certificate/manager", json_body={
            "domain": domain,
            "https": False,
            "force_https": False,
        })
        if not self._ok(resp):
            raise UpyunConsoleError(f"又拍云关闭 HTTPS 失败 ({domain}): {self._error_text(resp)}", 400)
        return resp


def upyun_validity_ms_to_iso(ms: Any) -> str:
    """又拍云返回的 validity.start/end 是毫秒时间戳 → ISO 字符串。"""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(ms) / 1000)) if ms else ""
    except (TypeError, ValueError):
        return ""
