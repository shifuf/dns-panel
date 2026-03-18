from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List


class CloudflareApiError(Exception):
    def __init__(self, message: str, status: int = 400, errors: List[Dict[str, Any]] | None = None) -> None:
        super().__init__(message)
        self.status = int(status)
        self.errors = errors or []


class CloudflareApi:
    def __init__(self, api_token: str) -> None:
        token = str(api_token or "").strip().replace("\r", "").replace("\n", "")
        if not token:
            raise CloudflareApiError("缺少 Cloudflare API Token", 400)
        self.api_token = token
        self.base = "https://api.cloudflare.com/client/v4"

    def _request(self, method: str, path: str, query: Dict[str, Any] | None = None, body: Dict[str, Any] | None = None) -> Any:
        qp: Dict[str, str] = {}
        for k, v in (query or {}).items():
            if v is None or v == "":
                continue
            qp[str(k)] = str(v)
        url = f"{self.base}{path}"
        if qp:
            url += "?" + urllib.parse.urlencode(qp, doseq=True)

        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            url,
            method=method.upper(),
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "User-Agent": "dns-panel-python-v2/1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                payload = json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="ignore") if e.fp else ""
            payload = {}
            try:
                payload = json.loads(raw) if raw else {}
            except Exception:
                pass
            errors = payload.get("errors") if isinstance(payload, dict) and isinstance(payload.get("errors"), list) else []
            msg = ""
            if errors and isinstance(errors[0], dict):
                msg = str(errors[0].get("message") or "").strip()
            if not msg:
                msg = str(payload.get("message") or e.reason or "Cloudflare API 请求失败")
            raise CloudflareApiError(msg, int(e.code or 400), errors)
        except Exception as e:
            raise CloudflareApiError(f"Cloudflare 网络请求失败: {e}", 503)

        if not isinstance(payload, dict):
            raise CloudflareApiError("Cloudflare 返回格式错误", 502)

        success = payload.get("success")
        if success is False:
            errors = payload.get("errors") if isinstance(payload.get("errors"), list) else []
            msg = ""
            if errors and isinstance(errors[0], dict):
                msg = str(errors[0].get("message") or "").strip()
            if not msg:
                msg = str(payload.get("message") or "Cloudflare API 错误")
            raise CloudflareApiError(msg, 400, errors)

        return payload.get("result")

    def verify_token(self) -> bool:
        try:
            self._request("GET", "/zones", {"per_page": 1})
            return True
        except Exception:
            return False

    def list_accounts(self) -> List[Dict[str, Any]]:
        result = self._request("GET", "/accounts", {"per_page": 50})
        if not isinstance(result, list):
            return []
        out = []
        for row in result:
            if not isinstance(row, dict):
                continue
            aid = str(row.get("id") or "").strip()
            if not aid:
                continue
            out.append({"id": aid, "name": row.get("name")})
        return out

    def get_default_account_id(self) -> str:
        accounts = self.list_accounts()
        if accounts:
            return str(accounts[0].get("id") or "")
        zones = self._request("GET", "/zones", {"per_page": 1})
        if isinstance(zones, list) and zones:
            account = zones[0].get("account") if isinstance(zones[0], dict) else {}
            if isinstance(account, dict):
                return str(account.get("id") or "")
        return ""

    def get_zone_by_name(self, domain: str, account_id: str | None = None) -> Dict[str, Any] | None:
        q: Dict[str, Any] = {"name": str(domain or "").strip(), "per_page": 1}
        if account_id:
            q["account.id"] = str(account_id).strip()
        res = self._request("GET", "/zones", q)
        if isinstance(res, list) and res:
            return res[0]
        return None

    def list_zones(self, page: int = 1, page_size: int = 20, keyword: str | None = None) -> Dict[str, Any]:
        q: Dict[str, Any] = {"page": int(page), "per_page": int(page_size)}
        if keyword:
            q["name"] = keyword
        result = self._request("GET", "/zones", q)
        zones = result if isinstance(result, list) else []
        return {"zones": zones, "total": len(zones)}

    def get_zone(self, zone_id: str) -> Dict[str, Any]:
        result = self._request("GET", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}")
        if not isinstance(result, dict):
            raise CloudflareApiError("获取域名详情失败", 502)
        return result

    def create_zone(self, domain: str, account_id: str) -> Dict[str, Any]:
        payload = {
            "name": str(domain or "").strip(),
            "type": "full",
            "account": {"id": str(account_id or "").strip()},
        }
        result = self._request("POST", "/zones", body=payload)
        if not isinstance(result, dict):
            raise CloudflareApiError("创建域名失败", 502)
        return result

    def delete_zone(self, zone_id: str) -> bool:
        self._request("DELETE", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}")
        return True

    def list_records(self, zone_id: str, page: int = 1, page_size: int = 100, filters: Dict[str, Any] | None = None) -> Dict[str, Any]:
        q: Dict[str, Any] = {"page": int(page), "per_page": int(page_size)}
        for k, v in (filters or {}).items():
            if v is None or v == "":
                continue
            q[str(k)] = v
        res = self._request("GET", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/dns_records", q)
        rows = res if isinstance(res, list) else []
        return {"records": rows, "total": len(rows)}

    def get_record(self, zone_id: str, record_id: str) -> Dict[str, Any]:
        result = self._request(
            "GET",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/dns_records/{urllib.parse.quote(str(record_id or '').strip())}",
        )
        if not isinstance(result, dict):
            raise CloudflareApiError("获取记录失败", 502)
        return result

    def create_record(self, zone_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        result = self._request("POST", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/dns_records", body=payload)
        if not isinstance(result, dict):
            raise CloudflareApiError("创建记录失败", 502)
        return result

    def update_record(self, zone_id: str, record_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        result = self._request(
            "PUT",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/dns_records/{urllib.parse.quote(str(record_id or '').strip())}",
            body=payload,
        )
        if not isinstance(result, dict):
            raise CloudflareApiError("更新记录失败", 502)
        return result

    def delete_record(self, zone_id: str, record_id: str) -> bool:
        self._request(
            "DELETE",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/dns_records/{urllib.parse.quote(str(record_id or '').strip())}",
        )
        return True

    def list_custom_hostnames(self, zone_id: str) -> List[Dict[str, Any]]:
        res = self._request("GET", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames")
        return res if isinstance(res, list) else []

    def create_custom_hostname(self, zone_id: str, hostname: str, custom_origin_server: str | None = None) -> Dict[str, Any]:
        body: Dict[str, Any] = {"hostname": str(hostname or "").strip(), "ssl": {"method": "http", "type": "dv"}}
        if custom_origin_server:
            body["custom_origin_server"] = str(custom_origin_server).strip()
        res = self._request("POST", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames", body=body)
        if not isinstance(res, dict):
            raise CloudflareApiError("创建自定义主机名失败", 502)
        return res

    def delete_custom_hostname(self, zone_id: str, hostname_id: str) -> bool:
        self._request(
            "DELETE",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames/{urllib.parse.quote(str(hostname_id or '').strip())}",
        )
        return True

    def get_fallback_origin(self, zone_id: str) -> str:
        try:
            res = self._request("GET", f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames/fallback_origin")
        except Exception:
            return ""
        if isinstance(res, dict):
            return str(res.get("origin") or "")
        return ""

    def update_fallback_origin(self, zone_id: str, origin: str) -> str:
        res = self._request(
            "PUT",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames/fallback_origin",
            body={"origin": str(origin or "").strip()},
        )
        if isinstance(res, dict):
            return str(res.get("origin") or "")
        return str(origin or "")

    def list_tunnels(self, account_id: str, page: int = 1, page_size: int = 50) -> List[Dict[str, Any]]:
        res = self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel",
            {"page": int(page), "per_page": int(page_size)},
        )
        if isinstance(res, list):
            return res
        if isinstance(res, dict) and isinstance(res.get("items"), list):
            return res.get("items")
        return []

    def create_tunnel(self, account_id: str, name: str) -> Dict[str, Any]:
        secret = base64.b64encode(os.urandom(32)).decode("ascii")
        res = self._request(
            "POST",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel",
            body={"name": str(name or "").strip(), "tunnel_secret": secret},
        )
        if not isinstance(res, dict):
            raise CloudflareApiError("创建 Tunnel 失败", 502)
        return res

    def delete_tunnel(self, account_id: str, tunnel_id: str) -> bool:
        self._request(
            "DELETE",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel/{urllib.parse.quote(str(tunnel_id or '').strip())}",
        )
        return True

    def get_tunnel_token(self, account_id: str, tunnel_id: str) -> str:
        res = self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel/{urllib.parse.quote(str(tunnel_id or '').strip())}/token",
        )
        if isinstance(res, str):
            return res
        if isinstance(res, dict):
            return str(res.get("token") or json.dumps(res, ensure_ascii=False))
        return str(res or "")

    def get_tunnel_config(self, account_id: str, tunnel_id: str) -> Any:
        return self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel/{urllib.parse.quote(str(tunnel_id or '').strip())}/configurations",
        )

    def update_tunnel_config(self, account_id: str, tunnel_id: str, config: Dict[str, Any]) -> Any:
        return self._request(
            "PUT",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel/{urllib.parse.quote(str(tunnel_id or '').strip())}/configurations",
            body={"config": config},
        )

    def list_cidr_routes(self, account_id: str, tunnel_id: str | None = None, page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"page": int(page), "per_page": int(page_size), "is_deleted": "false"}
        if tunnel_id:
            query["tunnel_id"] = str(tunnel_id)
        res = self._request("GET", f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/teamnet/routes", query)
        if isinstance(res, list):
            return res
        if isinstance(res, dict):
            for key in ("result", "routes", "items"):
                val = res.get(key)
                if isinstance(val, list):
                    return val
        return []

    def create_cidr_route(self, account_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        res = self._request("POST", f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/teamnet/routes", body=payload)
        if not isinstance(res, dict):
            raise CloudflareApiError("创建 CIDR 路由失败", 502)
        return res

    def delete_cidr_route(self, account_id: str, route_id: str) -> bool:
        self._request("DELETE", f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/teamnet/routes/{urllib.parse.quote(str(route_id or '').strip())}")
        return True

    def list_hostname_routes(self, account_id: str, tunnel_id: str | None = None, page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        query: Dict[str, Any] = {"page": int(page), "per_page": int(page_size)}
        if tunnel_id:
            query["tunnel_id"] = str(tunnel_id)
        res = self._request("GET", f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/zerotrust/routes/hostname", query)
        if isinstance(res, list):
            return res
        if isinstance(res, dict):
            for key in ("result", "routes", "items"):
                val = res.get(key)
                if isinstance(val, list):
                    return val
        return []

    def create_hostname_route(self, account_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        res = self._request(
            "POST",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/zerotrust/routes/hostname",
            body=payload,
        )
        if not isinstance(res, dict):
            raise CloudflareApiError("创建主机名路由失败", 502)
        return res

    def delete_hostname_route(self, account_id: str, route_id: str) -> bool:
        self._request(
            "DELETE",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/zerotrust/routes/hostname/{urllib.parse.quote(str(route_id or '').strip())}",
        )
        return True

    @staticmethod
    def normalize_hostname(value: Any) -> str:
        return str(value or "").strip().rstrip(".").lower()

    def upsert_tunnel_cname_record(self, zone_id: str, hostname: str, tunnel_id: str) -> Dict[str, str]:
        zone = str(zone_id or "").strip()
        host = self.normalize_hostname(hostname)
        tid = str(tunnel_id or "").strip()
        if not zone or not host or not tid:
            raise CloudflareApiError("参数不完整", 400)
        target = f"{tid}.cfargotunnel.com"
        target_norm = target.rstrip(".").lower()

        existing = self.list_records(zone, 1, 100, {"name": host})
        records = existing.get("records") if isinstance(existing, dict) else []
        rows = records if isinstance(records, list) else []
        matches = [r for r in rows if self.normalize_hostname(r.get("name")) == host]
        cnames = [r for r in matches if str(r.get("type") or "").upper() == "CNAME"]
        others = [r for r in matches if str(r.get("type") or "").upper() != "CNAME"]

        if others:
            raise CloudflareApiError("主机名已存在非 CNAME 记录，无法创建 Tunnel CNAME", 400)

        existing_cname = cnames[0] if cnames else None
        if existing_cname:
            content = str(existing_cname.get("content") or "").rstrip(".").lower()
            proxied = existing_cname.get("proxied") is True
            if content == target_norm and proxied:
                return {"action": "unchanged"}
            self.update_record(
                zone,
                str(existing_cname.get("id") or ""),
                {"type": "CNAME", "name": host, "content": target, "proxied": True, "ttl": 1},
            )
            return {"action": "updated"}

        self.create_record(zone, {"type": "CNAME", "name": host, "content": target, "proxied": True, "ttl": 1})
        return {"action": "created"}

    def delete_tunnel_cname_record_if_match(self, zone_id: str, hostname: str, tunnel_id: str) -> Dict[str, bool]:
        zone = str(zone_id or "").strip()
        host = self.normalize_hostname(hostname)
        tid = str(tunnel_id or "").strip()
        if not zone or not host or not tid:
            raise CloudflareApiError("参数不完整", 400)
        target = f"{tid}.cfargotunnel.com".lower()

        existing = self.list_records(zone, 1, 100, {"name": host, "type": "CNAME"})
        rows = existing.get("records") if isinstance(existing, dict) else []
        if not isinstance(rows, list):
            rows = []
        match = None
        for row in rows:
            if self.normalize_hostname(row.get("name")) != host:
                continue
            content = str(row.get("content") or "").rstrip(".").lower()
            if content == target:
                match = row
                break
        if not match:
            return {"deleted": False}
        self.delete_record(zone, str(match.get("id") or ""))
        return {"deleted": True}
