from __future__ import annotations

import json
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

    def _request(
        self,
        method: str,
        path: str,
        query: Dict[str, Any] | None = None,
        body: Dict[str, Any] | None = None,
        include_meta: bool = False,
    ) -> Any:
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

        return payload if include_meta else payload.get("result")

    @staticmethod
    def _extract_total(payload: Any, fallback_rows: List[Any]) -> int:
        if isinstance(payload, dict):
            info = payload.get("result_info")
            if isinstance(info, dict):
                raw_total = info.get("total_count")
                if raw_total is None:
                    raw_total = info.get("count")
                try:
                    return max(0, int(raw_total))
                except Exception:
                    pass
        return len(fallback_rows)

    def verify_token(self) -> bool:
        try:
            self._request("GET", "/zones", {"per_page": 1})
            return True
        except Exception:
            return False

    def list_accounts(self) -> List[Dict[str, Any]]:
        try:
            result = self._list_tunnel_pages("/accounts", {"per_page": 50})
        except CloudflareApiError as exc:
            if exc.status != 403:
                raise
            result = []
        if not result:
            zones = self._list_tunnel_pages("/zones", {"per_page": 50})
            result = [z.get("account") for z in zones if isinstance(z.get("account"), dict)]
        out = []
        seen = set()
        for row in result:
            if not isinstance(row, dict):
                continue
            aid = str(row.get("id") or "").strip()
            if not aid or aid in seen:
                continue
            seen.add(aid)
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

    def _list_tunnel_pages(self, path: str, query: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
        """Read complete account/tunnel collections; never silently truncate."""
        query = dict(query or {})
        page = max(1, int(query.get("page") or 1))
        size = max(1, int(query.get("per_page") or 50))
        rows: List[Dict[str, Any]] = []
        previous = None
        first_page = page
        read_count = 0
        expected_count = None
        total_pages = None
        while True:
            payload = self._request("GET", path, {**query, "page": page, "per_page": size}, include_meta=True)
            batch = payload.get("result") if isinstance(payload, dict) else None
            if isinstance(batch, dict):
                batch = next((batch[k] for k in ("items", "routes", "result") if isinstance(batch.get(k), list)), None)
            if not isinstance(batch, list):
                raise CloudflareApiError("Cloudflare 分页响应格式错误", 502)
            if batch and batch == previous:
                raise CloudflareApiError("Cloudflare 分页未推进，无法取得完整列表", 502)
            rows.extend(r for r in batch if isinstance(r, dict))
            read_count += len(batch)
            info = payload.get("result_info") or {}
            if info.get("total_pages") is not None:
                total_pages = int(info["total_pages"])
            if info.get("total_count") is not None:
                returned_size = int(info.get("per_page") or len(batch) or size)
                expected_count = max(0, int(info["total_count"]) - (first_page - 1) * returned_size)
            if not batch or (total_pages is not None and page >= total_pages):
                if expected_count is not None and read_count < expected_count:
                    raise CloudflareApiError("Cloudflare 返回的列表不完整，请刷新重试", 502)
                break
            if total_pages is None and expected_count is not None and read_count >= expected_count:
                break
            previous = batch
            page += 1
        return rows

    def list_tunnel_zones(self, account_id: str) -> List[Dict[str, Any]]:
        zones = self._list_tunnel_pages("/zones", {"account.id": account_id, "per_page": 50})
        return [z for z in zones if str((z.get("account") or {}).get("id") or "") == account_id]

    def tunnel_dns_records(self, account_id: str, tunnel_id: str) -> List[Dict[str, str]]:
        target = f"{tunnel_id}.cfargotunnel.com".lower()
        matches = []
        for zone in self.list_tunnel_zones(account_id):
            zid = str(zone.get("id") or "")
            records = self._list_tunnel_pages(f"/zones/{urllib.parse.quote(zid)}/dns_records", {"type": "CNAME", "content": target, "per_page": 100})
            for record in records:
                if str(record.get("type") or "").upper() == "CNAME" and self.normalize_hostname(record.get("content")) == target and record.get("id"):
                    matches.append({"zoneId": zid, "id": str(record["id"]), "hostname": str(record.get("name") or "")})
        return matches

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
        payload = self._request("GET", "/zones", q, include_meta=True)
        zones = payload.get("result") if isinstance(payload, dict) and isinstance(payload.get("result"), list) else []
        return {"zones": zones, "total": self._extract_total(payload, zones)}

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
        payload = self._request(
            "GET",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/dns_records",
            q,
            include_meta=True,
        )
        rows = payload.get("result") if isinstance(payload, dict) and isinstance(payload.get("result"), list) else []
        return {"records": rows, "total": self._extract_total(payload, rows)}

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

    def list_all_custom_hostnames(self, zone_id: str, max_pages: int = 10) -> List[Dict[str, Any]]:
        """Paged listing (the bare list endpoint returns only the first page)."""
        out: List[Dict[str, Any]] = []
        page = 1
        while page <= max_pages:
            res = self._request(
                "GET",
                f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames",
                {"page": page, "per_page": 50},
            )
            batch = res if isinstance(res, list) else []
            out.extend(x for x in batch if isinstance(x, dict))
            if len(batch) < 50:
                break
            page += 1
        return out

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

    def update_custom_hostname_custom_certificate(
        self, zone_id: str, hostname_id: str, certificate_pem: str, private_key_pem: str,
    ) -> Dict[str, Any]:
        """Upload a panel-managed certificate onto a custom hostname
        (ssl type=custom), replacing the previous edge certificate."""
        body: Dict[str, Any] = {
            "ssl": {
                "method": "http",
                "type": "custom",
                "custom_certificate": str(certificate_pem or ""),
                "custom_key": str(private_key_pem or ""),
            }
        }
        res = self._request(
            "PATCH",
            f"/zones/{urllib.parse.quote(str(zone_id or '').strip())}/custom_hostnames/{urllib.parse.quote(str(hostname_id or '').strip())}",
            body=body,
        )
        if not isinstance(res, dict):
            raise CloudflareApiError("上传自定义主机名证书失败", 502)
        return res

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
        res = self._list_tunnel_pages(
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel",
            {"page": int(page), "per_page": int(page_size), "is_deleted": "false"},
        )
        return [r for r in res if not r.get("deleted_at")]

    def create_tunnel(self, account_id: str, name: str) -> Dict[str, Any]:
        res = self._request(
            "POST",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel",
            body={"name": str(name or "").strip(), "config_src": "cloudflare"},
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
        token = res.get("token") if isinstance(res, dict) else res
        if isinstance(token, str) and token.strip():
            return token.strip()
        raise CloudflareApiError("Cloudflare 未返回有效的 Tunnel Token", 502)

    def get_tunnel_config(self, account_id: str, tunnel_id: str) -> Any:
        return self._request(
            "GET",
            f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/cfd_tunnel/{urllib.parse.quote(str(tunnel_id or '').strip())}/configurations",
        )

    def require_remote_tunnel(self, account_id: str, tunnel_id: str) -> None:
        tunnel = self._request("GET", f"/accounts/{urllib.parse.quote(account_id)}/cfd_tunnel/{urllib.parse.quote(tunnel_id)}")
        if not isinstance(tunnel, dict):
            raise CloudflareApiError("Tunnel 详情格式错误", 502)
        if tunnel.get("remote_config") is False or tunnel.get("config_src") == "local":
            raise CloudflareApiError("该 Tunnel 由本地配置管理，请在运行 cloudflared 的机器上编辑配置", 400)

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
        res = self._list_tunnel_pages(f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/teamnet/routes", query)
        if isinstance(res, list):
            return [r for r in res if not r.get("deleted_at") and (not tunnel_id or str(r.get("tunnel_id") or "") == str(tunnel_id))]
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
        query: Dict[str, Any] = {"page": int(page), "per_page": int(page_size), "is_deleted": "false"}
        if tunnel_id:
            query["tunnel_id"] = str(tunnel_id)
        res = self._list_tunnel_pages(f"/accounts/{urllib.parse.quote(str(account_id or '').strip())}/zerotrust/routes/hostname", query)
        if isinstance(res, list):
            return [r for r in res if not r.get("deleted_at") and (not tunnel_id or str(r.get("tunnel_id") or "") == str(tunnel_id))]
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
            if content != target_norm:
                raise CloudflareApiError("主机名已指向其他 CNAME，无法覆盖；请先检查现有 DNS 记录", 409)
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
