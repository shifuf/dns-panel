#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 - DNS面板SSL证书同步插件
# +-------------------------------------------------------------------
# | 从 DNS 面板系统拉取已签发的 SSL 证书，自动部署到宝塔管理的站点。
# +-------------------------------------------------------------------
import sys
import os
import json
import time
import re
import hashlib
import subprocess

# Set working directory to panel root
os.chdir("/www/server/panel")
sys.path.append("class/")
import public

# Plugin install path
__plugin_path = "/www/server/panel/plugin/dnspanel_ssl/"
__config = None


def _get_config(key=None, force=False):
    """Read plugin config from config.json."""
    global __config
    if not __config or force:
        config_file = __plugin_path + "config.json"
        if not os.path.exists(config_file):
            return None
        f_body = public.ReadFile(config_file)
        if not f_body:
            return None
        try:
            __config = json.loads(f_body)
        except Exception:
            __config = {}
    if key:
        return __config.get(key)
    return __config


def _set_config(key=None, value=None):
    """Write plugin config to config.json."""
    global __config
    if not __config:
        __config = {}
    if key:
        __config[key] = value
    config_file = __plugin_path + "config.json"
    _atomic_write(config_file, json.dumps(__config))
    try:
        os.chmod(config_file, 0o600)
    except Exception:
        pass
    return True


def _safe_site_name(site_name):
    name = str(site_name or "").strip()
    if not name or len(name) > 253 or not re.match(r"^[A-Za-z0-9._-]+$", name) or ".." in name:
        return None
    cert_root = os.path.realpath("/www/server/panel/vhost/cert")
    cert_dir = os.path.realpath(os.path.join(cert_root, name))
    if not cert_dir.startswith(cert_root + os.sep):
        return None
    return name


def _atomic_write(path, content, mode=0o600):
    tmp = path + ".dnspanel.tmp"
    with open(tmp, "wb") as fh:
        raw = content.encode("utf-8") if not isinstance(content, bytes) else content
        fh.write(raw)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path) if hasattr(os, "replace") else os.rename(tmp, path)


def _normalize_string_list(value):
    if isinstance(value, (list, tuple)):
        raw = value
    else:
        text = str(value or "").strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
            raw = parsed if isinstance(parsed, list) else text.split(",")
        except Exception:
            raw = text.split(",")
    result = []
    for item in raw:
        clean = str(item or "").strip()
        if clean and clean not in result:
            result.append(clean)
    return result


def _find_executable(candidates):
    for candidate in candidates:
        if not candidate:
            continue
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            continue
        for directory in os.environ.get("PATH", "").split(os.pathsep):
            path = os.path.join(directory, candidate)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
    return None


def _run_checked(command):
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        if not isinstance(output, str):
            output = output.decode("utf-8", errors="replace")
        return True, output
    except subprocess.CalledProcessError as exc:
        output = exc.output or b""
        if not isinstance(output, str):
            output = output.decode("utf-8", errors="replace")
        return False, output
    except Exception as exc:
        return False, str(exc)


def _validate_pem_pair(public_key, private_key, hostnames=None):
    if "-----BEGIN CERTIFICATE-----" not in public_key or "PRIVATE KEY-----" not in private_key:
        return False, "证书或私钥 PEM 格式无效"
    cert_tmp = "/tmp/dnspanel-cert-" + str(os.getpid()) + ".pem"
    key_tmp = "/tmp/dnspanel-key-" + str(os.getpid()) + ".pem"
    try:
        _atomic_write(cert_tmp, public_key)
        _atomic_write(key_tmp, private_key)
        cert_pub = subprocess.check_output(["openssl", "x509", "-in", cert_tmp, "-pubkey", "-noout"], stderr=subprocess.STDOUT)
        key_pub = subprocess.check_output(["openssl", "pkey", "-in", key_tmp, "-pubout"], stderr=subprocess.STDOUT)
        if hashlib.sha256(cert_pub).digest() != hashlib.sha256(key_pub).digest():
            return False, "证书与私钥不匹配"
        subprocess.check_output(["openssl", "x509", "-in", cert_tmp, "-checkend", "0", "-noout"], stderr=subprocess.STDOUT)
        candidates = [str(h).strip().lstrip("*.") for h in (hostnames or []) if str(h).strip()]
        if candidates:
            covered = False
            for hostname in candidates:
                try:
                    subprocess.check_output(["openssl", "x509", "-in", cert_tmp, "-checkhost", hostname, "-noout"], stderr=subprocess.STDOUT)
                    covered = True
                    break
                except Exception:
                    pass
            if not covered:
                return False, "证书域名与目标站点不匹配"
        return True, ""
    except Exception as e:
        return False, "证书校验失败: " + str(e)
    finally:
        for path in (cert_tmp, key_tmp):
            try:
                os.remove(path)
            except Exception:
                pass


def _http_request(url, method="GET", headers=None, data=None, timeout=30):
    """HTTP request using urllib (compatible with Python 2/3 panel runtime)."""
    try:
        import urllib.request as _urlmod
    except ImportError:
        import urllib2 as _urlmod
    req_headers = headers or {}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
    try:
        try:
            req = _urlmod.Request(url, data=body, headers=req_headers, method=method)
        except TypeError:
            # Older urllib2 has no method kwarg; emulate via get_method.
            req = _urlmod.Request(url, data=body, headers=req_headers)
            req.get_method = lambda: method
        class _NoRedirect(_urlmod.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = _urlmod.build_opener(_NoRedirect())
        resp = opener.open(req, timeout=timeout)
        return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"success": False, "message": str(e)})


def _validate_server_url(value):
    try:
        try:
            from urllib.parse import urlsplit
        except ImportError:
            from urlparse import urlsplit
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = parsed.hostname.lower()
        is_172_private = False
        if host.startswith("172."):
            try:
                is_172_private = 16 <= int(host.split(".")[1]) <= 31
            except Exception:
                pass
        local_http = host in ("127.0.0.1", "localhost", "::1") or host.startswith("10.") or host.startswith("192.168.") or is_172_private
        if parsed.scheme != "https" and not local_http:
            return None
        return str(value).strip().rstrip("/")
    except Exception:
        return None


def _dedup_latest_by_domain(certs):
    """Keep one cert per domain — the one with the MOST remaining validity.

    Tencent accumulates a new cert per (re)application, so a domain can have
    several issued certs. We deploy only the freshest (max notAfter).
    """
    best = {}
    for cert in certs or []:
        domain = (cert.get("domain") or "").strip().lower()
        if not domain:
            continue
        cur = best.get(domain)
        if not cur or (cert.get("notAfter") or "") > (cur.get("notAfter") or ""):
            best[domain] = cert
    return list(best.values())


def _source_label(cert):
    """Human-readable issuance source for the plugin UI.

    The panel tags acme.sh certs with source='letsencrypt' / provider='acme';
    everything else is a Tencent-issued or uploaded cert.
    """
    src = str(cert.get("source") or "").strip().lower()
    provider = str(cert.get("provider") or "").strip().lower()
    if src == "letsencrypt" or provider == "acme":
        return "Let's Encrypt"
    if cert.get("isUploaded"):
        return "上传证书"
    return "腾讯云"


def _auto_renew_label(cert):
    """Auto-renew status text. acme certs carry autoRenew + lastRenewedAt;
    Tencent certs renew via the panel's global scheduler (shown as '面板托管')."""
    provider = str(cert.get("provider") or "").strip().lower()
    if provider == "acme":
        if cert.get("autoRenew"):
            last = str(cert.get("lastRenewedAt") or "").strip()
            return ("自动续期 · 上次 " + last[:10]) if last else "自动续期"
        return "已关闭"
    return "面板托管"


def _panel_api(path):
    """Build full URL to the DNS panel API."""
    base = (_get_config("serverUrl") or "").strip().rstrip("/")
    return base + "/api" + path


def _panel_headers():
    """Authorization headers with the configured API token."""
    token = (_get_config("apiToken") or "").strip()
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


def _to_int(v):
    """Best-effort int coercion for IDs coming from form-encoded args."""
    try:
        return int(str(v).strip())
    except Exception:
        return v


def _panel_get(path, timeout=30):
    """GET a panel API path and return the parsed JSON dict (or an error dict)."""
    raw = _http_request(_panel_api(path), headers=_panel_headers(), timeout=timeout)
    try:
        return json.loads(raw)
    except Exception:
        return {"success": False, "message": "解析响应失败"}


def _panel_post(path, payload=None, timeout=60):
    """POST JSON to a panel API path and return the parsed JSON dict (or error)."""
    raw = _http_request(
        _panel_api(path), method="POST", headers=_panel_headers(),
        data=(payload if payload is not None else {}), timeout=timeout,
    )
    try:
        return json.loads(raw)
    except Exception:
        return {"success": False, "message": "解析响应失败"}


def _list_bt_sites():
    """Return BaoTa sites with bound domains: [{id, name, domains:[...]}].

    Robust across panel versions / site types — merges two sources:
      1) The `sites` DB table (+ bound domains from the `domain` table).
      2) nginx / apache vhost config filenames on disk — the file stem IS the
         site name BaoTa uses for its cert directory, so this works even when
         the DB query returns nothing (e.g. Docker / proxy sites).
    """
    import glob
    sites = {}

    # Source 1: BaoTa database
    try:
        rows = public.M("sites").field("id,name").select()
    except Exception:
        try:
            rows = public.M("sites").select()
        except Exception:
            rows = []
    if isinstance(rows, list):
        for s in rows:
            if not isinstance(s, dict) or not s.get("name"):
                continue
            name = str(s.get("name")).strip()
            entry = sites.setdefault(name, {"id": s.get("id"), "name": name, "domains": set()})
            try:
                doms = public.M("domain").where("pid=?", (s.get("id"),)).field("name").select()
                if isinstance(doms, list):
                    for d in doms:
                        if isinstance(d, dict) and d.get("name"):
                            entry["domains"].add(str(d.get("name")).strip())
            except Exception:
                pass

    # Source 2: vhost config filenames (filesystem fallback)
    _skip = ("0.default", "default", "phpfpm_status")
    for base in ("/www/server/panel/vhost/nginx", "/www/server/panel/vhost/apache"):
        try:
            for f in glob.glob(base + "/*.conf"):
                name = os.path.basename(f)
                if name.endswith(".conf"):
                    name = name[:-5]
                name = name.strip()
                if name and name not in _skip and not name.startswith("ssl."):
                    sites.setdefault(name, {"id": None, "name": name, "domains": set()})
        except Exception:
            pass

    out = []
    for name, s in sites.items():
        out.append({"id": s["id"], "name": name, "domains": sorted(s["domains"])})
    out.sort(key=lambda x: x["name"])
    return out


def _diagnose_sites():
    """Diagnostics shown when no sites are found, to pinpoint the cause."""
    import glob
    info = {}
    try:
        rows = public.M("sites").select()
        info["db_sites_count"] = len(rows) if isinstance(rows, list) else "非列表: " + str(type(rows))
    except Exception as e:
        info["db_sites_error"] = str(e)
    for base, key in (("/www/server/panel/vhost/nginx", "nginx_confs"),
                      ("/www/server/panel/vhost/apache", "apache_confs")):
        try:
            info[key] = [os.path.basename(x) for x in glob.glob(base + "/*.conf")]
        except Exception as e:
            info[key] = "err: " + str(e)
    return info


def _match_site_for_domain(domain, sites):
    """Find the BaoTa site serving `domain`, matching site name OR bound domains."""
    d = (domain or "").strip().lower().lstrip("*.")
    if not d:
        return None
    for s in sites:
        candidates = [str(s.get("name") or "").strip().lower()]
        candidates += [str(x).strip().lower().lstrip("*.") for x in (s.get("domains") or [])]
        for c in candidates:
            if not c:
                continue
            if d == c or d.endswith("." + c) or c.endswith("." + d):
                return s
    return None


def _match_sites_for_domain(domain, sites):
    """Return every BaoTa site that can use the certificate domain."""
    d = (domain or "").strip().lower().lstrip("*.")
    if not d:
        return []
    matched = []
    seen = set()
    for site in sites:
        site_name = str(site.get("name") or "").strip()
        candidates = [site_name.lower()]
        candidates += [str(x).strip().lower().lstrip("*.") for x in (site.get("domains") or [])]
        if any(c and (d == c or d.endswith("." + c) or c.endswith("." + d)) for c in candidates):
            if site_name and site_name not in seen:
                seen.add(site_name)
                matched.append(site)
    return matched


def _cert_deployed(site_name):
    """True if a certificate file already exists in the site's BaoTa cert dir."""
    if not site_name:
        return False
    p = "/www/server/panel/vhost/cert/" + str(site_name) + "/fullchain.pem"
    try:
        return os.path.exists(p) and os.path.getsize(p) > 0
    except Exception:
        return False


class dnspanel_ssl_main:

    def __init__(self):
        pass

    def index(self, args):
        return self.get_overview(args)

    # ── Overview page data ───────────────────────────────────────
    def get_overview(self, args):
        cfg = _get_config() or {}
        server_url = (cfg.get("serverUrl") or "").strip()
        has_token = bool((cfg.get("apiToken") or "").strip())
        auto_sync = cfg.get("autoSync", False)
        last_sync = cfg.get("lastSyncAt", "")

        # Fetch certificate count from the panel
        cert_count = 0
        connection_ok = False
        error_msg = ""
        # The panel's OWN auto-renew scheduler state (the source of truth). We
        # surface it so the plugin never claims "自动续期已开启" while the panel
        # side is actually off (or vice-versa) — this is the "真同步" the user
        # wants: one status, read live from the panel each time.
        panel_renew = None
        if server_url and has_token:
            try:
                data = _panel_get("/ssl/certificates?credentialId=all&page=1&limit=200")
                if data.get("success"):
                    connection_ok = True
                    cert_count = (data.get("pagination") or {}).get("total", 0)
                else:
                    error_msg = data.get("message", "连接失败")
            except Exception as e:
                error_msg = str(e)
            # Read the panel-side auto-renew toggle (best-effort).
            try:
                ar = _panel_get("/ssl/auto-renew")
                if ar.get("success"):
                    d = ar.get("data") or {}
                    panel_renew = {
                        "enabled": bool(d.get("enabled")),
                        "days": int(d.get("days") or 7),
                        "lastRunAt": d.get("lastRunAt") or "",
                        "lastResult": d.get("lastResult") or "",
                    }
            except Exception:
                panel_renew = None

        # Effective auto-renew = panel scheduler OR the local BaoTa cron. When we
        # can read the panel state, it is authoritative; fall back to the local
        # flag only when the panel is unreachable.
        effective_auto = (panel_renew["enabled"] if panel_renew else bool(auto_sync))

        return {
            "configured": bool(server_url and has_token),
            "serverUrl": server_url,
            "autoSync": bool(auto_sync),
            "autoRenew": effective_auto,
            "panelRenew": panel_renew,
            "lastSyncAt": last_sync,
            "connectionOk": connection_ok,
            "certCount": cert_count,
            "error": error_msg,
            "allowedSites": cfg.get("allowedSites") or [],
            "allowedSources": cfg.get("allowedSources") or ["tencent", "letsencrypt"],
            "availableSites": [site.get("name") for site in _list_bt_sites() if site.get("name")],
        }


    # ── Save connection settings ─────────────────────────────────
    def save_config(self, args):
        server_url = _validate_server_url(getattr(args, "serverUrl", ""))
        api_token = str(getattr(args, "apiToken", "") or "").strip()
        auto_sync = getattr(args, "autoSync", False)
        auto_sync = bool(auto_sync) and str(auto_sync) != "false"
        # Optional renew-window (days before expiry). Kept in sync with the panel.
        renew_days_raw = getattr(args, "renewDays", None)
        current_cfg = _get_config() or {}
        allowed_sites_raw = _normalize_string_list(getattr(args, "allowedSites", current_cfg.get("allowedSites") or []))
        allowed_sources_raw = _normalize_string_list(getattr(args, "allowedSources", current_cfg.get("allowedSources") or ["tencent", "letsencrypt"]))
        if not server_url:
            return public.ReturnMsg(False, "服务器地址无效；公网地址必须使用 HTTPS")

        # A blank token means "keep the existing one" (so editing other fields
        # doesn't force re-entering the secret). Require a token on first setup.
        existing_token = (_get_config("apiToken") or "").strip()
        if not api_token and not existing_token:
            return public.ReturnMsg(False, "请填写 API Token")

        known_sites = set(site.get("name") for site in _list_bt_sites() if site.get("name"))
        unsafe_sites = [name for name in allowed_sites_raw if not _safe_site_name(name) or name not in known_sites]
        if unsafe_sites:
            return public.ReturnMsg(False, "部署站点白名单包含不存在或不安全的站点: " + "、".join(unsafe_sites))
        allowed_sources = [source.lower() for source in allowed_sources_raw if source.lower() in ("tencent", "letsencrypt")]
        if not allowed_sources:
            return public.ReturnMsg(False, "至少选择一个允许部署的证书来源")
        _set_config("serverUrl", server_url)
        if api_token:
            _set_config("apiToken", api_token)
        _set_config("autoSync", auto_sync)
        _set_config("allowedSites", allowed_sites_raw)
        _set_config("allowedSources", allowed_sources)

        # 真同步：push the toggle to the panel's OWN auto-renew scheduler so the
        # plugin switch and the panel switch never diverge. When the plugin turns
        # auto-renew ON/OFF, the panel-side scheduler follows; the local BaoTa
        # cron (installed by install.sh) then acts as a redundant trigger.
        panel_synced = None
        try:
            renew_days = None
            if renew_days_raw is not None and str(renew_days_raw).strip() != "":
                try:
                    renew_days = max(1, min(60, int(renew_days_raw)))
                except Exception:
                    renew_days = None
                if renew_days is not None:
                    _set_config("renewDays", renew_days)
            payload = {"enabled": auto_sync}
            if renew_days is not None:
                payload["days"] = renew_days
            ar = _panel_post("/ssl/auto-renew", payload)
            panel_synced = bool(ar.get("success"))
        except Exception:
            panel_synced = None

        public.WriteLog("DNS面板SSL同步", "更新连接配置（自动续期=" + ("开" if auto_sync else "关") + "，面板同步=" + str(panel_synced) + "）")
        msg = "配置已保存"
        if panel_synced is True:
            msg += "，已同步面板自动续期开关"
        elif panel_synced is False:
            msg += "（面板自动续期同步失败，请检查 Token 权限）"
        return public.ReturnMsg(True, msg)

    # ── Toggle auto-renew (真同步: panel scheduler + local cron) ──
    def set_auto_renew(self, args):
        """Flip auto-renew from the overview switch.

        Writes the local flag AND pushes to the panel's own auto-renew
        scheduler so the two switches always agree. Reuses the existing
        renewDays if the caller doesn't supply one."""
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

        enabled_raw = getattr(args, "enabled", False)
        enabled = bool(enabled_raw) and str(enabled_raw) != "false"
        _set_config("autoSync", enabled)

        renew_days = None
        rd_raw = getattr(args, "renewDays", None)
        if rd_raw is not None and str(rd_raw).strip() != "":
            try:
                renew_days = max(1, min(60, int(rd_raw)))
                _set_config("renewDays", renew_days)
            except Exception:
                renew_days = None
        if renew_days is None:
            try:
                renew_days = int(cfg.get("renewDays") or 0) or None
            except Exception:
                renew_days = None

        payload = {"enabled": enabled}
        if renew_days is not None:
            payload["days"] = renew_days
        panel_synced = None
        try:
            ar = _panel_post("/ssl/auto-renew", payload)
            panel_synced = bool(ar.get("success"))
        except Exception:
            panel_synced = None

        public.WriteLog("DNS面板SSL同步", "切换自动续期=" + ("开" if enabled else "关") + "，面板同步=" + str(panel_synced))
        if panel_synced is False:
            return public.ReturnMsg(True, ("已" + ("开启" if enabled else "关闭") + "本机自动续期，但面板同步失败（请检查 Token 权限）"))
        return public.ReturnMsg(True, "自动续期已" + ("开启" if enabled else "关闭") + "（面板 + 本机已同步）")

    # ── List certificates from the DNS panel ─────────────────────
    def get_certificates(self, args):
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return {"success": False, "message": "请先配置连接信息", "data": []}

        keyword = str(getattr(args, "keyword", "") or "").strip()
        path = "/ssl/certificates?credentialId=all&page=1&limit=500"
        if keyword:
            path += "&search=" + keyword
        raw = _http_request(_panel_api(path), headers=_panel_headers())
        try:
            data = json.loads(raw)
        except Exception:
            return {"success": False, "message": "解析响应失败", "data": []}

        if not data.get("success"):
            return {"success": False, "message": data.get("message", "获取失败"), "data": []}

        certs = data.get("data") or []
        # Only deployable certs (issued or uploaded), then keep the freshest one
        # per domain so duplicates from repeated renewals never confuse deploy.
        issued = [c for c in certs if c.get("status") == "issued" or c.get("isUploaded")]
        issued = _dedup_latest_by_domain(issued)
        issued.sort(key=lambda c: (c.get("domain") or ""))
        # Annotate each cert with its matched BaoTa site + deployment status,
        # plus a human-readable issuance source and auto-renew status (the panel
        # returns provider/source/autoRenew/lastRenewedAt on each cert).
        sites = _list_bt_sites()
        for c in issued:
            site = _match_site_for_domain(c.get("domain"), sites)
            c["matchedSite"] = site["name"] if site else ""
            c["deployed"] = _cert_deployed(site["name"]) if site else False
            c["sourceLabel"] = _source_label(c)
            c["autoRenewLabel"] = _auto_renew_label(c)
        return {"success": True, "data": issued, "total": len(issued)}

    # ── List BaoTa sites ─────────────────────────────────────────
    def get_sites(self, args):
        sites = _list_bt_sites()
        if sites:
            return {"success": True, "data": sites}
        return {"success": True, "data": [], "debug": _diagnose_sites()}

    # ── Deploy a certificate to a BaoTa site ─────────────────────
    def deploy(self, args):
        cert_id = str(getattr(args, "certId", "") or "").strip()
        credential_id = str(getattr(args, "credentialId", "") or "").strip()
        site_name = _safe_site_name(getattr(args, "siteName", ""))

        if not cert_id or not site_name:
            return public.ReturnMsg(False, "缺少证书ID或站点名")
        known_site = next((s for s in _list_bt_sites() if s.get("name") == site_name), None)
        if not known_site:
            return public.ReturnMsg(False, "站点不存在或名称不安全")

        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")
        allowed_sites = set(str(x) for x in (cfg.get("allowedSites") or []) if str(x))
        if allowed_sites and site_name not in allowed_sites:
            return public.ReturnMsg(False, "目标站点不在部署白名单")

        # Fetch PEM content
        pem_path = "/ssl/certificates/" + cert_id + "/pem?credentialId=" + credential_id
        raw = _http_request(_panel_api(pem_path), headers=_panel_headers())
        try:
            data = json.loads(raw)
        except Exception:
            return public.ReturnMsg(False, "解析证书响应失败")

        if not data.get("success"):
            return public.ReturnMsg(False, data.get("message", "获取证书内容失败"))

        public_key = (data.get("data") or {}).get("publicKey", "")
        private_key = (data.get("data") or {}).get("privateKey", "")
        if not public_key or not private_key:
            return public.ReturnMsg(False, "证书公钥或私钥为空")
        site_hosts = [site_name] + list(known_site.get("domains") or [])
        valid, validation_error = _validate_pem_pair(public_key, private_key, site_hosts)
        if not valid:
            return public.ReturnMsg(False, validation_error)

        # Write cert files to BaoTa vhost cert directory
        cert_dir = os.path.realpath(os.path.join("/www/server/panel/vhost/cert", site_name))
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        fullchain_path = cert_dir + "/fullchain.pem"
        privkey_path = cert_dir + "/privkey.pem"

        fingerprint = hashlib.sha256((public_key + "\x00" + private_key).encode("utf-8")).hexdigest()
        deployed_fingerprints = cfg.get("deployedFingerprints") or {}
        if deployed_fingerprints.get(site_name) == fingerprint and _cert_deployed(site_name):
            return public.ReturnMsg(True, "证书未变化，无需重复部署")

        backups = {}
        for target in (fullchain_path, privkey_path):
            backups[target] = None
            if os.path.exists(target):
                backup = target + ".dnspanel.bak"
                with open(target, "rb") as src:
                    _atomic_write(backup, src.read())
                backups[target] = backup
        try:
            _atomic_write(fullchain_path, public_key)
            _atomic_write(privkey_path, private_key)
        except Exception as e:
            self._rollback_deploy(backups, None)
            return public.ReturnMsg(False, "证书原子写入失败: " + str(e))

        # For reverse proxy sites, directly modify nginx config
        web_server = str(public.GetWebServer() or "").strip().lower()
        nginx_conf_backup = None
        if web_server in ("nginx", "openresty"):
            try:
                nginx_conf_backup = self._enable_nginx_ssl_for_proxy(site_name, fullchain_path, privkey_path)
            except Exception as e:
                possible_backup = "/www/server/panel/vhost/nginx/" + site_name + ".conf.dnspanel.bak"
                self._rollback_deploy(backups, possible_backup if os.path.exists(possible_backup) else nginx_conf_backup)
                return public.ReturnMsg(False, "更新 Nginx/OpenResty 配置失败，已恢复原证书: " + str(e))

        # Reload web server
        if web_server in ("nginx", "openresty"):
            nginx_bin = _find_executable([
                "/www/server/nginx/sbin/nginx",
                "/www/server/openresty/nginx/sbin/nginx",
                "nginx",
            ])
            if not nginx_bin:
                self._rollback_deploy(backups, nginx_conf_backup)
                return public.ReturnMsg(False, "未找到 Nginx/OpenResty 可执行文件，已恢复原证书和配置")
            test_ok, test_output = _run_checked([nginx_bin, "-t"])
            public.WriteLog("DNS面板SSL同步", "nginx配置测试: " + test_output)
            if test_ok:
                if subprocess.call([nginx_bin, "-s", "reload"]) != 0:
                    self._rollback_deploy(backups, nginx_conf_backup)
                    return public.ReturnMsg(False, "Nginx 重载失败，已恢复原证书和配置")
                public.WriteLog("DNS面板SSL同步", "nginx已重载")
            else:
                public.WriteLog("DNS面板SSL同步", "nginx配置测试失败，未重载")
                self._rollback_deploy(backups, nginx_conf_backup)
                return public.ReturnMsg(False, "Nginx 配置校验失败，已恢复原证书和配置")
        elif web_server == "apache":
            apache_bin = _find_executable([
                "/www/server/apache/bin/httpd",
                "/usr/sbin/httpd",
                "/usr/sbin/apache2ctl",
                "httpd",
                "apachectl",
            ])
            if not apache_bin:
                self._rollback_deploy(backups, None)
                return public.ReturnMsg(False, "未找到 Apache 可执行文件，已恢复原证书")
            test_ok, test_output = _run_checked([apache_bin, "-t"])
            public.WriteLog("DNS面板SSL同步", "apache配置测试: " + test_output)
            if test_ok:
                if subprocess.call([apache_bin, "-k", "graceful"]) != 0:
                    self._rollback_deploy(backups, None)
                    return public.ReturnMsg(False, "Apache 重载失败，已恢复原证书")
            else:
                self._rollback_deploy(backups, None)
                return public.ReturnMsg(False, "Apache 配置校验失败，已恢复原证书")
        else:
            self._rollback_deploy(backups, nginx_conf_backup)
            return public.ReturnMsg(False, "暂不支持当前 Web 服务: " + (web_server or "unknown"))

        # Only mark the site as SSL-enabled after config validation/reload succeeds.
        try:
            import panelMysql as pm
            db = pm.panelMysql().dbfile("/www/server/panel/data/default.db")
            site_info = db.query("SELECT id FROM sites WHERE name=? LIMIT 1", (site_name,))
            if site_info:
                site_id = site_info[0][0]
                db.execute("UPDATE sites SET ssl=1 WHERE id=?", (site_id,))
                public.WriteLog("DNS面板SSL同步", "数据库更新: ssl=1 for site_id=" + str(site_id))
            db.close()
        except Exception as e:
            public.WriteLog("DNS面板SSL同步", "数据库操作: " + str(e))

        deployed_fingerprints[site_name] = fingerprint
        _set_config("deployedFingerprints", deployed_fingerprints)
        for backup in backups.values():
            if backup:
                try:
                    os.remove(backup)
                except Exception:
                    pass
        if nginx_conf_backup:
            try:
                os.remove(nginx_conf_backup)
            except Exception:
                pass

        public.WriteLog("DNS面板SSL同步", "部署证书到站点 " + site_name + " (certId=" + cert_id + ")")
        return public.ReturnMsg(True, "证书已部署并启用SSL，请刷新页面查看")

    def _rollback_deploy(self, backups, nginx_conf_backup):
        for target, backup in backups.items():
            try:
                if backup and os.path.exists(backup):
                    os.replace(backup, target) if hasattr(os, "replace") else os.rename(backup, target)
                elif not backup and os.path.exists(target):
                    os.remove(target)
            except Exception:
                pass
        if nginx_conf_backup:
            try:
                target = nginx_conf_backup[:-len(".dnspanel.bak")]
                os.replace(nginx_conf_backup, target) if hasattr(os, "replace") else os.rename(nginx_conf_backup, target)
            except Exception:
                pass

    def _enable_nginx_ssl_for_proxy(self, site_name, cert_path, key_path):
        """Enable SSL for nginx reverse proxy site by modifying config."""
        conf_path = "/www/server/panel/vhost/nginx/" + site_name + ".conf"
        if not os.path.exists(conf_path):
            public.WriteLog("DNS面板SSL同步", "配置文件不存在: " + conf_path)
            return None

        conf_content = public.ReadFile(conf_path)
        if not conf_content:
            public.WriteLog("DNS面板SSL同步", "无法读取配置文件: " + conf_path)
            return None

        conf_backup = conf_path + ".dnspanel.bak"
        _atomic_write(conf_backup, conf_content)

        public.WriteLog("DNS面板SSL同步", "开始修改nginx配置: " + site_name)

        # Check if SSL is already configured
        has_ssl = "listen 443 ssl" in conf_content
        has_cert = "ssl_certificate " in conf_content

        if has_ssl and has_cert:
            # Update existing certificate paths
            import re
            conf_content = re.sub(
                r'ssl_certificate\s+[^;]+;',
                'ssl_certificate    ' + cert_path + ';',
                conf_content
            )
            conf_content = re.sub(
                r'ssl_certificate_key\s+[^;]+;',
                'ssl_certificate_key    ' + key_path + ';',
                conf_content
            )
            public.WriteLog("DNS面板SSL同步", "已更新SSL证书路径")
        else:
            # Need to add SSL configuration
            # Find server_name directive to identify the server block
            lines = conf_content.split('\n')
            in_http_server = False
            http_server_start = -1
            brace_count = 0

            for i, line in enumerate(lines):
                stripped = line.strip()

                # Detect HTTP server block (listen 80)
                if 'server' in stripped and '{' in stripped:
                    in_http_server = True
                    http_server_start = i
                    brace_count = stripped.count('{') - stripped.count('}')
                elif in_http_server:
                    brace_count += stripped.count('{') - stripped.count('}')

                    # End of HTTP server block
                    if brace_count == 0:
                        # Insert HTTPS redirect before the closing brace
                        indent = '    '
                        redirect_line = indent + 'if ($server_port !~ 443){ return 301 https://$host$request_uri; }'
                        if redirect_line.strip() not in conf_content:
                            lines.insert(i, redirect_line)
                            public.WriteLog("DNS面板SSL同步", "已添加HTTPS跳转规则到HTTP块")
                        break

            # Now add HTTPS server block at the end
            # Extract server_name from the original config
            server_name_match = None
            import re
            match = re.search(r'server_name\s+([^;]+);', conf_content)
            if match:
                server_name_match = match.group(1).strip()

            # Build HTTPS server block
            https_block = '''
# HTTPS server block (auto-generated by DNS Panel SSL plugin)
server {
    listen 443 ssl http2;
    server_name ''' + (server_name_match or '~^') + ''';

    # SSL Certificate
    ssl_certificate    ''' + cert_path + ''';
    ssl_certificate_key    ''' + key_path + ''';
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
'''

            # Copy location blocks from HTTP server
            location_blocks = re.findall(r'(location\s+[^{]+\{[^}]*\})', conf_content, re.DOTALL)
            for loc in location_blocks:
                https_block += '\n    ' + loc + '\n'

            https_block += '}\n'

            lines = ('\n'.join(lines) + https_block).split('\n')
            public.WriteLog("DNS面板SSL同步", "已添加HTTPS server块")

        # Write back the modified config
        new_content = '\n'.join(lines)
        _atomic_write(conf_path, new_content)
        public.WriteLog("DNS面板SSL同步", "nginx配置已更新: " + conf_path)
        return conf_backup

    # ── Issuance: options + apply ────────────────────────────────
    def get_issue_options(self, args):
        """List credentials the panel exposes for issuing certificates.

        Two independent channels, mirroring the panel's own SSL page:
          • acme (Let's Encrypt): needs a DNS credential (cloudflare / dnspod /
            aliyun) — acme.sh drives DNS-01 itself. Only offered when the panel
            reports acme is available (Docker deploy).
          • tencent: a腾讯云 SSL credential申请免费 DV，面板自动加 DNS 验证记录。
        The DNS-01 automation + validation-record handling all happen server-
        side, so issuance here is 100% consistent with issuing on the panel.
        """
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return {"success": False, "message": "请先配置连接信息"}

        # DNS credentials usable by acme.sh (cloudflare / dnspod / aliyun).
        acme_supported = ("cloudflare", "dnspod", "dnspod_token", "aliyun")
        dns_creds = []
        acme_available = False
        try:
            dc = _panel_get("/dns-credentials?category=dns")
            if dc.get("success"):
                for r in (dc.get("data") or {}).get("credentials", []):
                    prov = str(r.get("provider") or "").strip().lower()
                    if prov in acme_supported:
                        dns_creds.append({
                            "id": r.get("id"),
                            "name": r.get("name"),
                            "provider": prov,
                        })
        except Exception:
            pass

        # Probe whether acme.sh is actually available on the panel: issue-acme
        # returns 503 when not. We infer availability cheaply — if there is at
        # least one usable DNS credential we surface the acme channel and let
        # the panel reject with a clear message if acme.sh is missing.
        acme_available = bool(dns_creds)

        # 腾讯云 SSL credentials (for free DV issuance via ApplyCertificate).
        ssl_creds = []
        try:
            sc = _panel_get("/ssl/credentials")
            if sc.get("success"):
                for r in (sc.get("data") or []):
                    ssl_creds.append({
                        "id": r.get("id"),
                        "name": r.get("name"),
                        "provider": r.get("provider"),
                    })
        except Exception:
            pass

        return {
            "success": True,
            "data": {
                "acmeAvailable": acme_available,
                "dnsCredentials": dns_creds,
                "sslCredentials": ssl_creds,
            },
        }

    def issue_cert(self, args):
        """Apply for a new certificate through the panel, then (optionally)
        deploy it to the matching BaoTa site once it's issued.

        channel='acme'    → POST /ssl/certificates/issue-acme  (Let's Encrypt)
        channel='tencent' → POST /ssl/certificates/apply       (腾讯云 免费 DV)

        Both are async on the panel (DNS-01 propagation), so we return the
        'applying' result immediately; the daily sync / 「立即同步」 deploys the
        cert once签发完成. This keeps the plugin's issuance flow identical to
        the panel's — same endpoints, same auto-DNS, same validation records.
        """
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

        channel = str(getattr(args, "channel", "") or "").strip().lower() or "acme"
        domain = str(getattr(args, "domain", "") or "").strip().lower().rstrip(".")
        if not domain:
            return public.ReturnMsg(False, "请填写要申请证书的域名")

        import re

        if channel == "acme":
            dns_cred_id = str(getattr(args, "dnsCredentialId", "") or "").strip()
            key_length = str(getattr(args, "keyLength", "") or "2048").strip() or "2048"
            if not dns_cred_id:
                return public.ReturnMsg(False, "请选择用于 DNS 验证的 DNS 凭证")
            payload = {
                "domain": domain,
                "dnsCredentialId": _to_int(dns_cred_id),
                "keyLength": key_length,
            }
            # Optional SANs: comma / space separated.
            alt = str(getattr(args, "altNames", "") or "").strip()
            if alt:
                names = [x.strip().lower().rstrip(".") for x in re.split(r"[\s,]+", alt) if x.strip()]
                if names:
                    payload["altNames"] = names
            data = _panel_post("/ssl/certificates/issue-acme", payload, timeout=60)
            if data.get("success"):
                public.WriteLog("DNS面板SSL同步", "申请 Let's Encrypt 证书：" + domain)
                return public.ReturnMsg(True, data.get("message") or "已提交 Let's Encrypt 签发，请稍后在证书列表查看")
            return public.ReturnMsg(False, data.get("message", "申请失败"))

        if channel == "tencent":
            cred_id = str(getattr(args, "credentialId", "") or "").strip()
            if not cred_id:
                return public.ReturnMsg(False, "请选择腾讯云 SSL 凭证")
            payload = {
                "credentialId": _to_int(cred_id),
                "domain": domain,
                "dvAuthMethod": "DNS",
                "autoDnsRecord": True,
                "autoMatchDns": True,
            }
            data = _panel_post("/ssl/certificates/apply", payload, timeout=120)
            if data.get("success"):
                public.WriteLog("DNS面板SSL同步", "申请腾讯云免费证书：" + domain)
                return public.ReturnMsg(True, data.get("message") or "已提交腾讯云证书申请，请稍后在证书列表查看")
            return public.ReturnMsg(False, data.get("message", "申请失败"))

        return public.ReturnMsg(False, "未知的签发渠道：" + channel)

    # ── Manual sync trigger ──────────────────────────────────────
    def sync_now(self, args):
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

        # Preferred incremental workflow: atomically claim deployment events,
        # deploy only changed certificates, and report success/failure so the
        # panel can retry with exponential backoff.
        event_mode = False
        event_deployed = 0
        event_failed = 0
        event_skipped = 0
        sites = _list_bt_sites()
        allowed_sites = set(str(x) for x in (cfg.get("allowedSites") or []) if str(x))
        allowed_sources = set(str(x).lower() for x in (cfg.get("allowedSources") or ["tencent", "letsencrypt"]))
        for _index in range(50):
            claim = _panel_post("/ssl/deployment-events/claim", {}, timeout=30)
            if not claim.get("success"):
                break
            event_mode = True
            event = claim.get("data")
            if not event:
                break
            event_id = event.get("id")
            domain = str(event.get("domain") or "").strip().lower()
            source = str(event.get("source") or "").strip().lower()
            matched_sites = _match_sites_for_domain(domain, sites)
            matched_names = [str(site.get("name") or "") for site in matched_sites if site.get("name")]
            allowed_matches = [site for site in matched_sites if not allowed_sites or str(site.get("name") or "") in allowed_sites]
            result_payload = {"status": "failed", "targetName": ", ".join(matched_names), "error": "未找到匹配站点"}
            if source not in allowed_sources:
                result_payload = {"status": "skipped", "error": "证书来源不在部署白名单"}
                event_skipped += 1
            elif matched_sites and not allowed_matches:
                result_payload = {"status": "skipped", "targetName": ", ".join(matched_names), "error": "匹配站点均不在部署白名单"}
                event_skipped += 1
            elif allowed_matches:
                successes = []
                failures = []
                fingerprints = {}
                for site in allowed_matches:
                    matched = str(site.get("name") or "")
                    try:
                        deploy_args = type("A", (), {})()
                        deploy_args.certId = event.get("remoteCertId", "")
                        deploy_args.credentialId = str(event.get("credentialId", ""))
                        deploy_args.siteName = matched
                        deployed_result = self.deploy(deploy_args)
                        if deployed_result.get("status"):
                            fingerprint = ((_get_config() or {}).get("deployedFingerprints") or {}).get(matched, "")
                            fingerprints[matched] = fingerprint
                            successes.append(matched)
                            event_deployed += 1
                        else:
                            failures.append(matched + ": " + str(deployed_result.get("msg") or "部署失败"))
                            event_failed += 1
                    except Exception as e:
                        failures.append(matched + ": " + str(e))
                        event_failed += 1
                result_payload = {
                    "status": "failed" if failures else "success",
                    "targetName": ", ".join([str(site.get("name") or "") for site in allowed_matches]),
                    "fingerprint": json.dumps(fingerprints, ensure_ascii=False, separators=(",", ":")),
                    "error": "; ".join(failures),
                }
                if failures and successes:
                    result_payload["error"] = "部分站点部署失败（成功: " + ", ".join(successes) + "）：" + result_payload["error"]
            else:
                event_failed += 1
            _panel_post("/ssl/deployment-events/" + str(event_id) + "/result", result_payload, timeout=30)

        if event_mode:
            _set_config("lastSyncAt", time.strftime("%Y-%m-%d %H:%M:%S"))
            public.WriteLog("DNS面板SSL同步", "增量同步完成：部署 " + str(event_deployed) + "，失败 " + str(event_failed) + "，跳过 " + str(event_skipped))
            return public.ReturnMsg(True, "增量同步完成：部署 " + str(event_deployed) + " 个，失败 " + str(event_failed) + " 个，跳过 " + str(event_skipped) + " 个")

        # Pull certs and auto-deploy to matching sites by domain
        raw = _http_request(
            _panel_api("/ssl/certificates?credentialId=all&page=1&limit=500"),
            headers=_panel_headers(),
        )
        try:
            data = json.loads(raw)
        except Exception:
            return public.ReturnMsg(False, "解析响应失败")

        if not data.get("success"):
            return public.ReturnMsg(False, data.get("message", "同步失败"))

        certs = data.get("data") or []
        # Deploy only the freshest cert per domain (most remaining validity).
        certs = _dedup_latest_by_domain(
            [c for c in certs if c.get("status") == "issued" or c.get("isUploaded")]
        )
        sites = _list_bt_sites()

        deployed = 0
        skipped = 0
        fallback_allowed_sites = set(str(x) for x in (cfg.get("allowedSites") or []) if str(x))
        fallback_allowed_sources = set(str(x).lower() for x in (cfg.get("allowedSources") or ["tencent", "letsencrypt"]))
        for cert in certs:
            domain = (cert.get("domain") or "").strip().lower()
            source = "letsencrypt" if cert.get("provider") == "acme" or cert.get("source") == "letsencrypt" else "tencent"
            if source not in fallback_allowed_sources:
                skipped += 1
                continue
            # Match cert domain to a site by name or bound domain.
            matched_sites = _match_sites_for_domain(domain, sites)
            if not matched_sites:
                skipped += 1
                continue
            deployable_sites = [site for site in matched_sites if not fallback_allowed_sites or str(site.get("name") or "") in fallback_allowed_sites]
            if not deployable_sites:
                skipped += 1
                continue

            # Auto-deploy to every matching whitelisted site.
            for site in deployable_sites:
                matched = str(site.get("name") or "")
                try:
                    args_deploy = type("A", (), {})()
                    args_deploy.certId = cert.get("remoteCertId", "")
                    args_deploy.credentialId = str(cert.get("credentialId", ""))
                    args_deploy.siteName = matched
                    result = self.deploy(args_deploy)
                    if result.get("status"):
                        deployed += 1
                    else:
                        skipped += 1
                except Exception:
                    skipped += 1

        # After deploying the fresh certs, ask the panel to prune superseded
        # certs (< keepDays remaining when a healthy newer one exists) and clean
        # up their leftover _dnsauth validation records. Guarded server-side so
        # it never deletes a domain's only/best cert. keepDays follows the
        # configured renew window so prune and renew share one threshold.
        keep_days = _to_int(cfg.get("renewDays")) if cfg.get("renewDays") else 7
        if not isinstance(keep_days, int):
            keep_days = 7
        pruned = 0
        if deployed > 0:
            try:
                praw = _http_request(
                    _panel_api("/ssl/certificates/prune-superseded"),
                    method="POST",
                    headers=_panel_headers(),
                    data={"keepDays": keep_days},
                )
                pdata = json.loads(praw)
                if pdata.get("success"):
                    pruned = len([p for p in (pdata.get("data") or {}).get("pruned", []) if not p.get("error")])
            except Exception:
                pass

        _set_config("lastSyncAt", time.strftime("%Y-%m-%d %H:%M:%S"))
        public.WriteLog("DNS面板SSL同步", "手动同步完成：部署 " + str(deployed) + "，跳过 " + str(skipped) + "，清理 " + str(pruned))
        msg = "同步完成：部署 " + str(deployed) + " 个，跳过 " + str(skipped) + " 个"
        if pruned:
            msg += "，清理过期证书 " + str(pruned) + " 个"
        return public.ReturnMsg(True, msg)

    # ── Auto-sync entry (called by cron) ─────────────────────────
    def auto_sync(self, args):
        cfg = _get_config() or {}
        if not cfg.get("autoSync"):
            return public.ReturnMsg(False, "自动同步未启用")
        # Renew window (days before expiry). Shared with the panel + prune step.
        renew_days = _to_int(cfg.get("renewDays")) if cfg.get("renewDays") else 7
        if not isinstance(renew_days, int):
            renew_days = 7
        # 1) Ask the panel to renew certs expiring within renew_days. The panel
        #    applies new certs and adds DNS validation; issuance completes
        #    asynchronously, so the freshly-issued cert is deployed on a later
        #    run. Safe to call daily — already-issued domains are skipped.
        try:
            _http_request(
                _panel_api("/ssl/certificates/renew-expired"),
                method="POST",
                headers=_panel_headers(),
                data={"renewDays": renew_days},
                timeout=180,
            )
        except Exception:
            pass
        # 2) Deploy the freshest issued cert per domain, then prune superseded
        #    (< renew_days) certs and clean their _dnsauth validation records.
        return self.sync_now(args)


# Allow running as a script from a cron task, e.g.:
#   /www/server/panel/pyenv/bin/python dnspanel_ssl_main.py auto_sync
if __name__ == "__main__":
    _action = sys.argv[1] if len(sys.argv) > 1 else "auto_sync"
    _inst = dnspanel_ssl_main()
    _fn = getattr(_inst, _action, None)
    if not _fn:
        print(json.dumps({"status": False, "msg": "unknown action: " + _action}, ensure_ascii=False))
    else:
        try:
            print(json.dumps(_fn(type("A", (), {})()), ensure_ascii=False))
        except Exception as _e:
            print(json.dumps({"status": False, "msg": str(_e)}, ensure_ascii=False))
