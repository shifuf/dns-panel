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
    public.WriteFile(config_file, json.dumps(__config))
    return True


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
        resp = _urlmod.urlopen(req, timeout=timeout)
        return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        return json.dumps({"success": False, "message": str(e)})


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


def _panel_api(path):
    """Build full URL to the DNS panel API."""
    base = (_get_config("serverUrl") or "").strip().rstrip("/")
    return base + "/api" + path


def _panel_headers():
    """Authorization headers with the configured API token."""
    token = (_get_config("apiToken") or "").strip()
    return {"Authorization": "Bearer " + token, "Content-Type": "application/json"}


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
        if server_url and has_token:
            try:
                raw = _http_request(
                    _panel_api("/ssl/certificates?credentialId=all&page=1&limit=200"),
                    headers=_panel_headers(),
                )
                data = json.loads(raw)
                if data.get("success"):
                    connection_ok = True
                    cert_count = (data.get("pagination") or {}).get("total", 0)
                else:
                    error_msg = data.get("message", "连接失败")
            except Exception as e:
                error_msg = str(e)

        return {
            "configured": bool(server_url and has_token),
            "serverUrl": server_url,
            "autoSync": auto_sync,
            "lastSyncAt": last_sync,
            "connectionOk": connection_ok,
            "certCount": cert_count,
            "error": error_msg,
        }

    # ── Save connection settings ─────────────────────────────────
    def save_config(self, args):
        server_url = str(getattr(args, "serverUrl", "") or "").strip()
        api_token = str(getattr(args, "apiToken", "") or "").strip()
        auto_sync = getattr(args, "autoSync", False)
        if not server_url:
            return public.ReturnMsg(False, "请填写服务器地址")

        # A blank token means "keep the existing one" (so editing other fields
        # doesn't force re-entering the secret). Require a token on first setup.
        existing_token = (_get_config("apiToken") or "").strip()
        if not api_token and not existing_token:
            return public.ReturnMsg(False, "请填写 API Token")

        _set_config("serverUrl", server_url)
        if api_token:
            _set_config("apiToken", api_token)
        _set_config("autoSync", bool(auto_sync) and str(auto_sync) != "false")
        public.WriteLog("DNS面板SSL同步", "更新连接配置")
        return public.ReturnMsg(True, "配置已保存")

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
        return {"success": True, "data": issued, "total": len(issued)}

    # ── List BaoTa sites ─────────────────────────────────────────
    def get_sites(self, args):
        sites = public.M("sites").field("id,name,path,status").order("id desc").select()
        return {"success": True, "data": sites}

    # ── Deploy a certificate to a BaoTa site ─────────────────────
    def deploy(self, args):
        cert_id = str(getattr(args, "certId", "") or "").strip()
        credential_id = str(getattr(args, "credentialId", "") or "").strip()
        site_name = str(getattr(args, "siteName", "") or "").strip()

        if not cert_id or not site_name:
            return public.ReturnMsg(False, "缺少证书ID或站点名")

        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

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

        # Write cert files to BaoTa vhost cert directory
        cert_dir = "/www/server/panel/vhost/cert/" + site_name
        if not os.path.exists(cert_dir):
            os.makedirs(cert_dir)

        fullchain_path = cert_dir + "/fullchain.pem"
        privkey_path = cert_dir + "/privkey.pem"

        public.WriteFile(fullchain_path, public_key)
        public.WriteFile(privkey_path, private_key)
        os.system("chmod 600 " + privkey_path + " " + fullchain_path)

        # Enable SSL for the site via BaoTa site config (set ssl flag)
        try:
            self._enable_site_ssl(site_name)
        except Exception:
            pass

        # Reload web server
        web_server = public.GetWebServer()
        if web_server == "nginx":
            public.ExecShell("nginx -t 2>/tmp/nginx_test_err && nginx -s reload")
        elif web_server == "apache":
            public.ExecShell("httpd -t 2>/tmp/apache_test_err && systemctl reload httpd")

        public.WriteLog("DNS面板SSL同步", "部署证书到站点 " + site_name + " (certId=" + cert_id + ")")
        return public.ReturnMsg(True, "证书已部署到 " + site_name + " 并重载 Web 服务")

    def _enable_site_ssl(self, site_name):
        """Enable HTTPS for a site using BaoTa site config API."""
        # Use BaoTa internal config to enable SSL redirect (best-effort)
        conf_path = "/www/server/panel/vhost/nginx/" + site_name + ".conf"
        if not os.path.exists(conf_path):
            conf_path = "/www/server/panel/vhost/apache/" + site_name + ".conf"
        # The SSL listen blocks are added by BaoTa automatically when cert files exist.
        # Trigger a config refresh by calling ServiceReload.
        public.ServiceReload()

    # ── Manual sync trigger ──────────────────────────────────────
    def sync_now(self, args):
        cfg = _get_config() or {}
        if not cfg.get("serverUrl") or not cfg.get("apiToken"):
            return public.ReturnMsg(False, "请先配置连接信息")

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
        sites = public.M("sites").field("id,name,path,status").select()
        site_names = [s["name"] for s in sites]

        deployed = 0
        skipped = 0
        for cert in certs:
            domain = (cert.get("domain") or "").strip().lower()
            # Match cert domain to a site (exact or wildcard parent)
            matched = None
            for sn in site_names:
                snl = sn.lower()
                if domain == snl or domain.endswith("." + snl):
                    matched = sn
                    break
            if not matched:
                skipped += 1
                continue

            # Auto-deploy
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
        # certs (<7 days remaining when a healthy newer one exists) and clean
        # up their leftover _dnsauth validation records. Guarded server-side so
        # it never deletes a domain's only/best cert.
        pruned = 0
        if deployed > 0:
            try:
                praw = _http_request(
                    _panel_api("/ssl/certificates/prune-superseded"),
                    method="POST",
                    headers=_panel_headers(),
                    data={"keepDays": 7},
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
        # 1) Ask the panel to renew certs expiring within 7 days. The panel
        #    applies new certs and adds DNS validation; issuance completes
        #    asynchronously, so the freshly-issued cert is deployed on a later
        #    run. Safe to call daily — already-issued domains are skipped.
        try:
            _http_request(
                _panel_api("/ssl/certificates/renew-expired"),
                method="POST",
                headers=_panel_headers(),
                data={"renewDays": 7},
                timeout=180,
            )
        except Exception:
            pass
        # 2) Deploy the freshest issued cert per domain, then prune superseded
        #    (<7 day) certs and clean their _dnsauth validation records.
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