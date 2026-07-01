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

        # For reverse proxy sites, directly modify nginx config
        web_server = public.GetWebServer()
        if web_server == "nginx":
            self._enable_nginx_ssl_for_proxy(site_name, fullchain_path, privkey_path)

        # Try to call BaoTa API for regular sites (may not work for proxy sites)
        site_id = None
        try:
            import panelMysql as pm
            dbpath = "/www/server/panel/data/default.db"
            db = pm.panelMysql().dbfile(dbpath)
            site_info = db.query("SELECT id FROM sites WHERE name=? LIMIT 1", (site_name,))
            if site_info:
                site_id = site_info[0][0]
                # Mark SSL as deployed in database
                db.execute("UPDATE sites SET ssl=1 WHERE id=?", (site_id,))
                public.WriteLog("DNS面板SSL同步", "数据库更新: ssl=1 for site_id=" + str(site_id))
            db.close()
        except Exception as e:
            public.WriteLog("DNS面板SSL同步", "数据库操作: " + str(e))

        # Reload web server
        if web_server == "nginx":
            test_result = public.ExecShell("nginx -t 2>&1")
            public.WriteLog("DNS面板SSL同步", "nginx配置测试: " + str(test_result[0]))
            if "successful" in str(test_result[0]) or "syntax is ok" in str(test_result[0]):
                public.ExecShell("nginx -s reload")
                public.WriteLog("DNS面板SSL同步", "nginx已重载")
            else:
                public.WriteLog("DNS面板SSL同步", "nginx配置测试失败，未重载")
        elif web_server == "apache":
            public.ExecShell("httpd -t && systemctl reload httpd")

        public.WriteLog("DNS面板SSL同步", "部署证书到站点 " + site_name + " (certId=" + cert_id + ")")
        return public.ReturnMsg(True, "证书已部署并启用SSL，请刷新页面查看")

    def _enable_nginx_ssl_for_proxy(self, site_name, cert_path, key_path):
        """Enable SSL for nginx reverse proxy site by modifying config."""
        conf_path = "/www/server/panel/vhost/nginx/" + site_name + ".conf"
        if not os.path.exists(conf_path):
            public.WriteLog("DNS面板SSL同步", "配置文件不存在: " + conf_path)
            return False

        conf_content = public.ReadFile(conf_path)
        if not conf_content:
            public.WriteLog("DNS面板SSL同步", "无法读取配置文件: " + conf_path)
            return False

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
        public.WriteFile(conf_path, new_content)
        public.WriteLog("DNS面板SSL同步", "nginx配置已更新: " + conf_path)
        return True


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
        sites = _list_bt_sites()

        deployed = 0
        skipped = 0
        for cert in certs:
            domain = (cert.get("domain") or "").strip().lower()
            # Match cert domain to a site by name or bound domain.
            site = _match_site_for_domain(domain, sites)
            matched = site["name"] if site else None
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