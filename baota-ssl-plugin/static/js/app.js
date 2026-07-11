/**
 * DNS面板SSL同步插件 - 前端交互
 *
 * Layout: a persistent shell (header + tabs + .dps-content) lives in index.html.
 * Every view renders ONLY into .dps-content, so switching tabs never destroys
 * the menu (the previous version nested a second .plugin_body inside the first,
 * so any tab switch wiped out the navigation).
 */
var dnspanel_ssl = {
    currentCerts: [],
    currentSites: [],

    init: function () {
        this.show_overview();
    },

    // Render HTML into the stable content area.
    setContent: function (html) {
        $('.dps-content').html(html);
    },

    setActiveTab: function (idx) {
        $('.dps-tab').removeClass('active');
        $('.dps-tab[data-idx="' + idx + '"]').addClass('active');
    },

    esc: function (s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function (m) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
        });
    },

    // Normalise plugin responses: ReturnMsg {status,msg} OR {success,data,message}.
    handle: function (rdata, okCb, errCb) {
        if (rdata === undefined || rdata === null) { if (errCb) errCb('无响应'); return; }
        if (typeof rdata.status === 'boolean') {
            if (rdata.status) { if (okCb) okCb(rdata); } else { if (errCb) errCb(rdata.msg || '操作失败'); }
            return;
        }
        if (typeof rdata.success === 'boolean') {
            if (rdata.success) { if (okCb) okCb(rdata); } else { if (errCb) errCb(rdata.message || '操作失败'); }
            return;
        }
        if (okCb) okCb(rdata);
    },

    request: function (func, args, cb) {
        request_plugin('dnspanel_ssl', func, args, function (rdata) { if (cb) cb(rdata); });
    },

    showMsg: function (msg, icon) {
        if (typeof layer !== 'undefined') layer.msg(msg, { icon: icon || 1, time: 3000 });
    },

    loadingHtml: function (text) {
        return '<div class="dps-loading"><img src="/static/img/loading.gif" style="width:28px"/>'
            + '<div style="margin-top:10px;">' + (text || '加载中…') + '</div></div>';
    },

    // ── Overview ─────────────────────────────────────────────────
    show_overview: function () {
        this.setActiveTab(0);
        this.setContent(this.loadingHtml('正在连接 DNS 面板…'));
        var that = this;
        this.request('get_overview', {}, function (rdata) { that.render_overview(rdata || {}); });
    },

    render_overview: function (d) {
        var badge = d.connectionOk
            ? '<span class="dps-badge ok">已连接</span>'
            : (d.configured ? '<span class="dps-badge err">连接失败</span>' : '<span class="dps-badge warn">未配置</span>');
        // Auto-renew status is read LIVE from the panel (panelRenew) — the panel
        // scheduler is the source of truth. When the panel is unreachable we fall
        // back to the local BaoTa cron flag (autoSync).
        var pr = d.panelRenew || null;
        var effective = d.autoRenew;
        var renewBadge = effective
            ? '<span class="dps-badge ok">已开启</span>'
            : '<span class="dps-badge warn">未开启</span>';
        var html = ''
            + '<div class="dps-card">'
            + '  <h3>运行状态</h3>'
            + '  <div class="dps-grid">'
            + '    <div class="k">连接状态</div><div class="v">' + badge + '</div>'
            + '    <div class="k">服务器地址</div><div class="v">' + (this.esc(d.serverUrl) || '<span style="color:#94a3b8">未配置</span>') + '</div>'
            + '    <div class="k">自动续期</div><div class="v">' + renewBadge + '</div>'
            + '    <div class="k">最近同步</div><div class="v">' + (this.esc(d.lastSyncAt) || '从未同步') + '</div>'
            + '    <div class="k">可用证书数</div><div class="v">' + (d.certCount || 0) + '</div>'
            + '  </div>'
            + (d.error ? '<div class="dps-alert error" style="margin-top:14px;">' + this.esc(d.error) + '</div>' : '')
            + '  <div class="dps-row" style="margin-top:18px;">'
            + (d.configured
                ? '    <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.sync_now()">立即同步</button>'
                + '    <button class="dps-btn dps-btn-ghost" onclick="dnspanel_ssl.show_issue()">申请证书</button>'
                + '    <button class="dps-btn dps-btn-ghost" onclick="dnspanel_ssl.show_certs()">查看证书</button>'
                : '    <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.show_config()">前往连接配置</button>')
            + '  </div>'
            + '</div>';

        // Auto-renew "真同步" card: shows the panel's own scheduler state and lets
        // the user flip it here — one switch drives both the panel scheduler and
        // the plugin's local cron (kept in step by save_config / set_auto_renew).
        if (d.configured) {
            var syncState, syncHint;
            if (pr) {
                syncState = pr.enabled
                    ? '<span class="dps-badge ok">面板自动续期已开启</span>'
                    : '<span class="dps-badge warn">面板自动续期未开启</span>';
                syncHint = '与 DNS 面板「设置 → 自动续期」实时同步。当前阈值：到期前 <b>'
                    + (pr.days || 7) + '</b> 天触发续期。';
            } else {
                syncState = '<span class="dps-badge err">无法读取面板续期状态</span>';
                syncHint = '未能连接面板读取自动续期开关，下方显示的是本机计划任务状态。';
            }
            var lastRun = pr && pr.lastRunAt ? this.esc(pr.lastRunAt) : '从未执行';
            var lastResult = pr && pr.lastResult ? this.esc(pr.lastResult) : '';
            html += ''
                + '<div class="dps-card">'
                + '  <h3>自动续期（与面板同步）</h3>'
                + '  <div class="dps-grid">'
                + '    <div class="k">同步状态</div><div class="v">' + syncState + '</div>'
                + '    <div class="k">面板上次执行</div><div class="v">' + lastRun + '</div>'
                + (lastResult ? '    <div class="k">上次结果</div><div class="v" style="font-weight:400;color:#64748b">' + lastResult + '</div>' : '')
                + '  </div>'
                + '  <div class="dps-alert info" style="margin-top:12px;">' + syncHint + '</div>'
                + '  <div class="dps-row" style="margin-top:6px;">'
                + '    <label class="dps-switch"><input type="checkbox" id="ov_auto_renew"' + (effective ? ' checked' : '') + ' onchange="dnspanel_ssl.toggle_auto_renew(this.checked)" /> 开启自动续期（面板 + 本机计划任务）</label>'
                + '  </div>'
                + '</div>';
        }
        this.setContent(html);
    },

    // Flip auto-renew from the overview: pushes to the panel scheduler AND the
    // local cron flag so the two never drift apart (真同步).
    toggle_auto_renew: function (enabled) {
        var that = this;
        var loadIdx = layer.load(1, { shade: [0.1, '#fff'] });
        this.request('set_auto_renew', { enabled: enabled }, function (rdata) {
            layer.close(loadIdx);
            that.handle(rdata,
                function (r) { that.showMsg(r.msg || '已更新自动续期', 1); that.show_overview(); },
                function (err) { that.showMsg(err, 2); that.show_overview(); });
        });
    },

    // ── Connection config ────────────────────────────────────────
    show_config: function () {
        this.setActiveTab(1);
        var html = ''
            + '<div class="dps-card" style="max-width:640px;">'
            + '  <h3>连接配置</h3>'
            + '  <div class="dps-alert info">填写 DNS 面板的访问地址与 API Token（在 DNS 面板「设置 → API Token」中创建）。</div>'
            + '  <div class="dps-field"><label>服务器地址</label>'
            + '    <input type="text" id="btssl_server_url" class="dps-input" placeholder="https://your-dns-panel.com" />'
            + '    <div class="hint">DNS 面板的根地址，不要带末尾斜杠。</div></div>'
            + '  <div class="dps-field"><label>API Token</label>'
            + '    <input type="text" id="btssl_api_token" class="dps-input" placeholder="dpan_xxxxxxxxxxxx" />'
            + '    <div class="hint">留空表示不修改已保存的 Token。</div></div>'
            + '  <div class="dps-field"><label class="dps-switch"><input type="checkbox" id="btssl_auto_sync" /> 启用自动续期（每日：检查到期 → 续期 → 部署 → 清理过期证书）</label>'
            + '    <div class="hint">开启后会同时打开 DNS 面板侧的自动续期开关（真同步），并注册本机每日计划任务。</div></div>'
            + '  <div class="dps-field"><label>续期提前天数</label>'
            + '    <input type="number" id="btssl_renew_days" class="dps-input" min="1" max="60" placeholder="7" style="max-width:160px;" />'
            + '    <div class="hint">证书到期前多少天触发续期，与面板共用该阈值（默认 7 天）。</div></div>'
            + '  <div class="dps-field"><label>自动部署站点白名单</label>'
            + '    <input type="text" id="btssl_allowed_sites" class="dps-input" placeholder="example.com, api.example.com" />'
            + '    <div class="hint" id="btssl_sites_hint">多个站点用逗号分隔；留空表示允许全部宝塔站点。</div></div>'
            + '  <div class="dps-field"><label>允许部署的证书来源</label>'
            + '    <label style="margin-right:18px;"><input type="checkbox" id="btssl_source_tencent" /> 腾讯云</label>'
            + '    <label><input type="checkbox" id="btssl_source_letsencrypt" /> Let\'s Encrypt</label>'
            + '    <div class="hint">未勾选的来源会在部署事件中标记为跳过，不会写入站点。</div></div>'
            + '  <div class="dps-row">'
            + '    <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.save_config()">保存配置</button>'
            + '    <button class="dps-btn dps-btn-ghost" onclick="dnspanel_ssl.show_overview()">返回概览</button>'
            + '  </div>'
            + '</div>';
        this.setContent(html);
        this.request('get_overview', {}, function (d) {
            d = d || {};
            $('#btssl_server_url').val(d.serverUrl || '');
            var pr = d.panelRenew || null;
            $('#btssl_auto_sync').prop('checked', !!d.autoRenew);
            $('#btssl_renew_days').val(pr && pr.days ? pr.days : 7);
            $('#btssl_allowed_sites').val((d.allowedSites || []).join(', '));
            var sources = d.allowedSources || ['tencent', 'letsencrypt'];
            $('#btssl_source_tencent').prop('checked', sources.indexOf('tencent') >= 0);
            $('#btssl_source_letsencrypt').prop('checked', sources.indexOf('letsencrypt') >= 0);
            if (d.availableSites && d.availableSites.length) {
                $('#btssl_sites_hint').text('可用站点：' + d.availableSites.join('、') + '。留空表示全部。');
            }
        });
    },

    save_config: function () {
        var serverUrl = $('#btssl_server_url').val().trim();
        var apiToken = $('#btssl_api_token').val().trim();
        var autoSync = $('#btssl_auto_sync').prop('checked');
        var renewDays = parseInt($('#btssl_renew_days').val(), 10);
        var allowedSites = $('#btssl_allowed_sites').val().trim();
        var allowedSources = [];
        if ($('#btssl_source_tencent').prop('checked')) allowedSources.push('tencent');
        if ($('#btssl_source_letsencrypt').prop('checked')) allowedSources.push('letsencrypt');
        if (!serverUrl) { this.showMsg('请填写服务器地址', 2); return; }
        if (!allowedSources.length) { this.showMsg('至少选择一个允许部署的证书来源', 2); return; }
        if (isNaN(renewDays) || renewDays < 1) { renewDays = 7; }
        var that = this;
        this.request('save_config', { serverUrl: serverUrl, apiToken: apiToken, autoSync: autoSync, renewDays: renewDays, allowedSites: allowedSites, allowedSources: JSON.stringify(allowedSources) }, function (rdata) {
            that.handle(rdata,
                function () { that.showMsg('配置已保存', 1); that.show_overview(); },
                function (err) { that.showMsg(err, 2); });
        });
    },

    // ── Certificate list ─────────────────────────────────────────
    show_certs: function () {
        this.setActiveTab(2);
        this.setContent('<div class="dps-card"><h3>证书列表</h3><div id="cert_list_body">' + this.loadingHtml() + '</div></div>');
        var that = this;
        this.request('get_certificates', {}, function (rdata) {
            that.handle(rdata,
                function (d) { that.currentCerts = d.data || []; that.render_certs(that.currentCerts); },
                function (err) { $('#cert_list_body').html('<div class="dps-alert error">' + that.esc(err) + '。请先到「连接配置」完成设置。</div>'); });
        });
    },

    render_certs: function (certs) {
        if (!certs.length) { $('#cert_list_body').html('<div class="dps-empty">没有已签发的证书</div>'); return; }
        var deployedCount = 0, matchedCount = 0;
        var rows = '';
        for (var i = 0; i < certs.length; i++) {
            var c = certs[i];
            var site = c.matchedSite || '';
            if (site) matchedCount++;
            if (c.deployed) deployedCount++;
            var siteCell = site
                ? '<span class="font-mono">' + this.esc(site) + '</span>'
                : '<span class="dps-badge warn">未匹配站点</span>';
            var statusCell = c.deployed
                ? '<span class="dps-badge ok">已部署</span>'
                : (site ? '<span class="dps-badge warn">未部署</span>' : '<span style="color:#94a3b8">—</span>');
            var actionCell = site
                ? '<button class="dps-btn dps-btn-ghost dps-btn-sm" onclick="dnspanel_ssl.deploy_to(\''
                    + this.esc(c.remoteCertId) + '\',' + (c.credentialId || 0) + ',\'' + this.esc(site) + '\')">'
                    + (c.deployed ? '重新部署' : '部署') + '</button>'
                : '<span style="color:#94a3b8;font-size:12px">无可部署站点</span>';
            // Source badge: Let's Encrypt certs (acme.sh) vs Tencent/uploaded.
            var srcLabel = c.sourceLabel || (c.provider === 'acme' ? "Let's Encrypt" : '腾讯云');
            var isLE = c.provider === 'acme' || c.source === 'letsencrypt';
            var sourceCell = '<span class="dps-badge ' + (isLE ? 'ok' : 'info') + '">' + this.esc(srcLabel) + '</span>';
            // Auto-renew: acme certs carry a status; others renew via panel scheduler.
            var renewLabel = c.autoRenewLabel || (c.provider === 'acme' ? '自动续期' : '面板托管');
            var renewCell = '<span style="font-size:12px;color:#64748b">' + this.esc(renewLabel) + '</span>';
            rows += '<tr>'
                + '<td><strong>' + this.esc(c.domain || '-') + '</strong></td>'
                + '<td>' + sourceCell + '</td>'
                + '<td>' + this.esc(c.notAfter || '-') + '</td>'
                + '<td>' + renewCell + '</td>'
                + '<td>' + siteCell + '</td>'
                + '<td>' + statusCell + '</td>'
                + '<td>' + actionCell + '</td>'
                + '</tr>';
        }
        var summary = '<div class="dps-alert info" style="margin-bottom:12px;">共 ' + certs.length
            + ' 张证书 · 匹配到站点 <b>' + matchedCount + '</b> · 已部署 <b>' + deployedCount + '</b></div>';
        $('#cert_list_body').html(
            summary
            + '<table class="dps-table"><thead><tr><th>域名</th><th>来源</th><th>过期时间</th><th>自动续期</th><th>匹配站点</th><th>部署状态</th><th>操作</th></tr></thead>'
            + '<tbody>' + rows + '</tbody></table>');
    },

    // ── Apply for a new certificate ──────────────────────────────
    // Mirrors the panel's own issuance: acme (Let's Encrypt, DNS-01 driven by
    // acme.sh) and 腾讯云 免费 DV (auto DNS validation). All the DNS-record
    // automation happens server-side, so this is 100% consistent with the panel.
    show_issue: function () {
        this.setActiveTab(3);
        this.setContent('<div class="dps-card"><h3>申请证书</h3><div id="issue_body">' + this.loadingHtml('正在读取可用凭证…') + '</div></div>');
        var that = this;
        this.request('get_issue_options', {}, function (rdata) {
            that.handle(rdata,
                function (d) { that.render_issue(d.data || {}); },
                function (err) { $('#issue_body').html('<div class="dps-alert error">' + that.esc(err) + '。请先到「连接配置」完成设置。</div>'); });
        });
    },

    render_issue: function (opt) {
        this._issueOpt = opt;
        var dnsCreds = opt.dnsCredentials || [];
        var sslCreds = opt.sslCredentials || [];
        var hasAcme = opt.acmeAvailable && dnsCreds.length;
        var hasTencent = sslCreds.length > 0;

        if (!hasAcme && !hasTencent) {
            $('#issue_body').html('<div class="dps-alert warn">暂无可用于签发的凭证。请先在 DNS 面板添加 DNS 凭证'
                + '（Cloudflare / DNSPod / 阿里云，用于 Let\'s Encrypt）或腾讯云 SSL 凭证。</div>');
            return;
        }

        // Channel selector — only show channels that have usable credentials.
        var chOpts = '';
        if (hasAcme) chOpts += '<option value="acme">Let\'s Encrypt（免费·自动 DNS 验证）</option>';
        if (hasTencent) chOpts += '<option value="tencent">腾讯云 免费 DV（自动 DNS 验证）</option>';

        var dnsOpts = '<option value="">-- 选择 DNS 凭证 --</option>';
        for (var i = 0; i < dnsCreds.length; i++) {
            dnsOpts += '<option value="' + dnsCreds[i].id + '">' + this.esc(dnsCreds[i].name)
                + ' (' + this.esc(dnsCreds[i].provider) + ')</option>';
        }
        var sslOpts = '<option value="">-- 选择腾讯云 SSL 凭证 --</option>';
        for (var j = 0; j < sslCreds.length; j++) {
            sslOpts += '<option value="' + sslCreds[j].id + '">' + this.esc(sslCreds[j].name) + '</option>';
        }

        var html = ''
            + '<div class="dps-alert info">在此申请的证书与在 DNS 面板申请完全一致：自动创建 DNS 验证记录并提交验证，签发完成后可「立即同步」部署到站点。</div>'
            + '  <div class="dps-field"><label>签发渠道</label>'
            + '    <select id="issue_channel" class="dps-input" onchange="dnspanel_ssl.on_issue_channel()">' + chOpts + '</select></div>'
            + '  <div class="dps-field"><label>域名</label>'
            + '    <input type="text" id="issue_domain" class="dps-input" placeholder="example.com 或 *.example.com" />'
            + '    <div class="hint">支持通配符（*.example.com，仅 DNS 验证）。</div></div>'
            // acme-only fields
            + '  <div id="issue_acme_fields">'
            + '    <div class="dps-field"><label>DNS 验证凭证</label>'
            + '      <select id="issue_dns_cred" class="dps-input">' + dnsOpts + '</select>'
            + '      <div class="hint">acme.sh 使用该凭证自动完成 DNS-01 验证。</div></div>'
            + '    <div class="dps-field"><label>密钥类型</label>'
            + '      <select id="issue_keylen" class="dps-input" style="max-width:220px;">'
            + '        <option value="2048">RSA 2048</option><option value="4096">RSA 4096</option>'
            + '        <option value="ec-256">ECC 256</option><option value="ec-384">ECC 384</option></select></div>'
            + '    <div class="dps-field"><label>附加域名（可选）</label>'
            + '      <input type="text" id="issue_alt" class="dps-input" placeholder="www.example.com, api.example.com" />'
            + '      <div class="hint">多个域名用逗号或空格分隔，将合并进同一张证书。</div></div>'
            + '  </div>'
            // tencent-only fields
            + '  <div id="issue_tencent_fields" style="display:none;">'
            + '    <div class="dps-field"><label>腾讯云 SSL 凭证</label>'
            + '      <select id="issue_ssl_cred" class="dps-input">' + sslOpts + '</select>'
            + '      <div class="hint">用于向腾讯云申请免费 DV 证书，验证记录自动匹配已有 DNS 凭证添加。</div></div>'
            + '  </div>'
            + '  <div class="dps-row" style="margin-top:6px;">'
            + '    <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.do_issue()">提交申请</button>'
            + '    <button class="dps-btn dps-btn-ghost" onclick="dnspanel_ssl.show_certs()">查看证书列表</button>'
            + '  </div>';
        $('#issue_body').html(html);
        this.on_issue_channel();
    },

    on_issue_channel: function () {
        var ch = $('#issue_channel').val();
        if (ch === 'tencent') {
            $('#issue_acme_fields').hide();
            $('#issue_tencent_fields').show();
        } else {
            $('#issue_acme_fields').show();
            $('#issue_tencent_fields').hide();
        }
    },

    do_issue: function () {
        var ch = $('#issue_channel').val();
        var domain = $('#issue_domain').val().trim();
        if (!domain) { this.showMsg('请填写域名', 2); return; }
        var payload = { channel: ch, domain: domain };
        if (ch === 'tencent') {
            var sslCred = $('#issue_ssl_cred').val();
            if (!sslCred) { this.showMsg('请选择腾讯云 SSL 凭证', 2); return; }
            payload.credentialId = sslCred;
        } else {
            var dnsCred = $('#issue_dns_cred').val();
            if (!dnsCred) { this.showMsg('请选择 DNS 验证凭证', 2); return; }
            payload.dnsCredentialId = dnsCred;
            payload.keyLength = $('#issue_keylen').val() || '2048';
            payload.altNames = $('#issue_alt').val().trim();
        }
        var that = this;
        var loadIdx = layer.load(1, { shade: [0.1, '#fff'] });
        this.request('issue_cert', payload, function (rdata) {
            layer.close(loadIdx);
            that.handle(rdata,
                function (r) {
                    layer.alert(that.esc(r.msg || '已提交申请，签发完成后请到「证书列表」部署'),
                        { icon: 1, title: '申请已提交' });
                },
                function (err) { that.showMsg(err, 2); });
        });
    },

    // ── Manual deploy ────────────────────────────────────────────
    show_deploy: function () {
        this.setActiveTab(4);
        var html = ''
            + '<div class="dps-card" style="max-width:720px;">'
            + '  <h3>手动部署</h3>'
            + '  <div class="dps-alert info">选择证书与目标站点，将 SSL 证书部署到宝塔站点并重载 Web 服务。</div>'
            + '  <div class="dps-field"><label>选择证书</label>'
            + '    <select id="deploy_cert" class="dps-input"><option value="">加载中…</option></select></div>'
            + '  <div class="dps-field"><label>选择站点</label>'
            + '    <select id="deploy_site" class="dps-input"><option value="">加载中…</option></select></div>'
            + '  <div id="deploy_site_diag"></div>'
            + '  <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.do_deploy()">部署证书</button>'
            + '</div>';
        this.setContent(html);
        var that = this;
        this.request('get_certificates', {}, function (rdata) {
            that.handle(rdata, function (d) {
                that.currentCerts = d.data || [];
                var opts = '<option value="">-- 选择证书 --</option>';
                for (var i = 0; i < that.currentCerts.length; i++) {
                    var c = that.currentCerts[i];
                    opts += '<option value="' + that.esc(c.remoteCertId) + '|' + (c.credentialId || 0) + '">'
                        + that.esc(c.domain) + ' (' + that.esc(c.issuer || '') + ')</option>';
                }
                $('#deploy_cert').html(opts);
            }, function (err) { $('#deploy_cert').html('<option value="">' + that.esc(err) + '</option>'); });
        });
        this.request('get_sites', {}, function (rdata) {
            that.handle(rdata, function (d) {
                that.currentSites = d.data || [];
                if (!that.currentSites.length) {
                    var dbg = d.debug ? '<pre style="white-space:pre-wrap;font-size:11px;background:#f8fafc;padding:8px;border-radius:6px;margin-top:8px;">'
                        + that.esc(JSON.stringify(d.debug, null, 2)) + '</pre>' : '';
                    $('#deploy_site').html('<option value="">未读取到站点</option>');
                    $('#deploy_site_diag').html('<div class="dps-alert warn">未读取到宝塔站点。请确认插件 Python 已更新并重启面板（见下方诊断）。' + dbg + '</div>');
                    return;
                }
                $('#deploy_site_diag').html('');
                var opts = '<option value="">-- 选择站点 --</option>';
                for (var i = 0; i < that.currentSites.length; i++) {
                    var s = that.currentSites[i];
                    var doms = (s.domains && s.domains.length) ? '（' + that.esc(s.domains.slice(0, 2).join(', ')) + '）' : '';
                    opts += '<option value="' + that.esc(s.name) + '">' + that.esc(s.name) + doms + '</option>';
                }
                $('#deploy_site').html(opts);
            }, function (err) { $('#deploy_site').html('<option value="">' + that.esc(err) + '</option>'); });
        });
    },

    do_deploy: function () {
        var certVal = $('#deploy_cert').val();
        var siteName = $('#deploy_site').val();
        if (!certVal || !siteName) { this.showMsg('请选择证书和站点', 2); return; }
        var parts = certVal.split('|');
        var that = this;
        var loadIdx = layer.load(1, { shade: [0.1, '#fff'] });
        this.request('deploy', { certId: parts[0], credentialId: parts[1], siteName: siteName }, function (rdata) {
            layer.close(loadIdx);
            that.handle(rdata, function () { that.showMsg('证书已部署到 ' + siteName, 1); }, function (err) { that.showMsg(err, 2); });
        });
    },

    // Deploy directly to a known site (matched server-side), then refresh list.
    deploy_to: function (certId, credentialId, siteName) {
        var that = this;
        layer.confirm('将证书部署到站点「' + siteName + '」并重载 Web 服务？', { btn: ['确定', '取消'] }, function (index) {
            layer.close(index);
            var loadIdx = layer.load(1, { shade: [0.1, '#fff'] });
            that.request('deploy', { certId: certId, credentialId: credentialId, siteName: siteName }, function (rdata) {
                layer.close(loadIdx);
                that.handle(rdata,
                    function () { that.showMsg('已部署到 ' + siteName, 1); that.show_certs(); },
                    function (err) { that.showMsg(err, 2); });
            });
        });
    },

    quick_deploy: function (certId, credentialId, domain) {
        var that = this;
        this.request('get_sites', {}, function (rdata) {
            that.handle(rdata, function (d) {
                var sites = d.data || [];
                var dl = String(domain).toLowerCase().replace(/^\*\./, '');
                var matched = null;
                for (var i = 0; i < sites.length; i++) {
                    var cands = [String(sites[i].name || '').toLowerCase()];
                    var doms = sites[i].domains || [];
                    for (var k = 0; k < doms.length; k++) cands.push(String(doms[k]).toLowerCase().replace(/^\*\./, ''));
                    for (var j = 0; j < cands.length; j++) {
                        var sn = cands[j];
                        if (sn && (dl === sn || dl.endsWith('.' + sn) || sn.endsWith('.' + dl))) { matched = sites[i].name; break; }
                    }
                    if (matched) break;
                }
                if (!matched) { that.showMsg('未找到匹配 ' + domain + ' 的站点，请用「手动部署」选择站点', 2); return; }
                that.deploy_to(certId, credentialId, matched);
            }, function (err) { that.showMsg(err, 2); });
        });
    },

    sync_now: function () {
        var that = this;
        layer.confirm('立即同步？将自动匹配证书域名到对应站点并部署。', { btn: ['开始同步', '取消'] }, function (index) {
            layer.close(index);
            var loadIdx = layer.load(1, { shade: [0.1, '#fff'] });
            that.request('sync_now', {}, function (rdata) {
                layer.close(loadIdx);
                that.handle(rdata, function (d) { that.showMsg(d.msg || '同步完成', 1); that.show_overview(); }, function (err) { that.showMsg(err, 2); });
            });
        });
    }
};

/**
 * Send request to plugin (standard BaoTa helper)
 */
function request_plugin(plugin_name, function_name, args, callback, timeout) {
    if (!timeout) timeout = 3600 * 1000;
    $.ajax({
        type: 'POST',
        url: '/plugin?action=a&s=' + function_name + '&name=' + plugin_name,
        data: args,
        timeout: timeout,
        success: function (rdata) {
            if (!callback) { layer.msg(rdata.msg, { icon: rdata.status ? 1 : 2 }); return; }
            return callback(rdata);
        }
    });
}

// Init on load
$(function () {
    $('.layui-layer-page').css({ 'width': '900px' });
    dnspanel_ssl.init();
});
