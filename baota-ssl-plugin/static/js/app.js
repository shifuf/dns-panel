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
        var renewBadge = d.autoSync
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
                + '    <button class="dps-btn dps-btn-ghost" onclick="dnspanel_ssl.show_certs()">查看证书</button>'
                : '    <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.show_config()">前往连接配置</button>')
            + '  </div>'
            + '</div>';
        this.setContent(html);
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
            + '  <div class="dps-field"><label class="dps-switch"><input type="checkbox" id="btssl_auto_sync" /> 启用自动续期（每日：检查到期 → 续期 → 部署 → 清理过期证书）</label></div>'
            + '  <div class="dps-row">'
            + '    <button class="dps-btn dps-btn-primary" onclick="dnspanel_ssl.save_config()">保存配置</button>'
            + '    <button class="dps-btn dps-btn-ghost" onclick="dnspanel_ssl.show_overview()">返回概览</button>'
            + '  </div>'
            + '</div>';
        this.setContent(html);
        this.request('get_overview', {}, function (d) {
            d = d || {};
            $('#btssl_server_url').val(d.serverUrl || '');
            $('#btssl_auto_sync').prop('checked', !!d.autoSync);
        });
    },

    save_config: function () {
        var serverUrl = $('#btssl_server_url').val().trim();
        var apiToken = $('#btssl_api_token').val().trim();
        var autoSync = $('#btssl_auto_sync').prop('checked');
        if (!serverUrl) { this.showMsg('请填写服务器地址', 2); return; }
        var that = this;
        this.request('save_config', { serverUrl: serverUrl, apiToken: apiToken, autoSync: autoSync }, function (rdata) {
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
        var rows = '';
        for (var i = 0; i < certs.length; i++) {
            var c = certs[i];
            rows += '<tr>'
                + '<td><strong>' + this.esc(c.domain || '-') + '</strong></td>'
                + '<td>' + this.esc(c.issuer || '-') + '</td>'
                + '<td>' + this.esc(c.notAfter || '-') + '</td>'
                + '<td><button class="dps-btn dps-btn-ghost dps-btn-sm" onclick="dnspanel_ssl.quick_deploy(\''
                    + this.esc(c.remoteCertId) + '\',' + (c.credentialId || 0) + ',\'' + this.esc(c.domain) + '\')">部署</button></td>'
                + '</tr>';
        }
        $('#cert_list_body').html(
            '<table class="dps-table"><thead><tr><th>域名</th><th>颁发者</th><th>过期时间</th><th>操作</th></tr></thead>'
            + '<tbody>' + rows + '</tbody></table>');
    },

    // ── Manual deploy ────────────────────────────────────────────
    show_deploy: function () {
        this.setActiveTab(3);
        var html = ''
            + '<div class="dps-card" style="max-width:720px;">'
            + '  <h3>手动部署</h3>'
            + '  <div class="dps-alert info">选择证书与目标站点，将 SSL 证书部署到宝塔站点并重载 Web 服务。</div>'
            + '  <div class="dps-field"><label>选择证书</label>'
            + '    <select id="deploy_cert" class="dps-input"><option value="">加载中…</option></select></div>'
            + '  <div class="dps-field"><label>选择站点</label>'
            + '    <select id="deploy_site" class="dps-input"><option value="">加载中…</option></select></div>'
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
                var opts = '<option value="">-- 选择站点 --</option>';
                for (var i = 0; i < that.currentSites.length; i++) {
                    opts += '<option value="' + that.esc(that.currentSites[i].name) + '">' + that.esc(that.currentSites[i].name) + '</option>';
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

    quick_deploy: function (certId, credentialId, domain) {
        var that = this;
        this.request('get_sites', {}, function (rdata) {
            that.handle(rdata, function (d) {
                var sites = d.data || [];
                var matched = null;
                for (var i = 0; i < sites.length; i++) {
                    var sn = String(sites[i].name).toLowerCase();
                    if (domain.toLowerCase() === sn || domain.toLowerCase().endsWith('.' + sn)) { matched = sites[i].name; break; }
                }
                if (!matched) { that.showMsg('未找到匹配 ' + domain + ' 的站点，请用「手动部署」选择站点', 2); return; }
                layer.confirm('将证书部署到站点「' + matched + '」？', { btn: ['确定', '取消'] }, function (index) {
                    layer.close(index);
                    var loadIdx = layer.load(1, { shade: [0.1, '#fff'] });
                    that.request('deploy', { certId: certId, credentialId: credentialId, siteName: matched }, function (rdata) {
                        layer.close(loadIdx);
                        that.handle(rdata, function () { that.showMsg('已部署到 ' + matched, 1); }, function (err) { that.showMsg(err, 2); });
                    });
                });
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
