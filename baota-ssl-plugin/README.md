# DNS 面板 SSL 同步插件（宝塔）

> 宝塔 Linux 面板插件，对接 [DNS 面板](https://github.com/shifuf/dns-panel)，自动将已签发的 SSL 证书同步并部署到宝塔站点，支持到期前自动续期、按域名取最新证书、清理过期证书与验证记录。

---

## 功能特性

| 功能 | 说明 |
| --- | --- |
| 证书拉取 | 通过 API Token 从 DNS 面板拉取已签发 / 已上传的证书 |
| 按域名去重 | 同一域名存在多张证书时，自动选取**剩余有效期最长**的一张 |
| 手动部署 | 在插件界面选择证书与站点，一键部署并重载 Web 服务 |
| 智能匹配部署 | 在证书列表点击「部署」，自动匹配同名 / 父级站点 |
| 自动续期同步 | 每日定时：检查到期 → 续期（剩余 ≤ 7 天）→ 部署 → 清理过期证书及残留验证记录 |
| 连接状态 | 概览页实时显示与 DNS 面板的连接状态、自动续期开关、最近同步时间 |

---

## 环境要求

- 宝塔 Linux 面板 7.7+（自带 Python 运行时 `/www/server/panel/pyenv`）
- 一个可访问的 [DNS 面板](https://github.com/shifuf/dns-panel) 实例
- 在 DNS 面板中创建的 **API Token**（设置 → API Token，形如 `dpan_xxxxxxxx`）
- 证书所属凭证为腾讯云（DNSPod / tencent_ssl）

---

## 安装

### 方式一：上传安装包

1. 将本目录打包为 `dnspanel_ssl.zip`：
   ```bash
   cd baota-ssl-plugin
   zip -r dnspanel_ssl.zip dnspanel_ssl_main.py info.json index.html install.sh static templates
   ```
2. 宝塔面板 → 软件商店 → 第三方插件 → 上传 `dnspanel_ssl.zip` 安装。

### 方式二：手动部署

```bash
cp -r baota-ssl-plugin /www/server/panel/plugin/dnspanel_ssl
bash /www/server/panel/plugin/dnspanel_ssl/install.sh install
```

安装脚本会自动注册一条**每日 03:30** 的自动续期/同步计划任务（使用宝塔自带 Python 运行时）。卸载时该任务会被一并移除。

---

## 配置

打开插件 → **连接配置**：

| 字段 | 说明 |
| --- | --- |
| 服务器地址 | DNS 面板根地址，如 `https://panel.example.com`（结尾不要带 `/`） |
| API Token | DNS 面板中创建的 `dpan_` 开头令牌；留空表示保留已保存的值 |
| 启用自动续期 | 开启后每日自动执行"续期 → 部署 → 清理"流程 |

保存后回到**概览**页，「连接状态」显示 `已连接` 即配置成功。

---

## 使用

- **概览**：查看连接状态、自动续期开关、可用证书数、最近同步时间。
- **证书列表**：查看从 DNS 面板拉取的证书（已按域名取最新），点击「部署」自动匹配站点部署。
- **手动部署**：手动选择证书与站点进行部署。
- **立即同步**：拉取最新证书并自动部署到匹配站点，完成后清理被取代的过期证书。

---

## 自动续期工作原理

插件的自动续期由宝塔计划任务每日触发 `auto_sync`，按以下顺序执行（全部调用 DNS 面板的开放接口，鉴权使用 API Token）：

1. **续期** —— 调用 `POST /api/ssl/certificates/renew-expired`（`renewDays=7`）：面板为剩余 ≤ 7 天的域名申请新证书并自动添加 DNS 验证记录。证书签发为异步过程，新证书会在后续某次运行中被部署。
2. **部署** —— 按域名取剩余有效期最长的证书，部署到名称匹配的宝塔站点并重载 Web 服务。
3. **清理** —— 调用 `POST /api/ssl/certificates/prune-superseded`（`keepDays=7`）：当某域名已存在健康的新证书时，删除其 < 7 天的旧证书，并清理残留的 `_dnsauth.*` 验证记录。

> 该流程同样可在 DNS 面板侧独立开启（设置中的"自动续期"开关 + 后台定时任务），两者可单独或同时使用。Docker 长驻部署建议使用面板侧定时任务。

---

## 证书部署位置

证书写入宝塔标准证书目录：

```
/www/server/panel/vhost/cert/<站点名>/fullchain.pem   # 公钥（完整证书链）
/www/server/panel/vhost/cert/<站点名>/privkey.pem     # 私钥（权限 600）
```

部署后自动 `nginx -t && nginx -s reload`（或 Apache 对应命令）。

> **注意**：对于**从未在宝塔配置过 SSL** 的站点，仅写入证书文件可能不足以启用 HTTPS（需站点已有 SSL 监听块）。本插件主要用于已启用 SSL 站点的**证书续期/替换**场景。

---

## 调用的面板接口

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/api/ssl/certificates?credentialId=all` | 拉取证书列表 |
| GET | `/api/ssl/certificates/<id>/pem?credentialId=<cid>` | 获取证书 PEM（公钥 + 私钥） |
| POST | `/api/ssl/certificates/renew-expired` | 续期到期证书 |
| POST | `/api/ssl/certificates/prune-superseded` | 清理过期证书与验证记录 |

均使用请求头 `Authorization: Bearer dpan_xxx` 鉴权。

---

## 故障排查

| 现象 | 排查 |
| --- | --- |
| 概览显示「连接失败」 | 检查服务器地址是否可达、API Token 是否正确（`dpan_` 开头） |
| 证书列表为空 | 确认 DNS 面板中存在状态为 `已签发` 的证书 |
| 部署后 HTTPS 不生效 | 站点需先在宝塔启用过一次 SSL；本插件用于续期/替换 |
| 自动续期未执行 | 确认已开启开关、计划任务存在：`crontab -l \| grep dnspanel_ssl` |
| 计划任务日志 | `/www/server/panel/plugin/dnspanel_ssl/sync.log` |

---

## 安全说明

- API Token 保存在插件目录 `config.json`（权限 600），请妥善保管，泄露等同于面板 SSL 接口的访问权限。
- 插件仅请求证书内容与续期/清理接口，不涉及面板其它管理能力。
- 删除证书与清理验证记录为不可逆操作；面板侧 `prune-superseded` 带有安全约束：仅当域名存在更新的健康证书时才会删除其过期旧证书。

---

## 许可证

随主项目 [dns-panel](https://github.com/shifuf/dns-panel) 一同发布。
