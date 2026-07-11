# DNS 面板

> 一体化的多服务商 DNS 管理面板：统一管理 DNS 解析、SSL 证书、边缘加速与域名到期监控，并提供宝塔 SSL 同步插件。

支持 Cloudflare、DNSPod、阿里云、腾讯云 EdgeOne 等多家服务商，内置 SSL 证书自动续期、API Token 集成与操作审计。

---

## 功能特性

| 模块 | 说明 |
| --- | --- |
| 🌍 多服务商 DNS | 统一管理 Cloudflare / DNSPod / 阿里云 等账户，支持记录的批量启用/禁用、批量删除、线路、备注、权重 |
| 📅 域名到期监控 | 基于 RDAP 自动查询到期时间（结果缓存），支持邮件 / Webhook 告警与到期窗口预警 |
| 🔒 SSL 证书管理 | 腾讯云 DV 证书申请、DNS 自动验证、续期、下载、上传第三方证书 |
| ♻️ SSL 自动续期 | 剩余 ≤ 7 天自动续期，失败支持邮件 / Webhook / 企业微信告警，并自动清理过期成功任务与执行日志 |
| ⚡ 边缘加速 | 腾讯云 EdgeOne 加速域名管理、阿里云 ESA 站点管理 |
| 🔗 Cloudflare Tunnel | Tunnel 与自定义主机名（Custom Hostnames）管理 |
| 🧩 宝塔 SSL 同步插件 | 通过 API Token 将证书同步部署到宝塔站点（见 `baota-ssl-plugin/`） |
| 🔑 API Token | 长期访问令牌，供外部集成（如宝塔插件）调用面板接口 |
| 🔐 安全 | JWT 登录、TOTP 两步验证、操作审计日志 |
| 📊 运营仪表盘 | 同步任务中心、告警中心、域名标签、保存视图、健康分统计 |
| 💾 数据备份 | 备份导出与选择性恢复 |
| 📱 响应式 UI | 适配桌面与移动端 |

---

## 技术栈

- **后端**：Python（标准库 `http.server`，`ThreadingHTTPServer`）、SQLite；**Redis 可选**（不可用时自动降级为进程内缓存，带连接熔断，不影响功能与性能）
- **前端**：Vue 3 + TypeScript + Naive UI + TailwindCSS + Vite + TanStack Query + Pinia
- **认证**：JWT + TOTP（两步验证）
- **容器化**：Docker / Docker Compose（Redis + 后端 + 前端三服务）

---

## 架构概览

```
┌────────────┐      ┌─────────────────────┐      ┌──────────────┐
│  前端 (Vue) │ ───▶ │  后端 (Python/SQLite) │ ───▶ │ 各服务商 API  │
│  Nginx :80  │      │       :4001          │      │ CF/DNSPod/腾讯 │
└────────────┘      └─────────┬───────────┘      └──────────────┘
                              │
                       ┌──────┴──────┐   ┌──────────────────────┐
                       │ Redis(可选) │   │ 宝塔 SSL 同步插件      │
                       └─────────────┘   │ (API Token 调用面板)   │
                                         └──────────────────────┘
```

> 后端也可直接托管前端构建产物（存在 `frontend/dist` 或设置 `FRONTEND_DIST` 时），实现**单进程**运行，仅暴露 `:4001`。

---

## 快速开始（Docker Compose）

### 环境要求
- Docker & Docker Compose
- Git

### 部署步骤

```bash
# 1. 克隆
git clone https://github.com/shifuf/dns-panel.git
cd dns-panel

# 2. 配置环境变量（务必修改密钥）
cp .env.example .env
#   编辑 .env：设置 JWT_SECRET、ENCRYPTION_KEY（32 字符）等

# 3. 启动（redis + 后端 + 前端）
docker compose up -d
```

访问：**`http://<服务器IP>:8080`**（前端容器，反代后端 `:4001`）。

> 首次从 `ghcr.io` 拉取镜像若为私有，需先 `docker login ghcr.io`。

---

## 本地 / 单进程运行（不依赖 Docker）

```bash
# 后端
cd backend && python app.py            # 监听 :4001，自动建表、自动加载同目录/上级 .env

# 前端（开发）
cd frontend && npm install && npm run dev     # :5174，/api 反代到 :4001

# 前端（生产，单进程托管）
cd frontend && npm run build           # 生成 dist/
# 后端检测到 frontend/dist 后会直接托管它 → 访问 http://<host>:4001
```

---

## 配置说明（环境变量）

| 变量名 | 描述 | 默认值 |
| --- | --- | --- |
| `PORT` | 后端服务端口 | `4001` |
| `JWT_SECRET` | JWT 签名密钥（≥32 字符） | 内置开发默认值，**生产必须修改** |
| `ENCRYPTION_KEY` | 凭证加密密钥（32 字符） | 内置开发默认值，**生产必须修改** |
| `CORS_ORIGIN` | 允许的前端来源 | `http://localhost:8080` |
| `DATABASE_URL` | 数据库路径（`file:` 前缀） | 容器内 `file:/app/db/database.db` |
| `REDIS_URL` | Redis 连接串（可选） | `redis://localhost:6379/0` |
| `FRONTEND_DIST` | 后端托管的前端构建目录（可选） | `../frontend/dist` |

> ⚠️ **关于 `ENCRYPTION_KEY`（重要）**：凭证、2FA 密钥、SMTP 密码等以该密钥加密存储。
> - **迁移 / 备份数据库到新环境时，必须携带相同的 `ENCRYPTION_KEY`**，否则凭证无法解密。
> - 修改密钥需对存量数据重新加密，可使用 `backend/reencrypt_keys.py`（设置 `OLD_ENCRYPTION_KEY` / `NEW_ENCRYPTION_KEY` 后运行，会先备份数据库）。
> - 本地 `.env` 已被 `.gitignore`，不会上传；各环境各自维护。

---

## 目录结构

```
├── backend/                  # 后端
│   ├── app.py                # 主应用（路由分发、鉴权、静态托管、定时任务）
│   ├── migrate.py            # 数据库迁移（启动时自动执行，幂等）
│   ├── reencrypt_keys.py     # 凭证密钥迁移工具
│   └── modules/              # 服务商 API、缓存、SSL、加速、路由处理等
├── frontend/                 # 前端（Vue 3 + Vite）
│   └── src/{pages,components,services,stores}
├── baota-ssl-plugin/         # 宝塔 SSL 同步插件（含独立 README）
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## 宝塔 SSL 同步插件

`baota-ssl-plugin/` 是配套的宝塔面板插件，通过 **API Token** 对接本面板，自动将已签发证书部署到一个或多个匹配的宝塔站点，并支持每日自动续期、按域名取最新证书、清理过期证书与验证记录。

详见 [`baota-ssl-plugin/README.md`](baota-ssl-plugin/README.md)。

使用前在面板「设置 → API Token」创建 `dpan_` 开头的令牌填入插件即可。

---

## 更新流程

### GitHub 自动发布
- 推送到 `main` 后自动触发 GitHub Actions 发布
- 基于最新 `v*` 标签自动递增版本号（起始 `v0.02`）
- Release 附带 `frontend-build.zip` / `backend-build.zip`
- 自动发布 Docker 镜像到 `ghcr.io/shifuf/dns-panel-backend` 与 `ghcr.io/shifuf/dns-panel-frontend`

### Docker 一键更新
```bash
docker compose up -d --pull always                       # 跟随最新发布
DNS_PANEL_VERSION=v0.24 docker compose up -d --pull always   # 固定到指定版本
```

### 脚本更新
```bash
chmod +x update.sh
./update.sh            # 拉取最新代码并无停机更新前后端
./update.sh backend    # 仅后端
./update.sh frontend   # 仅前端
```

> **数据库迁移无缝**：迁移在后端启动时自动执行，均为幂等 `CREATE TABLE/INDEX IF NOT EXISTS`，不修改既有数据，更新无需手动操作、不会丢数据。**升级时切勿更换生产 `ENCRYPTION_KEY`。**

---

## 常见问题

| 问题 | 排查 |
| --- | --- |
| 无法访问面板 | `docker compose ps` 查看容器状态；确认 `:8080`/`:4001` 端口开放 |
| 凭证验证失败 | 检查凭证信息、网络连通性、服务商 API 权限 |
| 升级后凭证无法解密 | `ENCRYPTION_KEY` 与加密时不一致 —— 恢复原密钥，或用 `reencrypt_keys.py` 迁移 |
| 列表加载慢 | 确认后端已重启加载最新代码；Redis 不是必需（已内置内存兜底） |
| 域名到期监控不工作 | 检查邮件 / Webhook 配置与域名信息 |

---

## 贡献指南

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feat/xxx`
3. 提交更改（建议使用 `feat: / fix: / docs:` 等约定式提交）
4. 推送并发起 Pull Request

---

## 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE)。

## 联系方式

- 项目地址：<https://github.com/shifuf/dns-panel>
- 问题反馈：<https://github.com/shifuf/dns-panel/issues>
