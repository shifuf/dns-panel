# Python Backend V2 (重构版)

当前目录为后端 Python 重构版本，保持 Vue 前端 `/api/*` 协议不变。

## 当前实现状态

已原生实现的路由分组：

- `/api/auth/*`（含 `2fa` 全流程）
- `/api/dns-credentials/*`（含 `providers` 与 `verify`）
- `/api/dns-records/*`
- `/api/hostnames/*`
- `/api/tunnels/*`
- `/api/aliyun-esa/*`
- `/api/logs/*`
- `/api/domain-expiry/*`
- `/api/dashboard/*`

说明：

- `dns-records` 当前为 Cloudflare 路径原生可用；其他 provider 的记录操作会返回明确错误提示（不再回退 Node）。
- 未匹配到的其他历史路径仍保留 `_proxy` 兜底能力。

## 模块化结构

- `app.py`: HTTP 入口、基础能力、路由分发（轻量化）
- `modules/route_handlers.py`: 各业务路由组实现（auth/dns-credentials/dns-records/hostnames/tunnels/aliyun-esa/logs/domain-expiry/dashboard）
- `modules/provider_catalog.py`: 多 provider 能力矩阵
- `modules/two_factor.py`: TOTP/otpauth/二维码数据封装
- `modules/cloudflare_api.py`: Cloudflare API 封装（Zones/Records/Hostnames/Tunnels）
- `modules/aliyun_esa_api.py`: Aliyun ESA 签名与接口封装
- `start.py`: Python v2 单独启动入口
- `start_python_backend.ps1`: Python v2 单独启动脚本
- `start_dual_backend.ps1`: 双后端联调脚本（Python + legacy Node）

## 启动

```powershell
.\python-backend-v2\start_dual_backend.ps1
```

或仅启动 Python v2：

```powershell
.\python-backend-v2\start_python_backend.ps1
```

默认端口：

- Python v2: `4001`（前端应指向此端口）
- Node legacy: `4101`（仅用于兜底场景）
