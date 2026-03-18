# DNS 面板

一个功能强大的 DNS 管理面板，支持多服务商集成、SSL 证书管理和域名到期监控。

## 功能特性

- 🌍 **多服务商支持**：集成 Cloudflare、阿里云、DNSPod 等多个 DNS 服务商
- 📅 **域名到期监控**：自动监控域名到期时间，支持邮件和 Webhook 通知
- 🔒 **SSL 证书管理**：支持 SSL 证书的申请、续期和管理
- 🔐 **两步验证**：支持 TOTP 两步验证，增强账户安全性
- 💾 **数据备份**：支持数据备份和恢复，确保数据安全
- 📱 **响应式设计**：适配桌面端和移动端
- 🚀 **快速部署**：支持 Docker 容器化部署

## 快速开始

### 环境要求

- Docker & Docker Compose
- Git

### 部署步骤

1. **克隆仓库**

```bash
git clone https://github.com/shifuf/dns-panel.git
cd dns-panel
```

2. **配置环境变量**

编辑 `.env` 文件，设置必要的环境变量：

```env
# 服务器配置
PORT=4001

# 安全配置
JWT_SECRET=your-jwt-secret-key
ENCRYPTION_KEY=your-encryption-key

# 前端配置
CORS_ORIGIN=http://xxx:5174

# 数据库配置
DATABASE_URL=file:./database.db
```

3. **启动服务**

```bash
docker-compose up -d
```

4. **访问面板**

打开浏览器，访问 `http://xxx:5174`

## 技术栈

- **后端**：Python 3.10, SQLite
- **前端**：Vue 3, Naive UI
- **容器化**：Docker, Docker Compose
- **认证**：JWT, TOTP

## 目录结构

```
├── backend/         # 后端代码
│   ├── modules/     # 功能模块
│   ├── app.py       # 主应用
│   └── requirements.txt
├── frontend/        # 前端代码
│   ├── src/         # 源代码
│   └── public/      # 静态资源
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── README.md
```

## 核心功能

### 1. DNS 管理

- 添加和管理多个 DNS 服务商账户
- 支持批量操作 DNS 记录
- 实时同步 DNS 记录

### 2. 域名到期监控

- 自动检测域名到期时间
- 支持邮件通知
- 支持 Webhook 通知
- 可自定义提醒阈值

### 3. SSL 证书管理

- 支持申请和续期 SSL 证书
- 自动 DNS 验证
- 证书状态监控

### 4. 安全管理

- 两步验证 (2FA)
- 密码强度检测
- 操作日志记录

### 5. 数据备份

- 导出备份数据
- 导入恢复数据
- 支持选择性恢复

## 配置说明

### 环境变量

| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| PORT | 后端服务端口 | 4001 |
| JWT_SECRET | JWT 签名密钥 | - |
| ENCRYPTION_KEY | 数据加密密钥 | - |
| CORS_ORIGIN | 前端地址 | http://xxx:5174 |
| DATABASE_URL | 数据库路径 | file:./database.db |

### Docker 配置

使用 `docker-compose.yml` 配置文件管理容器：

```yaml
version: '3.8'

services:
  dns-panel:
    build: .
    ports:
      - "4001:4001"
    volumes:
      - ./data:/app/data
      - ./database.db:/app/database.db
    environment:
      - PORT=4001
      - JWT_SECRET=your-jwt-secret-key
      - ENCRYPTION_KEY=your-encryption-key
      - CORS_ORIGIN=http://xxx:5174
    restart: unless-stopped
```

## 更新流程

### 自动更新

```bash
# 赋予脚本执行权限
chmod +x update.sh

# 运行更新脚本
./update.sh
```

### 手动更新

```bash
# 拉取最新代码
git pull

# 停止并重新构建
docker-compose down
docker-compose build
docker-compose up -d
```

## 常见问题

### 1. 无法访问面板

- 检查容器是否运行：`docker-compose ps`
- 检查端口映射：确保 4001 端口已开放
- 检查环境变量配置

### 2. 服务商凭证验证失败

- 检查凭证信息是否正确
- 检查网络连接
- 检查服务商 API 权限设置

### 3. 域名到期监控不工作

- 检查通知设置
- 检查邮箱或 Webhook 配置
- 检查域名信息是否正确

## 贡献指南

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 打开 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详情请参阅 [LICENSE](LICENSE) 文件

## 联系方式

- 项目链接：[https://github.com/shifuf/dns-panel](https://github.com/shifuf/dns-panel)
- 问题反馈：[GitHub Issues](https://github.com/shifuf/dns-panel/issues)
