#!/bin/bash

# 设置环境变量
export PORT=4001
export NODE_ENV=production
export DATABASE_URL=file:./db/database.db
export JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-please-min-32-chars
export ENCRYPTION_KEY=please-change-to-32-char-key!!
export CORS_ORIGIN=http://localhost:8080
export JWT_EXPIRES_IN=7d
export LOG_RETENTION_DAYS=90

echo "========================================"
echo "  DNS Panel - Python 后端启动"
echo "========================================"
echo ""
echo "数据库路径: $DATABASE_URL"
echo "监听端口: $PORT"
echo "CORS 允许: $CORS_ORIGIN"
echo ""
echo "按 Ctrl+C 停止服务"
echo ""

# 启动 Python 后端
python3 app.py
