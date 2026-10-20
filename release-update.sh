#!/bin/bash
# ============================================================
#  DNS Panel - 无 git 环境 Release 更新脚本
#  用法: bash release-update.sh
#  流程: 下载 GitHub Release 产物 → 备份数据库 → 替换 backend 代码
#        → 重建容器（代码目录挂载覆盖镜像内代码）→ 健康检查
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'
log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')] OK${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] !${NC} $*"; }

RELEASE_TAG="${1:-}"
if [ -z "$RELEASE_TAG" ]; then
    log "获取 GitHub 最新 Release..."
    RELEASE_TAG="$(curl -fsSL -H 'User-Agent: dns-panel-updater' https://api.github.com/repos/shifuf/dns-panel/releases/latest | grep -o '"tag_name": *"[^"]*"' | head -1 | sed 's/.*"tag_name": *"//;s/"//')"
    if [ -z "$RELEASE_TAG" ]; then
        echo "无法获取最新 Release，请检查网络（也可手动指定：bash release-update.sh v0.30）" >&2
        exit 1
    fi
fi
log "目标版本: $RELEASE_TAG"

BASE_URL="https://github.com/shifuf/dns-panel/releases/download/${RELEASE_TAG}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# ── 0. compose 文件存在性检查 ──
if [ ! -f docker-compose.yml ]; then
    echo "未找到 docker-compose.yml，请在部署目录执行" >&2
    exit 1
fi

# ── 1. 备份数据库（compose 在线备份优先，失败退回文件拷贝） ──
backup_db() {
    local db_file="./backend/db/database.db"
    [ -f "$db_file" ] || { warn "未找到数据库文件，跳过备份"; return 0; }
    local backup_dir="./backend/db/_release-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    if docker compose exec -T backend python -c "
import sqlite3
src = sqlite3.connect('/app/db/database.db')
dst = sqlite3.connect('/tmp/release-backup.db')
src.backup(dst)
dst.close(); src.close()
print('online backup ok')
" >/dev/null 2>&1 \
       && docker compose cp backend:/tmp/release-backup.db "$backup_dir/database.db" >/dev/null 2>&1; then
        ok "数据库已在线备份: $backup_dir/database.db"
    else
        cp "$db_file" "$backup_dir/database.db"
        ok "数据库已拷贝备份: $backup_dir/database.db"
    fi
    ls -1dt ./backend/db/_release-backup-* 2>/dev/null | tail -n +11 | xargs -r rm -rf
}

# ── 2. 下载并解压 Release 产物 ──
log "下载 backend-build.zip / frontend-build.zip ..."
curl -fSL --retry 3 -o "$TMP_DIR/backend.zip"  "$BASE_URL/backend-build.zip"
curl -fSL --retry 3 -o "$TMP_DIR/frontend.zip" "$BASE_URL/frontend-build.zip"
rm -rf "$TMP_DIR/backend" "$TMP_DIR/frontend"
mkdir -p "$TMP_DIR/backend" "$TMP_DIR/frontend"
python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMP_DIR/backend.zip"  "$TMP_DIR/backend"  || unzip -qo "$TMP_DIR/backend.zip"  -d "$TMP_DIR/backend"
python3 -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])" "$TMP_DIR/frontend.zip" "$TMP_DIR/frontend" || unzip -qo "$TMP_DIR/frontend.zip" -d "$TMP_DIR/frontend"
[ -f "$TMP_DIR/backend/app.py" ]  || { echo "backend 产物校验失败" >&2; exit 1; }
[ -f "$TMP_DIR/frontend/index.html" ] || { echo "frontend 产物校验失败" >&2; exit 1; }
ok "Release 产物下载解压完成"

# ── 3. 备份数据库 ──
backup_db

# ── 4. 更新 backend 代码目录（保留 db/，compose 以只读挂载这些文件进容器） ──
log "更新 backend 代码..."
mkdir -p backend
rm -rf backend/app_backup
mkdir -p backend/app_backup
for item in app.py migrate.py requirements.txt entrypoint.sh start.py; do
    [ -f "backend/$item" ] && mv "backend/$item" backend/app_backup/
done
[ -d backend/modules ] && mv backend/modules backend/app_backup/modules
cp -a "$TMP_DIR/backend/app.py" "$TMP_DIR/backend/migrate.py" "$TMP_DIR/backend/requirements.txt" "$TMP_DIR/backend/entrypoint.sh" backend/ 2>/dev/null || true
[ -f "$TMP_DIR/backend/start.py" ] && cp -a "$TMP_DIR/backend/start.py" backend/
rm -rf backend/modules
cp -a "$TMP_DIR/backend/modules" backend/modules
sed -i 's/\r$//' backend/entrypoint.sh && chmod +x backend/entrypoint.sh
ok "backend 代码已替换（旧代码备份在 backend/app_backup/）"

# ── 5. 更新 frontend 静态文件（backend 托管 dist，无需 nginx 容器参与构建） ──
log "更新 frontend 静态文件..."
rm -rf frontend/dist.old
[ -d frontend/dist ] && mv frontend/dist frontend/dist.old
mkdir -p frontend/dist
cp -a "$TMP_DIR/frontend/." frontend/dist/
ok "frontend 静态文件已替换（旧文件备份在 frontend/dist.old/）"

# ── 6. 滚动重建容器 ──
log "拉取最新基础镜像并重建容器..."
docker compose pull backend >/dev/null 2>&1 || true
docker compose up -d --no-deps --force-recreate backend
log "等待 backend 健康..."
for i in $(seq 1 30); do
    if docker compose exec -T backend python -c "import urllib.request; urllib.request.urlopen('http://localhost:4001/health', timeout=3)" >/dev/null 2>&1; then
        ok "backend /health 探测通过"
        break
    fi
    [ "$i" = "30" ] && { echo "backend 健康检查超时" >&2; exit 1; }
    sleep 2
done
docker compose up -d frontend redis 2>/dev/null || docker compose up -d

ok "release 更新完成: $RELEASE_TAG"
log "验证方式: curl http://127.0.0.1:4001/health"
