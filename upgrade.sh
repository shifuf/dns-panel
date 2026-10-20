#!/bin/bash
# ============================================================
#  DNS Panel - 无停机热更新（update.sh 的执行阶段）
#  用法: ./upgrade.sh [backend|frontend|all]
#  流程: 拉取新镜像 → 备份数据库 → 滚动重建 → 健康检查确认
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-all}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')] OK${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] !${NC} $*"; }

if ! command -v docker &>/dev/null; then
    echo "未找到 docker 命令" >&2
    exit 1
fi

SERVICES=()
case "$TARGET" in
    backend)  SERVICES=(backend) ;;
    frontend) SERVICES=(frontend) ;;
    all)      SERVICES=(backend frontend) ;;
    *) echo "无效目标: $TARGET（可选 backend / frontend / all）" >&2; exit 1 ;;
esac

# -- 1. 备份数据库（仅更新 backend / all 时） --
backup_db() {
    local db_file="./backend/db/database.db"
    [ -f "$db_file" ] || { warn "未找到数据库文件，跳过备份"; return 0; }
    local backup_dir="./backend/db/_upgrade-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"
    # 首选：容器内 sqlite 在线备份（保证一致性），失败再退回文件拷贝
    if docker compose exec -T backend python -c "
import sqlite3
src = sqlite3.connect('/app/db/database.db')
dst = sqlite3.connect('/tmp/upgrade-backup.db')
src.backup(dst)
dst.close(); src.close()
print('online backup ok')
" >/dev/null 2>&1 \
       && docker compose cp backend:/tmp/upgrade-backup.db "$backup_dir/database.db" >/dev/null 2>&1; then
        ok "数据库已在线备份: $backup_dir/database.db"
    else
        cp "$db_file" "$backup_dir/database.db"
        ok "数据库已拷贝备份: $backup_dir/database.db"
    fi
    ls -1dt ./backend/db/_upgrade-backup-* 2>/dev/null | tail -n +11 | xargs -r rm -rf
}

# -- 2. 拉取新镜像 --
log "拉取新镜像: ${SERVICES[*]}"
docker compose pull "${SERVICES[@]}"

# -- 3. 数据库备份（backend 涉及表结构迁移，务必先备份） --
if [ "$TARGET" = "backend" ] || [ "$TARGET" = "all" ]; then
    backup_db
fi

# -- 4. 滚动重建并等待健康检查 --
log "滚动重建服务: ${SERVICES[*]}"
if ! docker compose up -d --no-deps --wait "${SERVICES[@]}"; then
    echo "服务未能达到健康状态，请检查日志: docker compose logs -f --tail=100 ${SERVICES[*]}" >&2
    exit 1
fi

# -- 5. 最终健康确认 --
confirm_backend_health() {
    local i
    for i in $(seq 1 30); do
        if docker compose exec -T backend python -c \
            "import urllib.request; urllib.request.urlopen('http://localhost:4001/health', timeout=3)" \
            >/dev/null 2>&1; then
            ok "backend /health 探测通过"
            return 0
        fi
        sleep 2
    done
    echo "backend 健康检查超时，请人工确认: docker compose logs -f backend" >&2
    return 1
}

for svc in "${SERVICES[@]}"; do
    if docker compose ps --status running --services | grep -qx "$svc"; then
        ok "服务已运行: $svc"
    else
        echo "服务未运行: $svc" >&2
        exit 1
    fi
done

if [ "$TARGET" = "backend" ] || [ "$TARGET" = "all" ]; then
    confirm_backend_health || exit 1
fi

ok "热更新完成（重建间隙 < 数秒，健康检查已确认）"
log "当前服务状态:"
docker compose ps
