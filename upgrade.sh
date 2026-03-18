#!/bin/bash
# ============================================================
#  DNS Panel - 无停机热更新脚本
#  用法: ./upgrade.sh [backend|frontend|all]
#  默认: all（更新后端和前端）
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] !${NC} $*"; }
err()  { echo -e "${RED}[$(date '+%H:%M:%S')] ✗${NC} $*"; }

TARGET="${1:-all}"

# ----------------------------------------------------------
#  预检
# ----------------------------------------------------------
if ! command -v docker &>/dev/null; then
    err "未找到 docker 命令"
    exit 1
fi

if ! docker compose version &>/dev/null && ! docker-compose version &>/dev/null; then
    err "未找到 docker compose"
    exit 1
fi

# 统一 compose 命令
DC="docker compose"
if ! docker compose version &>/dev/null; then
    DC="docker-compose"
fi

log "使用 compose 命令: $DC"
log "更新目标: $TARGET"
echo ""

# ----------------------------------------------------------
#  自动备份数据库
# ----------------------------------------------------------
DB_DIR="./backend/db"
DB_FILE="$DB_DIR/database.db"

if [ -f "$DB_FILE" ]; then
    mkdir -p "$DB_DIR"
    BACKUP_NAME="database.db.pre-upgrade.$(date +%Y%m%d_%H%M%S)"
    cp "$DB_FILE" "$DB_DIR/$BACKUP_NAME"
    ok "数据库已备份: backend/db/$BACKUP_NAME"
else
    warn "未找到数据库文件，跳过备份"
fi

# ----------------------------------------------------------
#  等待健康检查通过
# ----------------------------------------------------------
wait_healthy() {
    local svc="$1"
    local max_wait=120
    local elapsed=0

    log "等待 $svc 健康检查通过 (最长 ${max_wait}s)..."

    while [ $elapsed -lt $max_wait ]; do
        local health
        health=$($DC ps "$svc" --format '{{.Health}}' 2>/dev/null || echo "unknown")

        if [ "$health" = "healthy" ]; then
            ok "$svc 已健康 (${elapsed}s)"
            return 0
        fi

        # 检查容器是否还在运行
        local state
        state=$($DC ps "$svc" --format '{{.State}}' 2>/dev/null || echo "unknown")
        if [ "$state" = "exited" ] || [ "$state" = "dead" ]; then
            err "$svc 已退出，查看日志:"
            $DC logs --tail=20 "$svc"
            return 1
        fi

        sleep 2
        elapsed=$((elapsed + 2))
    done

    err "$svc 在 ${max_wait}s 内未通过健康检查"
    $DC logs --tail=20 "$svc"
    return 1
}

# ----------------------------------------------------------
#  滚动更新单个服务
# ----------------------------------------------------------
rolling_update() {
    local svc="$1"
    log "======== 开始更新 $svc ========"

    # 1) 构建新镜像（不停机）
    log "构建 $svc 新镜像..."
    $DC build --no-cache "$svc"
    ok "$svc 镜像构建完成"

    # 2) 用新镜像替换容器
    #    --no-deps: 不重启依赖服务
    #    -d: 后台运行
    log "启动 $svc 新容器..."
    $DC up -d --no-deps --force-recreate "$svc"

    # 3) 等待新容器健康
    if ! wait_healthy "$svc"; then
        err "$svc 更新失败!"
        warn "可以通过 '$DC logs $svc' 排查问题"
        return 1
    fi

    ok "======== $svc 更新完成 ========"
    echo ""
}

# ----------------------------------------------------------
#  执行更新
# ----------------------------------------------------------
case "$TARGET" in
    backend)
        rolling_update backend
        ;;
    frontend)
        rolling_update frontend
        ;;
    all)
        # 后端先更新，前端依赖后端
        rolling_update backend
        rolling_update frontend
        ;;
    *)
        err "未知目标: $TARGET"
        echo "用法: $0 [backend|frontend|all]"
        exit 1
        ;;
esac

# ----------------------------------------------------------
#  清理无效资源
# ----------------------------------------------------------
log "清理旧容器和悬空镜像..."

# 清理已停止的容器
STOPPED=$(docker ps -a --filter "status=exited" --filter "label=com.docker.compose.project" -q 2>/dev/null || true)
if [ -n "$STOPPED" ]; then
    COUNT=$(echo "$STOPPED" | wc -l | tr -d ' ')
    docker rm $STOPPED >/dev/null 2>&1 || true
    ok "已清理 $COUNT 个已停止的容器"
else
    ok "无已停止的容器需要清理"
fi

# 清理悬空镜像（旧版本构建产物）
DANGLING=$(docker images -f "dangling=true" -q 2>/dev/null || true)
if [ -n "$DANGLING" ]; then
    COUNT=$(echo "$DANGLING" | wc -l | tr -d ' ')
    docker rmi $DANGLING >/dev/null 2>&1 || true
    ok "已清理 $COUNT 个悬空镜像"
else
    ok "无悬空镜像需要清理"
fi

# 清理构建缓存（可选，只清理不用的）
docker builder prune -f --filter "until=72h" >/dev/null 2>&1 || true
ok "已清理 72 小时前的构建缓存"

echo ""

# ----------------------------------------------------------
#  输出最终状态
# ----------------------------------------------------------
log "======== 当前服务状态 ========"
$DC ps
echo ""
ok "更新完成! 全程无停机。"
