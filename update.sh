#!/bin/bash
# ============================================================
#  DNS Panel - GitHub 拉取 + 无停机更新入口
#  用法: ./update.sh [backend|frontend|all]
#  默认: all
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TARGET="${1:-all}"
REMOTE="${GIT_REMOTE:-origin}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[$(date '+%H:%M:%S')]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date '+%H:%M:%S')] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] !${NC} $*"; }
err()  { echo -e "${RED}[$(date '+%H:%M:%S')] ✗${NC} $*"; }

if ! command -v git &>/dev/null; then
    err "未找到 git 命令"
    exit 1
fi

if [ ! -d ".git" ]; then
    err "当前目录不是 Git 仓库: $SCRIPT_DIR"
    exit 1
fi

if [ ! -f "./upgrade.sh" ]; then
    err "未找到升级脚本: ./upgrade.sh"
    exit 1
fi

BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
if [ -z "$BRANCH" ]; then
    err "当前仓库处于 detached HEAD，无法自动 pull"
    exit 1
fi

if ! git remote get-url "$REMOTE" >/dev/null 2>&1; then
    err "未找到 Git 远程: $REMOTE"
    exit 1
fi

if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
    err "检测到已跟踪文件存在未提交修改，请先提交或还原后再执行更新"
    git status --short
    exit 1
fi

OLD_HEAD="$(git rev-parse HEAD)"

log "获取远程更新: $REMOTE/$BRANCH"
git fetch --tags "$REMOTE"

REMOTE_HEAD="$(git rev-parse "$REMOTE/$BRANCH" 2>/dev/null || true)"
if [ -z "$REMOTE_HEAD" ]; then
    err "未找到远程分支: $REMOTE/$BRANCH"
    exit 1
fi

if [ "$OLD_HEAD" = "$REMOTE_HEAD" ]; then
    ok "当前已经是最新代码，无需从 GitHub 拉取"
    exit 0
fi

log "拉取最新代码..."
git pull --ff-only "$REMOTE" "$BRANCH"
NEW_HEAD="$(git rev-parse HEAD)"

if [ "$OLD_HEAD" = "$NEW_HEAD" ]; then
    warn "代码未发生变化，跳过服务更新"
    exit 0
fi

ok "代码已更新: ${OLD_HEAD:0:7} -> ${NEW_HEAD:0:7}"
log "开始执行无停机热更新..."

bash "./upgrade.sh" "$TARGET"
