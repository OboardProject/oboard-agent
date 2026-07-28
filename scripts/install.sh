#!/bin/sh
set -eu
(set -o pipefail) 2>/dev/null && set -o pipefail

CONTROLLER_URL=${OBOARD_CONTROLLER_URL:-${1:-}}
CONTROLLER_URL=${CONTROLLER_URL%/}
ACTION=${OBOARD_ACTION:-${2:-install}}
ENROLL_TOKEN=${OBOARD_ENROLL_TOKEN:-${3:-}}

if [ -z "$CONTROLLER_URL" ]; then
  echo "缺少主控地址。" >&2
  echo "请从面板复制服务器安装命令，或按下面的格式执行：" >&2
  echo "  curl -fsSL https://raw.githubusercontent.com/OboardProject/oboard-agent/main/scripts/install.sh | sudo env OBOARD_CONTROLLER_URL='https://panel.example.com' OBOARD_ENROLL_TOKEN='安装令牌' sh" >&2
  exit 1
fi

case "$ACTION" in
  install|update|uninstall) ;;
  *)
    echo "不支持的操作：$ACTION（可用：install、update、uninstall）" >&2
    exit 1
    ;;
esac

if [ "$ACTION" = install ] && [ -z "$ENROLL_TOKEN" ]; then
  echo "安装 Agent 需要面板生成的一次性安装令牌。" >&2
  echo "请先在主控面板添加服务器，再复制该服务器的安装命令。" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "安装需要写入系统目录，请切换到 root 或使用 sudo -E 重新执行。" >&2
  exit 1
fi

OBOARD_UPDATE_REPO=${OBOARD_UPDATE_REPO:-OboardProject/oboard-agent}
case "$OBOARD_UPDATE_REPO" in
  [A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*) ;;
  *) echo "更新仓库格式无效，请使用 owner/name 格式。" >&2; exit 1 ;;
esac

SCRIPT_TMP=$(mktemp "${TMPDIR:-/tmp}/oboard-agent-install.XXXXXX") || {
  echo "无法创建安装临时文件，请检查临时目录是否可用。" >&2
  exit 1
}
cleanup() { rm -f "$SCRIPT_TMP"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! curl --proto '=http,https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 -fsSL \
  "$CONTROLLER_URL/install/agent.sh" -o "$SCRIPT_TMP"; then
  echo "无法从主控下载安装程序，请确认主控地址和网络连接后重试。" >&2
  exit 1
fi

env \
  OBOARD_ACTION="$ACTION" \
  OBOARD_CONTROLLER_URL="$CONTROLLER_URL" \
  OBOARD_ENROLL_TOKEN="$ENROLL_TOKEN" \
  OBOARD_ALLOW_PANEL_UPDATE="${OBOARD_ALLOW_PANEL_UPDATE:-}" \
  OBOARD_UPDATE_SOURCE="${OBOARD_UPDATE_SOURCE:-}" \
  OBOARD_UPDATE_REPO="$OBOARD_UPDATE_REPO" \
  sh "$SCRIPT_TMP"
