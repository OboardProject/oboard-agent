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

echo "OBoard Agent 安装程序"
echo "====================="
echo "主控地址：$CONTROLLER_URL"
echo "操作：$ACTION"
echo ""
echo "Controller 和 Agent 相互独立，可以安装在同一台服务器上。"
echo "Agent 使用独立的服务名和数据目录，不会覆盖 oboard-controller。"
echo "兼容：Debian/Ubuntu、Alpine、CentOS/RHEL/Rocky/Alma、常见 LXC/KVM 模板（systemd 或 OpenRC）。"
echo ""

OBOARD_UPDATE_REPO=${OBOARD_UPDATE_REPO:-OboardProject/oboard-agent}
case "$OBOARD_UPDATE_REPO" in
  [A-Za-z0-9_.-]*/[A-Za-z0-9_.-]*) ;;
  *) echo "OBOARD_UPDATE_REPO must look like owner/name" >&2; exit 1 ;;
esac

curl -fsSL "$CONTROLLER_URL/install/agent.sh" | env \
  OBOARD_ACTION="$ACTION" \
  OBOARD_CONTROLLER_URL="$CONTROLLER_URL" \
  OBOARD_ENROLL_TOKEN="$ENROLL_TOKEN" \
  OBOARD_ALLOW_PANEL_UPDATE="${OBOARD_ALLOW_PANEL_UPDATE:-}" \
  OBOARD_UPDATE_SOURCE="${OBOARD_UPDATE_SOURCE:-}" \
  OBOARD_UPDATE_REPO="$OBOARD_UPDATE_REPO" \
  sh
