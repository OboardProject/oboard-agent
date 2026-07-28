#!/bin/sh
set -eu
(set -o pipefail) 2>/dev/null && set -o pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export OBOARD_ACTION=update

CONTROLLER_URL=${OBOARD_CONTROLLER_URL:-${1:-}}
if [ -z "$CONTROLLER_URL" ]; then
  echo "缺少主控地址，请设置 OBOARD_CONTROLLER_URL。" >&2
  exit 1
fi

if [ -x "$SCRIPT_DIR/install.sh" ]; then
  exec env OBOARD_ACTION=update OBOARD_CONTROLLER_URL="$CONTROLLER_URL" "$SCRIPT_DIR/install.sh"
fi

SCRIPT_TMP=$(mktemp "${TMPDIR:-/tmp}/oboard-agent-update.XXXXXX") || {
  echo "无法创建更新临时文件，请检查临时目录是否可用。" >&2
  exit 1
}
cleanup() { rm -f "$SCRIPT_TMP"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
if ! curl --proto '=http,https' --proto-redir '=https' --tlsv1.2 --connect-timeout 10 --max-time 60 -fsSL \
  "${CONTROLLER_URL%/}/install/agent.sh" -o "$SCRIPT_TMP"; then
  echo "无法从主控下载更新程序，请确认主控地址和网络连接后重试。" >&2
  exit 1
fi
env OBOARD_ACTION=update OBOARD_CONTROLLER_URL="${CONTROLLER_URL%/}" sh "$SCRIPT_TMP"
