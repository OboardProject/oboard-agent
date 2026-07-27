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

curl --proto '=https' --tlsv1.2 -fsSL "${CONTROLLER_URL%/}/install/agent.sh" | \
  env OBOARD_ACTION=update OBOARD_CONTROLLER_URL="${CONTROLLER_URL%/}" sh
