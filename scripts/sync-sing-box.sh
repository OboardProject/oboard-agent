#!/usr/bin/env bash
set -euo pipefail

AGENT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KERNEL_DIR="$AGENT_DIR/kernel/oboard-sb"
TARGET=${1:-latest}

echo "==> Syncing sing-box dependency: $TARGET"
go -C "$KERNEL_DIR" get "github.com/sagernet/sing-box@$TARGET"
go -C "$KERNEL_DIR" mod tidy

VERSION=$(go -C "$KERNEL_DIR" list -m -f '{{.Version}}' github.com/sagernet/sing-box)
case "$VERSION" in
  *-alpha.*|*-beta.*|*-rc.*)
    if [ "${OBOARD_ALLOW_PRERELEASE_SING_BOX:-0}" != "1" ]; then
      echo "Refusing prerelease sing-box $VERSION without OBOARD_ALLOW_PRERELEASE_SING_BOX=1" >&2
      exit 1
    fi
    CHANNEL=prerelease
    ;;
  *) CHANNEL=stable ;;
esac

for symbol in \
  protocol/vless.RegisterInbound protocol/vless.RegisterOutbound \
  protocol/hysteria2.RegisterInbound protocol/hysteria2.RegisterOutbound \
  protocol/anytls.RegisterInbound protocol/anytls.RegisterOutbound \
  protocol/shadowsocks.RegisterInbound protocol/shadowsocks.RegisterOutbound \
  protocol/socks.RegisterOutbound; do
  go -C "$KERNEL_DIR" doc "github.com/sagernet/sing-box/$symbol" >/dev/null
done

KERNEL_TAGS=${OBOARD_SB_TAGS:-with_utls}
go -C "$KERNEL_DIR" test -tags "$KERNEL_TAGS" ./...
CGO_ENABLED=0 go -C "$KERNEL_DIR" build -trimpath -tags "$KERNEL_TAGS" -o "$KERNEL_DIR/oboard-sb.sync-check" ./cmd/oboard-sb
rm -f "$KERNEL_DIR/oboard-sb.sync-check"
printf 'github.com/sagernet/sing-box %s\nchannel %s\nverified %s\n' \
  "$VERSION" "$CHANNEL" "$(date -u +%Y-%m-%d)" > "$KERNEL_DIR/UPSTREAM_VERSION"
echo "==> sing-box $VERSION synced and verified"
