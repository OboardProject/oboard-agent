#!/usr/bin/env bash
set -euo pipefail

AGENT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KERNEL_DIR="$AGENT_DIR/kernel/oboard-sb"
TARGET=${1:-latest}
KERNEL_TAGS=${OBOARD_SB_TAGS:-with_utls,with_gvisor}

require_kernel_tag() {
  local normalized=",${KERNEL_TAGS// /,},"
  case "$normalized" in
    *",$1,"*) ;;
    *)
      echo "OBOARD_SB_TAGS must include $1" >&2
      exit 1
      ;;
  esac
}
require_kernel_tag with_utls
require_kernel_tag with_gvisor

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
  adapter/inbound.Register adapter/outbound.Register adapter.DNSRouter \
  common/listener.Listener.ListenTCP common/listener.Listener.ListenUDP \
  protocol/vless.RegisterInbound protocol/vless.RegisterOutbound \
  protocol/hysteria2.RegisterInbound protocol/hysteria2.RegisterOutbound \
  protocol/anytls.RegisterInbound protocol/anytls.RegisterOutbound \
  protocol/shadowsocks.RegisterInbound protocol/shadowsocks.RegisterOutbound \
  protocol/socks.RegisterOutbound; do
  go -C "$KERNEL_DIR" doc "github.com/sagernet/sing-box/$symbol" >/dev/null
done

for symbol in \
  apis/client.ClientConfig apis/common.DNSResolver \
  apis/common.StreamListenerFactory apis/common.PacketListenerFactory \
  apis/server.ServerConfig; do
  go -C "$KERNEL_DIR" doc "github.com/enfein/mieru/v3/$symbol" >/dev/null
done

go -C "$KERNEL_DIR" test -tags "$KERNEL_TAGS" ./...
SYNC_CHECK=$(mktemp "${TMPDIR:-/tmp}/oboard-sb-sync-check.XXXXXX")
trap 'rm -f "$SYNC_CHECK"' EXIT
CGO_ENABLED=0 go -C "$KERNEL_DIR" build -trimpath -tags "$KERNEL_TAGS" -o "$SYNC_CHECK" ./cmd/oboard-sb
rm -f "$SYNC_CHECK"
trap - EXIT
printf 'github.com/sagernet/sing-box %s\nchannel %s\nverified %s\n' \
  "$VERSION" "$CHANNEL" "$(date -u +%Y-%m-%d)" > "$KERNEL_DIR/UPSTREAM_VERSION"
echo "==> sing-box $VERSION synced and verified"
