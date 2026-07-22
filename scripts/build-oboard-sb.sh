#!/usr/bin/env bash
set -euo pipefail

AGENT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KERNEL_DIR="$AGENT_DIR/kernel/oboard-sb"
VERSION_VALUE=${VERSION:-$(tr -d '[:space:]' < "$AGENT_DIR/VERSION")}
BUILD_VALUE=${BUILD:-${BUILD_NUMBER:-$(date -u +%Y%m%d%H%M%S)}}
COMMIT_VALUE=${COMMIT:-$(git -C "$AGENT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}
DATE_VALUE=${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
TARGET_OS=${GOOS:-$(go env GOOS)}
TARGET_ARCH=${GOARCH:-$(go env GOARCH)}
TAGS=${OBOARD_SB_TAGS:-with_utls}
OUT=${OUT:-$AGENT_DIR/dist/bin/$TARGET_OS-$TARGET_ARCH/oboard-sb}
SING_BOX_MODULE_VERSION=${SING_BOX_VERSION:-$(go -C "$KERNEL_DIR" list -m -f '{{.Version}}' github.com/sagernet/sing-box)}
SING_BOX_VERSION_VALUE=${SING_BOX_MODULE_VERSION#v}

case "$SING_BOX_VERSION_VALUE" in
  ""|"(devel)"|unknown)
    echo "Unable to resolve a release sing-box module version: $SING_BOX_MODULE_VERSION" >&2
    exit 1
    ;;
esac

mkdir -p "$(dirname "$OUT")"
LDFLAGS="-s -w -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Version=$VERSION_VALUE -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Build=$BUILD_VALUE -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Commit=$COMMIT_VALUE -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Date=$DATE_VALUE -X github.com/sagernet/sing-box/constant.Version=$SING_BOX_VERSION_VALUE"

CGO_ENABLED=0 GOOS="$TARGET_OS" GOARCH="$TARGET_ARCH" \
  go -C "$KERNEL_DIR" build -trimpath -tags "$TAGS" -ldflags "$LDFLAGS" -o "$OUT" ./cmd/oboard-sb

echo "$OUT"
