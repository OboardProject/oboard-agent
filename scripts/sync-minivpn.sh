#!/bin/sh
# sync-minivpn.sh — regenerate the OpenVPN client fork from upstream minivpn.
# The fork lives at kernel/oboard-sb/third_party/minivpn and must stay
# byte-identical to the upstream protocol subset (internal/ and pkg/config,
# pkg/tunnel, without upstream tests) plus the patch in
# kernel/oboard-sb/third_party/minivpn-oboard.patch.
#
# Usage: ./scripts/sync-minivpn.sh [v0.0.x]   (defaults to the pinned version)

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KERNEL_DIR="$SCRIPT_DIR/../kernel/oboard-sb"
FORK_DIR="$KERNEL_DIR/third_party/minivpn"
PATCH_FILE="$KERNEL_DIR/third_party/minivpn-oboard.patch"
VERSION_FILE="$KERNEL_DIR/third_party/minivpn-version"
INTERNAL_PACKAGES="bytesx controlchannel datachannel model networkio optional packetmuxer reliabletransport runtimex session tlssession tun workers"
PKG_PACKAGES="config tunnel"

cd "$KERNEL_DIR"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(sed -n 's/^[[:space:]]*github.com\/ooni\/minivpn v\(.*\)$/\1/p' go.mod | head -1)
fi
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac
if [ "$VERSION" = "v" ]; then
  echo "error: no minivpn version pinned in go.mod and no version argument" >&2
  exit 1
fi

echo "==> downloading github.com/ooni/minivpn@$VERSION"
GOFLAGS=-mod=mod go mod download "github.com/ooni/minivpn@$VERSION"
UPSTREAM_DIR="$(go env GOMODCACHE)/github.com/ooni/minivpn@$VERSION"
if [ ! -d "$UPSTREAM_DIR" ]; then
  echo "error: upstream module not found in module cache: $UPSTREAM_DIR" >&2
  exit 1
fi

copy_subset() {
  dest="$1"
  mkdir -p "$dest/internal" "$dest/pkg"
  cp "$UPSTREAM_DIR/LICENSE" "$UPSTREAM_DIR/go.mod" "$dest/"
  for pkg in $INTERNAL_PACKAGES; do
    cp -R "$UPSTREAM_DIR/internal/$pkg" "$dest/internal/"
  done
  for pkg in $PKG_PACKAGES; do
    cp -R "$UPSTREAM_DIR/pkg/$pkg" "$dest/pkg/"
  done
  chmod -R u+w "$dest"
  find "$dest" -name '*_test.go' -exec rm -f {} +
}

echo "==> refreshing fork tree from upstream subset"
rm -rf "$FORK_DIR"
copy_subset "$FORK_DIR"

echo "==> applying $PATCH_FILE"
(
  cd "$FORK_DIR"
  git init -q .
  git apply -p1 "$PATCH_FILE"
  rm -rf .git
)

echo "==> verifying fork delta matches the committed patch"
DIFF_DIR=$(mktemp -d "${TMPDIR:-/tmp}/oboard-minivpn-diff.XXXXXX")
trap 'rm -rf "$DIFF_DIR"' EXIT
copy_subset "$DIFF_DIR/upstream"
cp -R "$FORK_DIR/." "$DIFF_DIR/fork/"
(
  cd "$DIFF_DIR"
  # exit 1 is expected: upstream and fork differ by design
  git diff --no-index --no-prefix upstream fork > regenerated.patch || true
)
if ! cmp -s "$DIFF_DIR/regenerated.patch" "$PATCH_FILE"; then
  echo "error: fork tree differs from upstream plus the committed patch" >&2
  exit 1
fi

echo "==> verifying the fork and the kernel"
(cd "$FORK_DIR" && GOWORK=off go vet ./... && GOWORK=off go test ./...)
go mod edit -require="github.com/ooni/minivpn@$VERSION"
go mod tidy
go vet -tags with_utls,with_gvisor ./internal/protocol/openvpn ./internal/protocol/vpngatepool
go test -tags with_utls,with_gvisor ./internal/protocol/openvpn ./internal/protocol/vpngatepool

printf 'github.com/ooni/minivpn %s\nverified %s\n' \
  "$VERSION" "$(date -u +%Y-%m-%d)" > "$VERSION_FILE"
echo "==> minivpn $VERSION synced and verified"
