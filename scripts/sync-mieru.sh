#!/bin/sh
# sync-mieru.sh — regenerate the Mieru fork from upstream and reapply the
# logical-clock patch. The fork lives at kernel/oboard-sb/third_party/mieru
# and must stay byte-identical to upstream plus the patch in
# kernel/oboard-sb/third_party/mieru-clock.patch.
#
# Usage: ./scripts/sync-mieru.sh [v3.x.y]   (defaults to the go.mod pin)

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KERNEL_DIR="$SCRIPT_DIR/../kernel/oboard-sb"
FORK_DIR="$KERNEL_DIR/third_party/mieru"
PATCH_FILE="$KERNEL_DIR/third_party/mieru-clock.patch"
VERSION_FILE="$KERNEL_DIR/third_party/mieru-version"

cd "$KERNEL_DIR"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION=$(sed -n 's/^[[:space:]]*github.com\/enfein\/mieru\/v3 v\(.*\)$/\1/p' go.mod | head -1)
fi
case "$VERSION" in
  v*) ;;
  *) VERSION="v$VERSION" ;;
esac
if [ -z "$VERSION" ]; then
  echo "error: no Mieru version pinned in go.mod and no version argument" >&2
  exit 1
fi

echo "==> downloading github.com/enfein/mieru/v3@$VERSION"
go mod download "github.com/enfein/mieru/v3@$VERSION"

GOMODCACHE_DIR=$(go env GOMODCACHE)
UPSTREAM_DIR="$GOMODCACHE_DIR/github.com/enfein/mieru/v3@$VERSION"
if [ ! -d "$UPSTREAM_DIR" ]; then
  echo "error: upstream module not found in module cache: $UPSTREAM_DIR" >&2
  exit 1
fi

echo "==> refreshing fork tree from upstream"
rm -rf "$FORK_DIR"
mkdir -p "$FORK_DIR"
cp -R "$UPSTREAM_DIR/." "$FORK_DIR/"
chmod -R u+w "$FORK_DIR"

echo "==> applying $PATCH_FILE"
(
  cd "$FORK_DIR"
  git init -q .
  git apply -p1 "$PATCH_FILE"
  rm -rf .git
)

echo "==> verifying fork delta matches the committed patch"
DIFF_DIR=$(mktemp -d "${TMPDIR:-/tmp}/oboard-mieru-diff.XXXXXX")
trap 'rm -rf "$DIFF_DIR"' EXIT
cp -R "$UPSTREAM_DIR/." "$DIFF_DIR/upstream/"
cp -R "$FORK_DIR/." "$DIFF_DIR/fork/"
chmod -R u+w "$DIFF_DIR"
(
  cd "$DIFF_DIR"
  # exit 1 is expected: upstream and fork differ by design
  git diff --no-index --no-prefix upstream fork > regenerated.patch || true
)
if ! cmp -s "$DIFF_DIR/regenerated.patch" "$PATCH_FILE"; then
  echo "error: fork tree differs from upstream plus the committed patch" >&2
  exit 1
fi

echo "==> updating module pin and verifying"
go mod edit -require="github.com/enfein/mieru/v3@$VERSION"
go mod tidy
go mod verify
go vet ./...
go test -tags with_utls,with_gvisor ./...

for symbol in \
  pkg/cipher.SetTimeFunc pkg/protocol.SetTimeFunc \
  apis/client.ClientConfig apis/common.DNSResolver \
  apis/common.StreamListenerFactory apis/common.PacketListenerFactory \
  apis/server.ServerConfig; do
  go doc "github.com/enfein/mieru/v3/$symbol" >/dev/null
done

printf 'github.com/enfein/mieru/v3 %s\nverified %s\n' \
  "$VERSION" "$(date -u +%Y-%m-%d)" > "$VERSION_FILE"
echo "==> Mieru $VERSION synced and verified"
