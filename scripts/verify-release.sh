#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
KERNEL_TAGS=${OBOARD_SB_TAGS:-with_utls,with_gvisor}
normalized=",${KERNEL_TAGS// /,},"
for required in with_utls with_gvisor; do
  case "$normalized" in
    *",$required,"*) ;;
    *) echo "OBOARD_SB_TAGS must include $required" >&2; exit 1 ;;
  esac
done
command -v go >/dev/null || { echo 'go is required' >&2; exit 1; }
command -v govulncheck >/dev/null || {
  echo 'Install golang.org/x/vuln/cmd/govulncheck@v1.8.0 before verification' >&2
  exit 1
}
CACHE_ROOT=${OBOARD_VERIFY_CACHE_ROOT:-"$ROOT/../.cache"}
mkdir -p "$CACHE_ROOT"
CACHE=$(mktemp -d "$CACHE_ROOT/verify-release.XXXXXX")
cleanup() {
  local status=$?
  if ! chmod -R u+w "$CACHE" || ! rm -rf "$CACHE"; then
    echo 'Failed to clean verification cache' >&2
    if [ "$status" -eq 0 ]; then status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
export CGO_ENABLED=0 GOWORK=off GOCACHE="$CACHE/go" GOTMPDIR="$CACHE/tmp" GOMODCACHE="$CACHE/mod"
mkdir -p "$GOCACHE" "$GOTMPDIR" "$GOMODCACHE"
for module in "$ROOT" "$ROOT/kernel/oboard-sb"; do
  (
    cd "$module"
    set --
    if [ "$module" != "$ROOT" ]; then set -- -tags "$KERNEL_TAGS"; fi
    go test "$@" ./...
    go vet "$@" ./...
    go mod verify
    govulncheck "$@" ./...
  )
done
