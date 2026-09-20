#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CACHE_ROOT=${OBOARD_VERIFY_CACHE_ROOT:-"$ROOT/../.cache"}
mkdir -p "$CACHE_ROOT"
TEST_DIR=$(mktemp -d "$CACHE_ROOT/verify-release-test.XXXXXX")
cleanup() {
  local status=$?
  if ! chmod -R u+w "$TEST_DIR" || ! rm -rf "$TEST_DIR"; then
    echo 'Failed to clean verification test directory' >&2
    if [ "$status" -eq 0 ]; then status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
mkdir -p "$TEST_DIR/bin"
cat > "$TEST_DIR/bin/go" <<'MOCK'
#!/usr/bin/env bash
set -eu
printf '%s|%s|%s|%s|%s\n' "${0##*/}" "$PWD" "$GOWORK" "$CGO_ENABLED" "$*" >> "$TEST_LOG"
count=$(wc -l < "$TEST_LOG" | tr -d ' ')
module="$GOMODCACHE/example.org/module@v1.0.$count"
mkdir -p "$module/nested"
printf 'module fixture\n' > "$module/nested/go.mod"
chmod -R a-w "$module"
if [ "$count" = "${FAIL_AT:-0}" ]; then exit 37; fi
MOCK
chmod +x "$TEST_DIR/bin/go"
cp "$TEST_DIR/bin/go" "$TEST_DIR/bin/govulncheck"
export PATH="$TEST_DIR/bin:$PATH" TEST_LOG="$TEST_DIR/log"
export OBOARD_VERIFY_CACHE_ROOT="$TEST_DIR/cache"
unset OBOARD_SB_TAGS
assert_cache_clean() {
  if [ -n "$(find "$OBOARD_VERIFY_CACHE_ROOT" -mindepth 1 -print -quit)" ]; then
    echo 'verification left cache files behind' >&2; exit 1
  fi
}
bash "$ROOT/scripts/verify-release.sh"
assert_cache_clean
expected="$TEST_DIR/expected"
{
  for module in "$ROOT" "$ROOT/kernel/oboard-sb"; do
    tags=''
    if [ "$module" != "$ROOT" ]; then tags='-tags with_utls,with_gvisor '; fi
    printf 'go|%s|off|0|test %s./...\n' "$module" "$tags"
    printf 'go|%s|off|0|vet %s./...\n' "$module" "$tags"
    printf 'go|%s|off|0|mod verify\n' "$module"
    printf 'govulncheck|%s|off|0|%s./...\n' "$module" "$tags"
  done
} > "$expected"
diff -u "$expected" "$TEST_LOG"
for fail in {1..8}; do
  : > "$TEST_LOG"
  if FAIL_AT=$fail bash "$ROOT/scripts/verify-release.sh"; then
    echo "verification accepted failure $fail" >&2; exit 1
  else
    status=$?
  fi
  test "$status" -eq 37
  assert_cache_clean
  test "$(wc -l < "$TEST_LOG" | tr -d ' ')" = "$fail"
done
for tags in with_utls with_gvisor not_with_utls,with_gvisor; do
  : > "$TEST_LOG"
  if OBOARD_SB_TAGS=$tags bash "$ROOT/scripts/verify-release.sh"; then
    echo "verification accepted invalid tags $tags" >&2; exit 1
  fi
  test ! -s "$TEST_LOG"
done
: > "$TEST_LOG"
OBOARD_SB_TAGS='with_utls,with_gvisor,with_quic' bash "$ROOT/scripts/verify-release.sh"
grep -q 'test -tags with_utls,with_gvisor,with_quic ./...' "$TEST_LOG"
assert_cache_clean
mkdir -p "$TEST_DIR/no-scanner"
ln -s "$TEST_DIR/bin/go" "$TEST_DIR/no-scanner/go"
ln -s "$(command -v dirname)" "$TEST_DIR/no-scanner/dirname"
: > "$TEST_LOG"
if PATH="$TEST_DIR/no-scanner" /bin/bash "$ROOT/scripts/verify-release.sh"; then
  echo 'verification accepted missing scanner' >&2; exit 1
fi
test ! -s "$TEST_LOG"
echo 'verify-release script tests passed'
