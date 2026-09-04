#!/usr/bin/env bash
set -euo pipefail

# Fetches the pinned upstream realm release binary and installs it as the
# bundled oboard-realm asset for one platform. The Agent no longer looks for a
# realm binary on the host PATH, so this pinned artifact is the only source of
# the port-forwarding backend.

AGENT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MANIFEST="$AGENT_DIR/scripts/realm-manifest.json"
VENDORED_LICENSE="$AGENT_DIR/third_party/realm/LICENSE"
OUT_DIR=${1:?output directory is required}
OS_VALUE=${2:?target os is required}
ARCH_VALUE=${3:?target arch is required}

if [ "$OS_VALUE" != linux ]; then
  echo "realm is bundled for linux only, got $OS_VALUE" >&2
  exit 2
fi

read -r REALM_VERSION REALM_ASSET REALM_SHA256 REALM_LICENSE_SHA256 < <(python3 - "$MANIFEST" "$ARCH_VALUE" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
arch = sys.argv[2]
target = manifest.get("targets", {}).get(arch)
if not target:
    sys.exit(f"realm-manifest.json does not pin an asset for {arch}")
print(manifest["version"], target["asset"], target["sha256"], manifest["license_sha256"])
PY
)

sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

actual_license=$(sha256_of "$VENDORED_LICENSE")
if [ "$actual_license" != "$REALM_LICENSE_SHA256" ]; then
  echo "Vendored realm LICENSE does not match realm-manifest.json license_sha256" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

url="https://github.com/zhboner/realm/releases/download/$REALM_VERSION/$REALM_ASSET"
curl -fsSL --retry 3 --connect-timeout 20 "$url" -o "$tmp/$REALM_ASSET"
actual=$(sha256_of "$tmp/$REALM_ASSET")
if [ "$actual" != "$REALM_SHA256" ]; then
  echo "realm checksum mismatch for $REALM_ASSET: got $actual, expected $REALM_SHA256" >&2
  exit 1
fi

# Upstream ships a single stripped static binary named realm at the archive
# root. Reject anything else rather than installing an unexpected payload.
contents=$(tar -tzf "$tmp/$REALM_ASSET")
if [ "$contents" != "realm" ]; then
  echo "Unexpected layout in $REALM_ASSET:" >&2
  printf '%s\n' "$contents" >&2
  exit 1
fi

mkdir -p "$tmp/extract"
tar -xzf "$tmp/$REALM_ASSET" -C "$tmp/extract"
if [ ! -f "$tmp/extract/realm" ]; then
  echo "$REALM_ASSET does not contain a realm binary" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
target="$OUT_DIR/oboard-realm-$OS_VALUE-$ARCH_VALUE"
install -m 0755 "$tmp/extract/realm" "$target"
echo "==> Bundled realm $REALM_VERSION for $OS_VALUE/$ARCH_VALUE at $target"
