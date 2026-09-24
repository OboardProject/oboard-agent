#!/usr/bin/env bash
set -euo pipefail

AGENT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
KERNEL_DIR="$AGENT_DIR/kernel/oboard-sb"
VERSION_VALUE=${VERSION:-$(tr -d '[:space:]' < "$AGENT_DIR/VERSION")}
COMMIT_VALUE=${COMMIT:-$(git -C "$AGENT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}
DATE_VALUE=${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
BUILD_VALUE=${BUILD:-${BUILD_NUMBER:-$(date -u +%Y%m%d%H%M%S)}}
OUT_DIR=${OUT_DIR:-$AGENT_DIR/dist/release}
PLATFORMS=${OBOARD_PLATFORMS:-"linux/amd64 linux/arm64 windows/amd64"}
REPO=${OBOARD_AGENT_REPO:-OboardProject/oboard-agent}
SIGNING_KEY=${OBOARD_RELEASE_SIGNING_KEY:-}
# STAGE splits the release so CI can compile platforms on parallel runners
# without handing them the signing key:
#   build    compile PLATFORMS into OUT_DIR (binaries only, no manifest)
#   package  sign a manifest over the PLATFORMS binaries already in OUT_DIR
#   all      both, in one process (default; local builds)
STAGE=${OBOARD_RELEASE_STAGE:-all}
case "$STAGE" in
  all|build|package) ;;
  *) echo "OBOARD_RELEASE_STAGE must be all, build, or package" >&2; exit 2 ;;
esac
SING_BOX_MODULE_VERSION=$(go -C "$KERNEL_DIR" list -m -f '{{.Version}}' github.com/sagernet/sing-box)
if [ -n "${SING_BOX_VERSION:-}" ] && [ "${SING_BOX_VERSION#v}" != "${SING_BOX_MODULE_VERSION#v}" ]; then
  echo "SING_BOX_VERSION does not match the actual module dependency" >&2
  exit 1
fi
SING_BOX_VERSION_VALUE=${SING_BOX_MODULE_VERSION#v}

case "$SING_BOX_VERSION_VALUE" in
  ""|"(devel)"|unknown)
    echo "Unable to resolve a release sing-box module version: $SING_BOX_MODULE_VERSION" >&2
    exit 1
    ;;
esac

# A build stage never sees the signing key, so it takes the public key the
# binaries embed from OBOARD_RELEASE_PUBLIC_KEY. Whenever the signing key is
# present it is authoritative, and a supplied public key must match it: the
# manifest would otherwise be signed by a key the shipped Agent does not trust.
RELEASE_PUBLIC_KEY=${OBOARD_RELEASE_PUBLIC_KEY:-}
if [ -n "$SIGNING_KEY" ]; then
  derived_public_key=$(go -C "$AGENT_DIR" run ./scripts/print_release_public_key.go)
  if [ -n "$RELEASE_PUBLIC_KEY" ] && [ "$RELEASE_PUBLIC_KEY" != "$derived_public_key" ]; then
    echo "OBOARD_RELEASE_PUBLIC_KEY does not match OBOARD_RELEASE_SIGNING_KEY" >&2
    exit 1
  fi
  RELEASE_PUBLIC_KEY=$derived_public_key
fi
if [[ "$VERSION_VALUE" != *dev* && "$BUILD_VALUE" != dev ]]; then
  if [ "$STAGE" != build ] && [ -z "$SIGNING_KEY" ]; then
    echo "OBOARD_RELEASE_SIGNING_KEY is required for production release builds" >&2
    exit 1
  fi
  if [ -z "$RELEASE_PUBLIC_KEY" ]; then
    echo "OBOARD_RELEASE_PUBLIC_KEY is required to build production release binaries" >&2
    exit 1
  fi
fi

AGENT_LDFLAGS="-s -w -X github.com/OboardProject/oboard-agent/internal/version.Version=$VERSION_VALUE -X github.com/OboardProject/oboard-agent/internal/version.Build=$BUILD_VALUE -X github.com/OboardProject/oboard-agent/internal/version.Commit=$COMMIT_VALUE -X github.com/OboardProject/oboard-agent/internal/version.Date=$DATE_VALUE -X github.com/OboardProject/oboard-agent/internal/version.ReleasePublicKey=$RELEASE_PUBLIC_KEY"
KERNEL_LDFLAGS="-s -w -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Version=$VERSION_VALUE -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Build=$BUILD_VALUE -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Commit=$COMMIT_VALUE -X github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/version.Date=$DATE_VALUE -X github.com/sagernet/sing-box/constant.Version=$SING_BOX_VERSION_VALUE"
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

if [ "$STAGE" != package ]; then
  rm -rf "$OUT_DIR"
fi
mkdir -p "$OUT_DIR/bin"
files_json="[]"

add_file_manifest() {
  local name=$1 component=$2 os=$3 arch=$4 path=$5
  local sha size
  read -r sha size < <(python3 - "$path" <<'PY'
import hashlib, pathlib, sys
p=pathlib.Path(sys.argv[1]); b=p.read_bytes(); print(hashlib.sha256(b).hexdigest(), len(b))
PY
)
  files_json=$(python3 - "$files_json" "$name" "$component" "$os" "$arch" "$sha" "$size" <<'PY'
import json, sys
items=json.loads(sys.argv[1])
items.append({"name":sys.argv[2],"component":sys.argv[3],"os":sys.argv[4],"arch":sys.argv[5],"sha256":sys.argv[6],"size":int(sys.argv[7])})
print(json.dumps(items,separators=(',',':')))
PY
)
}

build_platform() {
  local os=$1 arch=$2
  echo "==> Building oboard-agent $os/$arch"
  mkdir -p "$OUT_DIR/bin/$os-$arch"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go -C "$AGENT_DIR" build -trimpath -ldflags "$AGENT_LDFLAGS" -o "$OUT_DIR/bin/$os-$arch/oboard-agent" ./cmd/agent
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go -C "$KERNEL_DIR" build -trimpath -tags "$KERNEL_TAGS" -ldflags "$KERNEL_LDFLAGS" -o "$OUT_DIR/bin/$os-$arch/oboard-sb" ./cmd/oboard-sb
  echo "==> Bundling oboard-realm $os/$arch"
  "$AGENT_DIR/scripts/fetch-realm.sh" "$OUT_DIR" "$os" "$arch"
  cp "$OUT_DIR/oboard-realm-$os-$arch" "$OUT_DIR/bin/$os-$arch/oboard-realm"
  cp "$OUT_DIR/bin/$os-$arch/oboard-agent" "$OUT_DIR/oboard-agent-$os-$arch"
  cp "$OUT_DIR/bin/$os-$arch/oboard-sb" "$OUT_DIR/oboard-sb-$os-$arch"
}

if [ "$STAGE" != package ]; then
  for platform in $PLATFORMS; do
    build_platform "${platform%/*}" "${platform#*/}"
  done
fi
if [ "$STAGE" = build ]; then
  echo "==> Agent release binaries written to $OUT_DIR (unsigned build stage)"
  exit 0
fi

for platform in $PLATFORMS; do
  os=${platform%/*}
  arch=${platform#*/}
  for component in agent sb realm; do
    name="oboard-$component-$os-$arch"
    if [ ! -f "$OUT_DIR/$name" ]; then
      echo "Release binary $name is missing from $OUT_DIR" >&2
      exit 1
    fi
    add_file_manifest "$name" "$component" "$os" "$arch" "$OUT_DIR/$name"
  done
done

python3 - "$OUT_DIR/release-manifest.json" "$VERSION_VALUE" "$BUILD_VALUE" "$COMMIT_VALUE" "$DATE_VALUE" "$REPO" "$files_json" <<'PY'
import json, sys
path, version, build, commit, date, repo, files = sys.argv[1:]
manifest={"version":version,"build":build,"commit":commit,"date":date,"repo":repo,"files":json.loads(files)}
open(path,'w').write(json.dumps(manifest,separators=(',',':'),sort_keys=False))
PY

if [ -n "$SIGNING_KEY" ]; then
  go -C "$AGENT_DIR" run ./scripts/sign_manifest.go "$OUT_DIR/release-manifest.json" > "$OUT_DIR/release-manifest.json.sig"
else
  : > "$OUT_DIR/release-manifest.json.sig"
fi
(
  cd "$OUT_DIR"
  find . -maxdepth 1 -type f ! -name 'sha256sums.txt' -print0 | sort -z | xargs -0 shasum -a 256 | sed 's#  \./#  #'
) > "$OUT_DIR/sha256sums.txt"
echo "==> Agent release artifacts written to $OUT_DIR"
