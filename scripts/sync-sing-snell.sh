#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
workspace=$(dirname -- "$repo")
version=v0.0.0-20260829071736-20f2eaec77c3
export GOCACHE="${GOCACHE:-$workspace/.cache/snell-sync/go}"
export GOMODCACHE="${GOMODCACHE:-$workspace/.cache/snell-sync/mod}"
export GOTMPDIR="${GOTMPDIR:-$workspace/.cache/snell-sync/tmp}"
mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOTMPDIR"
stage=$(mktemp -d "$GOTMPDIR/snell-sync.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
GOWORK=off go mod download -json "github.com/sagernet/sing-snell@$version" > "$stage/module.json"
python3 - "$stage" <<'PYTHON'
import json, pathlib, shutil, sys
stage = pathlib.Path(sys.argv[1])
source = pathlib.Path(json.loads((stage / 'module.json').read_text())['Dir'])
target = stage / 'source'
target.mkdir()
for path in source.rglob('*'):
    if path.is_file() and (path.suffix == '.go' or path.name in ('go.mod', 'go.sum', 'LICENSE')):
        dest = target / path.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
PYTHON
patch --batch -d "$stage/source" -p1 < "$repo/scripts/patches/sing-snell.patch"
target="$repo/kernel/oboard-sb/third_party/sing-snell"
if [[ "${1:-}" == --check ]]; then
    diff -ru --exclude=UPSTREAM "$stage/source" "$target"
elif [[ $# == 0 ]]; then
    cp "$target/UPSTREAM" "$stage/source/UPSTREAM"
    rm -rf -- "$target"
    mv -- "$stage/source" "$target"
else
    echo 'usage: sync-sing-snell.sh [--check]' >&2
    exit 2
fi
