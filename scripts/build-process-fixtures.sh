#!/usr/bin/env bash
set -euo pipefail
# OBOARD_PROCESS_WORKSPACE may be RUNNER_TEMP in a standalone Agent checkout.
: "${OBOARD_PROCESS_WORKSPACE:?set an external workspace or RUNNER_TEMP}"
: "${OBOARD_PROCESS_KERNEL:?set an explicit workspace/dist output path}"
: "${OBOARD_PROCESS_KERNEL_NEXT:?set a distinct workspace/dist output path}"
: "${OBOARD_PROCESS_MANIFEST:?set an explicit workspace/dist manifest path}"
: "${GOCACHE:?set an external Go cache}"
: "${GOMODCACHE:?set an external Go module cache}"
: "${GOTMPDIR:?set an external Go temporary directory}"
root=$(cd "$(dirname "$0")/.." && pwd)
python3 "$root/scripts/process-fixture-provenance.py" build
