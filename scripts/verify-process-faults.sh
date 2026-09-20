#!/usr/bin/env bash
set -euo pipefail
# Explicit opt-in; this is a real-kernel/component-process suite, not fleet E2E.
: "${OBOARD_PROCESS_KERNEL:?set an absolute path to a real locally built oboard-sb}"
: "${GOCACHE:?set a workspace-owned Go cache}"
: "${GOTMPDIR:?set a workspace-owned Go temporary directory}"
: "${TMPDIR:?set a short workspace-owned temporary directory for Unix sockets}"
[[ "$OBOARD_PROCESS_KERNEL" = /* && -x "$OBOARD_PROCESS_KERNEL" ]] || { echo 'real kernel executable required' >&2; exit 1; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
: "${OBOARD_PROCESS_KERNEL_NEXT:?set the second fixture binary}"
: "${OBOARD_PROCESS_MANIFEST:?build fixtures with build-process-fixtures.sh first}"
python3 "$root/scripts/process-fixture-provenance.py" verify
case "${1:-}" in
  '') pattern='^TestRealKernelProcessFaults$'; printf 'Scope: B/C/D/E real Agent helper and kernel processes; A/F/G NOT COVERED by this entry.\n' ;;
  --all)
    pattern='^TestReal(Kernel(ProcessFaults|BuildReplacement|AuthorizationFaults)|Agent(HTTPResultLoss|AuthorizationReconnect))$'
    printf 'Scope: B-G component processes, including signed WS delivery/reconnect and HTTP result loss; controlled Controller peer, not three-binary E2E.\n' ;;
  --delivery)
    pattern='^TestRealAgent(HTTPResultLoss|AuthorizationReconnect)$'
    printf 'Scope: real Agent HTTP result loss and signed WS authorization reconnect with a controlled Controller peer.\n' ;;
  --authorization)
    pattern='^TestRealKernelAuthorizationFaults$'
    printf 'Scope: G kernel Unix API revocation/stale grant/restart/expiry with real TCP; Controller reconnect NOT covered.\n' ;;
  --build)
    : "${OBOARD_PROCESS_KERNEL_NEXT:?set a second kernel binary with distinct build metadata}"
    [[ "$OBOARD_PROCESS_KERNEL_NEXT" = /* && -x "$OBOARD_PROCESS_KERNEL_NEXT" ]] || exit 1
    pattern='^TestRealKernelBuildReplacement$'
    printf 'Scope: F real kernel replacement and running build verification only.\n' ;;
  *) echo 'usage: verify-process-faults.sh [--all|--build|--authorization|--delivery]' >&2; exit 2 ;;
esac
GOWORK=off go test ./internal/agent -run "$pattern" -count=1 -timeout=120s -v
