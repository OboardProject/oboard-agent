# Linux memory regression measurement component

Status: **incomplete benchmark tooling**, not a supported-memory claim or a release gate.
`sample.py` is a read-only cgroup v2 sampler. It does not start binaries, create
cgroups, configure the host, generate traffic, contact nodes, or establish network
isolation. It deliberately returns exit 2 after collecting measurements, not a
benchmark pass. Validation errors or observed OOM return 1. No baseline is shipped.

## Required external fixture

Use only explicit synthetic Agent/kernel configurations and test binaries in an
externally isolated Linux fixture with no external network route. An operator must
provide a private delegated cgroup whose **single parent memory.max** is one of
128, 256, 512 or 1024 MiB. Put Agent, the real kernel and every active forwarding
subprocess directly in that same cgroup, not in child cgroups. This first version
rejects child membership so hidden per-component memory, swap or CPU limits cannot
invalidate the shared-budget measurement. Controller, load generator and sampler
must be outside the entire measured subtree. No sudo or global host setting changes are performed by this tool.
The flag below is an operator attestation, not proof of network isolation.

Example for one phase (all paths and PIDs are supplied by the fixture):

```sh
python3 scripts/memory-regression/sample.py \
  --cgroup "$TEST_CGROUP" --budget-mib 128 --swap-bytes 0 \
  --agent-pid "$AGENT_PID" --kernel-pid "$KERNEL_PID" \
  --controller-pid "$CONTROLLER_PID" --load-pid "$LOAD_PID" \
  --controller-repo "$CONTROLLER_REPO" --agent-repo "$AGENT_REPO" \
  --phase steady --duration 30 --interval 0.5 \
  --isolated-synthetic-fixture --output "$WORKSPACE/dist/test/memory-steady.json"
```

Repeat `--forwarder-pid` for every forwarder. Each role needs a distinct live PID.
The tool checks PID start identity, membership, memory and swap limits each sample;
it refuses ancestor memory or swap limits stricter than the requested budget or
explicit swap policy. `ancestor_limits` records ancestor memory, swap and CPU
limits (including `max`; absent root controls are null).
Use a fresh cgroup for each repeat. `memory.peak` is a lifetime measurement and is
not reset by this tool; the report explicitly leaves freshness unverified.
Outputs are exclusive-created with mode 0600; existing evidence is never replaced.
No process command line, environment or configuration is recorded. Keep outputs
outside repositories. The sampler starts no long-lived child process and owns no
fixture resources, so fixture lifecycle and cleanup remain the caller's duty.

## Measurement interpretation

`memory.current` is the group total. `memory.stat` categories overlap (for example
shmem is part of file); never add all categories or add them to memory.current.
`memory.events_delta` and `cpu_stat_delta` subtract this invocation's first sample,
not the prior run's accumulated totals. Sampling is independent of process
validation: if a PID disappears, the tool attempts a final cgroup sample and
retains available event deltas alongside the separate `process_failure` reason.
An OOM is retained as `oom_failure`, rather than hidden by the dead-PID failure.
A failed final read is explicitly marked unavailable; missing observations are
not proof of no OOM. CPU `usage_usec` divided by elapsed wall
microseconds is CPU-core utilization, not normalized percent of host CPUs.
`observed_peak_bytes` is sampled and can miss short spikes. A null kernel peak
means unsupported, not zero. Sampling costs, provenance hashing before sampling,
and repeated file reads are outside the constrained group but still consume host
resources. Record interference separately and freeze builds/source changes during
formal measurements. Full worktree fingerprints include ignored-file exclusions,
tracked contents/modes and untracked non-ignored files; commit alone is insufficient.

## Synthetic SOCKS5 load component

`load.py` runs real sockets through an explicitly supplied **IPv4 loopback** SOCKS5
listener. The listener must require username/password authentication and allow
synthetic loopback TCP and UDP destinations. The tool starts its own ephemeral
127.0.0.1 TCP/UDP echo targets; it accepts no destination argument and does not
perform DNS or dial external addresses. UDP uses SOCKS5 UDP ASSOCIATE, not TCP
encapsulation; the returned relay address must also be an explicit IPv4 loopback
address (wildcard/domain/IPv6 replies are rejected). This does not prove that the
proxy itself has no external network access: use the external isolated fixture.

Pass one bounded JSON line on stdin with `username` and `password`. Supply it
through a private file descriptor or a mode-0600 synthetic credential file, never
through argv, shell command text or logging. For example:

```sh
python3 scripts/memory-regression/load.py \
  --proxy-host 127.0.0.1 --proxy-port "$SYNTHETIC_SOCKS_PORT" \
  --protocol both --mode transfer --duration 30 --concurrency 4 \
  --burst-multiplier 2 --payload-bytes 1024 --max-operations 10000 \
  --output "$WORKSPACE/dist/test/load-transfer.json" < "$PRIVATE_CREDENTIAL_FILE"
```

Run separately with `--mode idle` and `--mode reconnect`. Each invocation runs
warmup, steady, burst and recovery in order. Duration is per phase; burst multiplies
worker count. Connections are retained within each phase for transfer/idle, and
recreated for every reconnect operation. Phase boundaries close connections; idle
inserts `--idle-seconds` between verified exchanges. Both-protocol runs require at
least two workers and assign even workers TCP, odd workers UDP. One outstanding
request per worker gives closed-loop load, not a fixed offered request rate.
The operation cap is per phase; `operation_cap_reached` means the phase can finish
early and is not evidence of the full requested observation duration. Choose caps
and durations accordingly. Maximums are 64 burst workers, 25,000 operations per
phase, 60,000 payload bytes and 300 seconds per phase. Network reads/writes have
bounded timeouts; echo sockets, sessions and owned threads are closed/joined.

Every completion verifies fresh random payload bytes; UDP additionally verifies
reserved/fragment fields and the returned target endpoint. A refused proxy cannot
fall back to direct echo. Each phase records raw operation samples, offered and
completed counts, errors, verified roundtrip payload bytes, throughput and nearest-
rank p50/p95/p99 latency. Latency includes authentication/connect setup when needed
and deliberate idle waiting in idle mode; it is not pure network RTT. Throughput
counts application bytes in both directions, excluding SOCKS/IP overhead; failed
partial transfers contribute no verified bytes. Percentiles describe successful
operations only, beside explicit error counts; empty results never pass.

The exclusive-created JSON report is mode 0600 and includes no credentials,
payload contents or underlying exception messages. Exit 1 indicates validation or
load correctness failure, including any operation failure or a missing protocol.
Exit 0 means **only this load component passed**, never a complete memory benchmark.
Reports always set `benchmark_complete=false` and list `missing_evidence`, including
real kernel identity/path proof: this tool cannot distinguish a real kernel from a
SOCKS fixture. It does not launch the kernel, configure cgroups, exercise Agent
control, apply configurations or implement QUIC. Run it outside the measured group
and align phase timestamps with sampler runs through external orchestration.

## Opt-in Linux process-group orchestration

`run.py` is an **incomplete evidence collector**, not a passing benchmark. It
creates one unique child of an already-private delegated cgroup v2 parent. The
parent must already expose the memory controller in `cgroup.subtree_control`;
the runner never enables controllers, uses sudo, creates namespaces or changes
global settings. Linux `cgroup.kill` is required for descendant cleanup. Do not
supply a parent shared with another workload. External network isolation is the
operator's responsibility, and the fixture's boolean declaration is not proof.

Supply an explicit JSON fixture, containing only synthetic inputs, for example:

```json
{
  "synthetic_only": true,
  "external_network_isolation": true,
  "declared_build_tags": ["with_utls", "with_gvisor"],
  "audit_enabled": false,
  "interference_absent": true,
  "proxy_port": 19080,
  "processes": {
    "controller": {"binary": "/fixture/bin/controller", "args": [], "cwd": "/fixture/controller", "configs": ["/fixture/controller/config"]},
    "agent": {"binary": "/fixture/bin/agent", "args": [], "cwd": "/fixture/agent", "configs": ["/fixture/agent/config"]},
    "kernel": {"binary": "/fixture/bin/kernel", "args": [], "cwd": "/fixture/kernel", "configs": ["/fixture/kernel/config"]}
  }
}
```

This is a **schema example, not a working OBoard configuration**. Supply actual
binary arguments and explicit synthetic configurations; the runner does not
invent enrollment, certificates, tokens, service definitions, or remote commands.
Every cwd must be an existing mode-0700 private fixture directory. Binaries must
run in the foreground, not daemonize or escape their process session; the runner
checks `/proc/PID/exe` against the supplied binary hash. Do not use a shell wrapper.
Optional forwarding processes use keys `forwarder-<name>`. Configure Agent to use
the fixture-owned kernel, not a host service manager. Do not supply production
paths or credentials in args/configs. The executable receives only a minimal
PATH/HOME/LANG environment, never the caller's credentials.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/memory-regression/run.py \
  --fixture /fixture/run.json --parent /sys/fs/cgroup/private-delegation \
  --controller-repo "$CONTROLLER_REPO" --agent-repo "$AGENT_REPO" \
  --credentials /fixture/socks-credentials.json \
  --budget-mib 128 --swap-bytes 0 --duration 10 --interval 0.5 \
  --output "$WORKSPACE/dist/test/memory-run-unique"
```

The output directory must not exist. Credentials must be a mode-0600 regular file
(symlinks and FIFOs are rejected). Before starting any process, the runner opens
it once with nonblocking/no-follow flags and validates at most 2048 bytes of JSON.
Each load receives that validated snapshot through a bounded pipe, never by
reopening the supplied path. It uses the stdin JSON shape of `load.py`; no password
argv is added. Process
stdout/stderr is discarded to avoid capturing secrets. The private `run.json`
contains no arguments/configuration contents; it records executable and config
hashes, actual PIDs, architecture/kernel, both repository dirty fingerprints,
ancestor CPU/memory/swap constraints, requested limits, samples and event deltas.
Declared tags/audit/interference settings remain **unverified declarations**.
The executable hash verifies the running file, not runtime build metadata,
configuration digest, or which process owns the SOCKS listener.

Agent, kernel and declared forwarders join the same fresh child **before exec**.
Controller, load and sampler remain outside it; PID/start-time membership and
limits are checked during load. No per-component duplicate memory budgets are
used. `idle`, `reconnect`, then `transfer` each run `load.py`'s four phases and both
TCP/UDP paths with its bounded default load parameters. Samples span each full
mode; use monotonic timestamps in the load reports to align phase boundaries,
not assumed duration (operation caps can shorten phases). Initial/final counters
cover startup and load; the new cgroup provides a fresh lifetime peak. Memory
classification overlap and sampler overhead described above still apply.

A bounded loopback listener check is readiness only, not Agent control evidence.
The runner neither invokes an arbitrary configuration command nor retries one.
Load errors, identity failures, OOM, timeout, unavailable final samples and cleanup
failures exit 1. Successful collection still exits **2** and lists missing evidence.
The summary on stdout is deliberately limited; raw machine-readable reports are
private. Still-owned, unreaped session leaders are group-killed and waited on;
only the owned cgroup is killed/removed. A leader already reaped by poll/wait is
never signalled by its old PID, which could now belong to another process. Its
outside-cgroup descendants cannot safely be identified: this is recorded in
`cleanup_limitations`, not claimed as successful descendant cleanup. Foreground
Controller sessions remain owned until cleanup; daemonizing/session-escaping
children are unsupported. Fixture directories are operator-owned and
not deleted. SIGINT/SIGTERM trigger cleanup; SIGKILL/host crash cannot: inspect the
unique `oboard-measure-*` child and fixture process sessions before manual cleanup,
never recursively clean a shared delegated parent.

Run each of 128/256/512/1024 MiB explicitly with a new output directory and repeat
cells without concurrent builds. No matrix measurements have been run on macOS,
no support promise or performance threshold is implied, and the runner cannot
currently certify authenticated Agent responsiveness or repeated apply under load.
The lightweight `test_run.py` covers refusal/validation, pre-exec membership wiring
and kill/wait behavior with mocks; it is not Linux cgroup execution evidence.

## Remaining acceptance work

An actual fixture must independently prove the SOCKS listener belongs to the real
kernel and combine load phases with resource sampling. QUIC remains unimplemented.
Record Agent control responses and repeated configuration application under load. It must pin binary hashes/build tags
(`with_utls,with_gvisor`), synthetic config settings including audit, process build
identity, load parameters and external isolation. It must account for all enabled
forwarders, repeat each matrix cell, quantify variation and only then set any
performance threshold. The sampler's nonempty data does **not** provide this proof.
Exploratory OOM is recorded as failure, not converted into a support commitment.
A process-group cap is not equivalent to a same-size VM.

The current production Agent and kernel detection reads fixed root cgroup paths
(`detectedCgroupMemoryLimit` in `internal/agent/tuning.go` and
`kernel/oboard-sb/internal/minibox/resources.go`); it does not walk the current
process's cgroup ancestors. A nested group limit may therefore not influence
production Go budgeting even though the kernel enforces the cap. This is a known
measurement caveat, not fixed by changing production tuning in this tool change.
Existing pure `effectiveMemory` tests do not prove parent-limit detection.

## Lightweight tests

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/memory-regression -p 'test_*.py'
```

These tests exercise parsing, non-Linux rejection, full validation with synthetic
cgroup files and mocked membership, ancestor swap constraints, child-membership
rejection, and CLI exit/report behavior when a process disappears after an OOM
counter increase. They also check incomplete exit 2 and exclusive 0600 reports.
`test_load.py` also starts a synthetic authenticated SOCKS5 TCP/UDP relay and real
local echo sockets, covering all three modes, proxy refusal (no direct fallback),
payload corruption, UDP endpoint mismatch, private reports and credential redaction.
Relay byte counts prove the test load traverses that fixture. These are not real
kernel or Linux cgroup integration tests. Go boundary tests call production
budget/profile functions directly; run the focused package tests separately using
the workspace's isolated Go caches. macOS cannot validate the real Linux fixture.
