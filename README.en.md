# oboard-agent

[中文](README.md) | **English**

OBoard node-side Agent for enrollment, configuration apply, runtime probes, and updates, with the slim proxy kernel `oboard-sb` built in.

## Features

- **Low-memory friendly**: selects a runtime profile from effective memory to reduce OOM risk on small containers and NAT hosts
- **Light control plane**: limits Agent threads and memory so resources stay available for the data-plane `oboard-sb`
- **Local operations**: manage start/stop, view logs, and check Controller connectivity with `obag`
- **Networking and forwarding**: tunnels plus Realm / nft port-forward backends with automatic selection for multi-node paths

## Repository layout

| Path | Description |
|------|-------------|
| `cmd/agent` | Agent entrypoint (includes local management commands) |
| `internal/agent` | Task execution, updates, diagnostics, log collection, and host-side apply logic |
| `kernel/oboard-sb` | Slim sing-box based kernel (separate Go module) |
| `deploy/systemd`, `deploy/openrc` | Service units for Agent and kernel |

## Build

```bash
go test ./...
go build -o ../dist/agent/oboard-agent ./cmd/agent

cd kernel/oboard-sb
go test ./...
go build -o ../../../dist/agent/oboard-sb ./cmd/oboard-sb
```

> For local development, write build outputs under the parent workspace `dist/` directory so this repository tree stays clean.

## Install and manage

### Enroll a node

Open the target server in the OBoard panel, copy the install command, and run it as **root** on the node:

```bash
curl -fsSL 'https://panel.example.com/install/agent.sh' | OBOARD_ENROLL_TOKEN='one-time-token' bash
```

The same script supports update and uninstall:

```bash
curl -fsSL 'https://panel.example.com/install/agent.sh' | bash -s -- update
curl -fsSL 'https://panel.example.com/install/agent.sh' | bash -s -- uninstall
```

### Hidden path (base path)

If the Controller enables `OBOARD_BASE_PATH`, both the install script URL and the Agent’s persisted `controller_url` must include that prefix, for example:

| Purpose | Example |
|---------|---------|
| Install script | `https://panel.example.com/hidden/install/agent.sh` |
| Controller URL | `https://panel.example.com/hidden` |

WebSocket connections, task callbacks, health checks, and signed release downloads all use the same path prefix.

### Local management

After installation, use `obag` in an SSH session on the node (the installer places it on `PATH`).

Open the interactive menu:

```bash
obag
```

Common subcommands:

```bash
obag status              # Agent and kernel status
obag start               # start Agent and kernel (root required)
obag stop                # stop Agent and kernel (root required)
obag restart             # restart Agent and kernel (root required)
obag logs agent          # Agent logs
obag logs core           # oboard-sb kernel logs
obag check               # check connectivity to Controller
obag help                # show usage
```

Status, logs, and connectivity checks usually do not require root. Start, stop, and restart need root (`sudo obag ...`).

## Resource and memory policy

Default `resource_profile=auto` selects a runtime profile from **effective memory**.  
Effective memory is the lower of physical RAM and the cgroup (v1 / v2) limit, so Docker, LXC, Incus, and similar capped environments are handled correctly.

| Profile | Condition (summary) | Policy |
|---------|---------------------|--------|
| Small | Effective memory &lt; 512 MiB, or unknown | Prefer stability and lower usage; reduce OOM risk |
| Large | Effective memory ≥ 512 MiB (including large cgroup limits) | Allow the kernel to use more cores and residual memory |

See `kernel/oboard-sb/README.md` for finer profile tiers and kernel behavior, and workspace `docs/KERNEL.md` for protocol scope and upstream sync notes.

## License

Copyright 2026 OBoard contributors.

`oboard-agent` (including `kernel/oboard-sb`) is released under the
[GNU GPL v3](LICENSE).  
You may use, modify, and redistribute this software under the terms of that license.
