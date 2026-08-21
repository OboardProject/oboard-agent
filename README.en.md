# oboard-agent

[中文](README.md) | **English**

OBoard is the node-side Agent for connecting to the Controller, applying configuration, executing tasks, and maintaining the proxy kernel. It also provides local node operations. The proxy kernel `oboard-sb` is maintained in this repository as a separate Go module.

## Features

- **One-command Controller enrollment**: register with a one-time token, authenticate with an Agent identity and bearer token, and use the WebSocket task channel with reconnection and task retries
- **Signed deployment**: receive and verify signed Controller tasks, atomically apply configuration, update Agent/kernel assets, and restore or repair drifted desired state on startup
- **Slim proxy kernel**: built-in `oboard-sb` with VLESS/Reality, Hysteria2, AnyTLS, Shadowsocks, SOCKS5, Mieru, and WireGuard endpoints
- **Networking**: proxy paths, tunnels, Realm/nft port forwarding, transparent forwarding, restricted SSH services, and UDP over TCP
- **Adaptive resources**: select a runtime profile from physical memory and cgroup effective memory to keep resources available for the data plane and reduce OOM risk on small nodes
- **Local operations**: use `obag` for status, start, stop, restart, Agent/kernel logs, and Controller connectivity checks
- **Probes and diagnostics**: automated tasks for inbounds, port forwards, egress IP, MTU, DNS, time, log collection, and certificate issuance with HTTP-01
- **Audit and presence**: controlled connection audit and presence reporting that can be enabled or disabled by Controller policy and cleared promptly when disabled
- **Security boundaries**: signed release verification, restricted task permissions, minimal permissions for sensitive files, isolated SSH host identity, and protected forwarding keys

## License

Copyright 2026 OBoard contributors.

`oboard-agent` (including `kernel/oboard-sb`) is released under the [GNU GPL v3](LICENSE). You may use, modify, and redistribute this software under the terms of that license.
