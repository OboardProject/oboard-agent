# oboard-agent

**中文** | [English](README.en.md)

OBoard 节点侧 Agent，负责节点注册、配置落地、运行探测与版本更新，并内置精简代理内核 `oboard-sb`。

## 特点

- **小内存友好**：按有效内存自动选择运行档位，降低小规格容器与 NAT 主机上的 OOM 风险
- **控制面轻量**：限制 Agent 的线程与内存占用，将资源优先留给数据面 `oboard-sb`
- **本机可运维**：通过 `obag` 管理服务启停、查看日志，并检测与主控的连通性
- **组网与转发**：支持隧道及 Realm / nft 等端口转发智能选择，便于多节点链路部署

## 仓库结构

| 路径 | 说明 |
|------|------|
| `cmd/agent` | Agent 程序入口（含本机管理命令） |
| `internal/agent` | 任务执行、更新、诊断、日志采集与主机落地逻辑 |
| `kernel/oboard-sb` | 基于 sing-box 的精简内核（独立 Go 模块） |
| `deploy/systemd`、`deploy/openrc` | Agent 与内核的服务单元文件 |

## 构建

```bash
go test ./...
go build -o ../dist/agent/oboard-agent ./cmd/agent

cd kernel/oboard-sb
go test ./...
go build -o ../../../dist/agent/oboard-sb ./cmd/oboard-sb
```

> 本地开发时，建议将编译产物输出至工作区上级目录的 `dist/`，以避免污染本仓库目录。

## 安装与管理

### 注册节点

在 OBoard 面板中打开目标服务器，复制安装命令，于节点 **root** 执行：

```bash
curl -fsSL 'https://panel.example.com/install/agent.sh' | OBOARD_ENROLL_TOKEN='一次性令牌' bash
```

同一脚本亦支持更新与卸载：

```bash
curl -fsSL 'https://panel.example.com/install/agent.sh' | bash -s -- update
curl -fsSL 'https://panel.example.com/install/agent.sh' | bash -s -- uninstall
```

### 隐藏路径

若主控启用了 `OBOARD_BASE_PATH`，安装脚本 URL 与 Agent 持久化的 `controller_url` 均须包含该前缀，例如：

| 用途 | 示例 |
|------|------|
| 安装脚本 | `https://panel.example.com/hidden/install/agent.sh` |
| Controller 地址 | `https://panel.example.com/hidden` |

WebSocket 连接、任务回调、健康检查以及签名发布包下载均使用同一路径前缀。

### 本机管理

安装完成后，可在节点 SSH 会话中直接使用 `obag`（安装脚本会将其加入 `PATH`）。

打开交互式管理菜单：

```bash
obag
```

常用子命令：

```bash
obag status              # 查看 Agent 与内核运行状态
obag start               # 启动 Agent 与内核（需 root）
obag stop                # 停止 Agent 与内核（需 root）
obag restart             # 重启 Agent 与内核（需 root）
obag logs agent          # 查看 Agent 日志
obag logs core           # 查看 oboard-sb 内核日志
obag check               # 检查与主控的连通性
obag help                # 显示用法说明
```

查看状态、日志与连通性一般无需 root；启动、停止与重启操作需要 root 权限（可使用 `sudo obag ...`）。

## 资源与内存策略

默认 `resource_profile=auto`，按**有效内存**自动选择运行档位。  
有效内存取物理内存与 cgroup（v1 / v2）限制中的较小值，适用于 Docker、LXC、Incus 等设置了内存限额的环境。

| 档位 | 条件（概要） | 策略取向 |
|------|----------------|----------|
| Small | 有效内存 &lt; 512 MiB，或无法探测 | 优先稳定与省资源，降低 OOM 风险 |
| Large | 有效内存 ≥ 512 MiB（含大限额容器） | 允许内核更充分利用多核与剩余内存 |

更细的档位划分与内核行为说明见 `kernel/oboard-sb/README.md`；协议范围与上游同步说明见工作区 `docs/KERNEL.md`。

## 许可证

Copyright 2026 OBoard contributors.

`oboard-agent`（含 `kernel/oboard-sb`）以 [GNU GPL v3](LICENSE) 发布。  
可在该许可证允许的范围内使用、修改与再分发本软件。
