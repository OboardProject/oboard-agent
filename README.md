# oboard-agent

**中文** | [English](README.en.md)

OBoard 节点侧 Agent，负责接入 Controller、落地配置、执行任务、维护代理内核，并提供节点本地运维。代理内核 `oboard-sb` 与 Agent 同仓维护，作为独立模块构建。

## 特性

- **一键接入主控**：通过一次性令牌注册，使用 Agent 身份和 Bearer 认证连接 Controller，支持 WebSocket 任务通道、断线重连与任务重试
- **已签名部署**：接收并校验 Controller 签名任务，原子应用配置、更新 Agent / 内核，启动后自动恢复并修复漂移的期望状态
- **轻量代理内核**：内置 `oboard-sb`，支持 VLESS/Reality、Hysteria2、AnyTLS、Shadowsocks、SOCKS5、Mieru 与 WireGuard 端点
- **组网能力**：代理路径、隧道、Realm / nft 端口转发、透明转发、受限 SSH 服务与 UDP over TCP
- **资源自适应**：根据物理内存与 cgroup 有效内存选择运行档位，优先保证数据面资源，降低小规格节点 OOM 风险
- **本地运维**：提供 `obag` 查看状态、启动、停止、重启、查看 Agent / 内核日志并检查与主控的连通性
- **探测与诊断**：支持入站、端口转发、出口 IP、MTU、DNS、时间、日志采集与证书 HTTP-01 等自动化任务
- **审计与在线状态**：支持受控连接审计和 presence 状态上报，按主控策略启停并及时释放本地状态
- **安全边界**：签名发布校验、受限任务权限、敏感文件最小权限、SSH 主机身份隔离与代理转发密钥保护

## 许可证

Copyright 2026 OBoard contributors.

`oboard-agent`（含 `kernel/oboard-sb`）以 [GNU GPL v3](LICENSE) 发布。可在该许可证允许的范围内使用、修改与再分发本软件。
