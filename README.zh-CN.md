# oboard-agent

**中文** | [English](README.md)

OBoard-Agent 是一个负责与 Oboard 面板主控通信、配置 Oboard-sb 内核、执行主控下发任务的管理程序

## 特性

- **一键接入**：通过一次性令牌注册，支持 WebSocket 通信、断线重连与任务重试
- **代理内核**：内置 `oboard-sb` 内核，支持 VLESS、Hysteria2、AnyTLS、Shadowsocks、SOCKS5、Mieru 与 WireGuard 端点，并支持基于独立 sshd 实现的 SSH 代理支持。
- **组网能力**：支持 WG/SSH 隧道、Realm / nft 端口转发、链式代理
- **资源自适应**：根据内存自动调整策略，优先保证稳定性并兼具性能，降低 OOM 风险
- **本地运维**：提供 `obag` 查看状态、启动、停止、重启、查看 Agent / 内核日志并检查与主控的连通性
- **探测与诊断**：支持入站、端口转发、出口 IP、MTU、DNS、时间、日志采集与证书等自动化任务
- **审计**：支持对使用情况进行统计，降低泄露风险
- **类探针功能**：支持对服务器运行状态、延迟进行测量与回报

## 许可证

Copyright 2026 OBoard contributors.

Oboard-sb 基于 [Sing-Box](https://github.com/SagerNet/sing-box) 进行修改，再次对 [Sing-Box](https://github.com/SagerNet/sing-box)  表示感谢！

`oboard-agent`以 [GNU GPL v3](LICENSE) 发布。
