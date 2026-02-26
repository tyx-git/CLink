# CLink 升级待办（Upgrade Backlog）

## 用户体验与接入流程 (UX & Onboarding)
- [ ] 设计 `client/` 首次启动向导，自动复制 `config/clink.sample.toml` 并逐步提示证书、端口与数据目录设置，减少手动编辑。
- [ ] 为 `clink-cli` 增加 `clink-cli quickstart <profile>` 一键体验命令，串联配置生成、`python scripts/run_tests.py` 预检查以及常见诊断说明。
- [ ] 实现配置文件热重载伴随回滚：监听 `config/` 目录变更，自动备份旧版本，并在 `clink-cli diag` 中展示差异供用户确认。

## 高效传输架构 (High-Performance Transport)
- [ ] 在 `src/core/transport` 中实现基于 `BufferPool` 的零拷贝 DMA 路径，让 VirtualInterface 与 TLS 层共享内存块并记录引用计数。
- [ ] 为 `ReliabilityEngine` 引入 RTT、抖动与丢包的在线估计，动态调整批量大小、拥塞窗口与补发策略，必要时混合 TCP/QUIC。
- [ ] 在 `TransportAdapter` 中添加可插拔 SIMD 压缩/解压策略，根据会话配置自动选择无损或低延迟编码，提高链路利用率。

## 进程级数据通道 (Process-Scoped Data Plane)
- [x] **[Stability]** 增强 DLL 注入模块的 IPC 错误处理，增加管道断开检测与优雅退出机制。
- [ ] 在 `client/` 侧评估 Windows Detours 与 Linux LD_PRELOAD 两种注入策略，从目标进程内捕获 socket/管道数据并注入隧道。
- [ ] 针对 Minecraft 场景提供 `profiles/minecraft.toml`，包含进程名、监听端口、推荐 MTU 以及 QoS 参数，方便快速联机。
- [ ] 扩展 `scripts/run_tests.py`，加入进程级链路回归：记录注入/回放延迟、带宽与重传率，并输出报告到 `logs/process_tests/`。

## 数据质量监控 (Data Quality Monitoring)
- [ ] 在 `docs/` 中撰写流量质量仪表板指引，集成 OpenTelemetry SDK，将虚拟网卡、压缩层与加密层指标统一上报。
- [ ] 扩展 `logs/` 结构，引入数据完整性与延迟分布采样，并在 `clink-cli status` 中展示实时的会话质量摘要。

## 核心模块演进 (Core Modules)
- [x] **[Critical]** 完成 Windows TAP 虚拟网卡驱动对接，实现 ARP 响应与 MAC 地址自动协商。
- [x] **[Performance]** `VirtualInterface` 写入路径全异步化改造，消除线程阻塞并确保 200+ 并发下的线程安全。
- [ ] 在 `modules/` 新增 `process_router`，通过插件接口将多路进程流聚合到 TUN/TAP 输出，同时暴露策略钩子。
- [ ] 根据 `docs/architecture` 的 IO 拓扑更新 SessionManager，使其支持多端口、多进程同时绑定，并对单点拥塞做自适应限速。
