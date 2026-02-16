# CLINK 开发进度与计划 (2026-02-14)

## 已完成增强 (CLI & Observability)
- **命令行界面 (CLI) 颜色与格式化**:
  - 实现了跨平台终端颜色支持 (Win32 VT Processing & ANSI)。
  - 优化了 `status` 和 `monitor` 命令的输出布局，增加了表格化显示。
- **实时监控 (Monitor)**:
  - 实现了交互式监控原型，支持 1s 频率自动刷新。
  - 增加了详细的会话列表，包含 ID、用户、上传/下载流量、RTT 和远程地址。
  - 增加了总流量统计 (TOTAL) 汇总显示。
- **流量统计 (Metrics)**:
  - 在 `ReliabilityEngine` 中实现了字节级流量统计 (`bytes_sent`, `bytes_received`)。
  - 实现了从传输层到应用层 IPC 状态的自动同步。
- **日志系统优化**:
  - 修复了日志文件被截断的问题，改为追加模式。
  - 引入了滚动日志 (Rotating Log)，限制日志文件大小 (10MB) 和数量 (5个)。
  - 调整了初始化顺序，确保捕获完整的启动日志。

## 待办事项 (Next Steps)

### 1. 传输层与协议优化 (Data Plane)
- [ ] **真实的 RTT 测量**: 目前 RTT 显示为 0ms，需要实现在 `ReliabilityEngine` 中通过心跳包或数据包确认来计算真实的往返时间。
- [ ] **重传机制增强**: 完善 `ReliabilityEngine` 的丢包检测与快速重传逻辑。
- [ ] **拥塞控制**: 引入简单的滑动窗口或 BBR 算法，优化高延迟环境下的吞吐量。

### 2. 安全与策略 (Security & Policy)
- [ ] **OpenTelemetry 完整集成**: 目前仅有抽象层，需要接入实际的 OTLP Exporter (如 Jaeger 或 Prometheus) 来实现分布式追踪。
- [ ] **动态策略生效**: 确保配置文件修改后，策略引擎不仅重新加载，还能实时应用到已建立的会话中。
- [ ] **用户认证增强**: 实现基于证书或 Token 的完整认证流程，替换目前的 N/A 用户 ID。

### 3. CLI 交互性提升 (Control Plane)
- [ ] **日志实时查看命令**: 实现 `clink-cli logs --tail`，通过 IPC 订阅或文件监听实现类似 `tail -f` 的效果。
- [ ] **会话管理操作**: 增加 `clink-cli disconnect <session_id>` 命令，支持踢出特定用户。
- [ ] **诊断报告生成**: 实现 `clink-cli diag`，一键收集系统状态、网络拓扑和最近错误日志。

## 架构变更记录
- **IPC 消息结构**: `status` 命令的 JSON 响应增加了 `user_id` 和 `remote_endpoint` 字段。
- **日志配置**: `clink.init.toml` 中的日志 Sink 类型从 `file` 变更为 `rotating`。
