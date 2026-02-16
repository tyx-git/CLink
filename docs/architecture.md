# CVPN 架构设计

## 背景与目标
CVPN 面向内网床头等受限场景，提供稳定、低开销的安全链路。系统需要满足以下目标：
- 以 C++20 为主的跨平台实现，兼容 Windows 服务与 Linux 守护进程。
- 长时间运行稳定，支持热更新配置和模块化扩展（传输、认证、监控）。
- 提供 CLI/自动化接口，便于床旁护理、运维平台或脚本快速接入。

## 环境与约束
- **开发设备**：Windows 11（32 GB RAM / 1 TB SSD），可使用 `D:\Software\Language\mingw64\bin` 内的 g++ 与 `D:\Software\Git` 的 Git 工具。
- **远端资源**：Ubuntu 服务器（公网 https://115.190.41.219），需开放 TCP 9443、UDP 443 等端口以供服务端测试。
- **工具链**：clang-format、clang-tidy 等已安装，当前阶段仅需保持代码风格一致，后续可统一执行。
- **密钥策略**：采用非对称加密，密文存放于项目目录 `ace/`，证书体系暂缓实现，因此需为未来 PKI 预留扩展点。

## 总体架构概览
CVPN 由三大组件构成：
1. **cvpn-service**：常驻服务/守护进程，负责控制面和数据面所有逻辑。
2. **cvpn-cli**：面向操作员的命令行工具，用于连接、断开、查看状态、诊断。
3. **cvpn::core**：共享的运行时和基础库，提供生命周期、配置、事件循环、依赖注册能力。

### 逻辑分层
- **Core Runtime 层**：抽象生命周期管理、任务调度、依赖注入、日志与度量入口。
- **Control Plane 层**：包括 CLI、Admin RPC、配置管理、策略评估与会话编排接口。
- **Data Plane 层**：隧道管理、虚拟网卡抽象、传输适配器（TCP/TLS、QUIC 等）、包格式与 QoS/心跳机制。
- **Security Plane 层**：认证提供者、加密封装、ACL、秘钥管理（读取 ace/ 中密文，调用非对称解密）。
- **Observability 层**：结构化日志、指标导出、追踪、诊断快照，供 CLI 与外部监控消费。

## 模块设计
### 1. Core Runtime & Module Registry
- 暴露 `Application` 生命周期接口，由 service/CLI 驱动。
- 内建 IO 执行器：Windows 采用 IOCP + Boost.Asio，Linux 采用 epoll + Asio。
- 模块注册器使用能力标签（Transport/Auth/Observability）注入，实现热插拔。
- 当前内置示例模块包含：
  - `HeartbeatModule`：读取 `transport.heartbeat_ms` 并在事件循环外输出心跳监督日志。
  - `MetricsModule`：绑定 `observability.metrics_endpoint` 并模拟指标导出状态。

### 2. 配置与策略
- TOML Schema 定义在 `config/`，启动时加载 `config/cvpn.toml`，支持环境变量覆盖。
- File watcher 监控配置文件并触发增量更新，控制面校验后在核心状态机中生效。
- 策略层将全局默认、分组策略、设备策略合并，输出到 Session Manager。

### 3. 传输与会话管理
- **Session Manager**：维护隧道、流量统计、心跳、带宽控制。
- **Transport Adapter**：通用接口 + 实现（TCP-over-TLS、QUIC/msquic），未来可扩展私有协议。
- **Packet Engine**：封装序列号、ACK、重传/退避策略，并向 QoS 模块暴露事件。

### 4. 安全与秘钥
- **Credential Provider**：支持预共享密钥、LDAP Token、硬件证书等插件。
- **密钥托管**：从 `ace/` 读取密文，使用本地私钥解密后注入运行时；统一对外暴露 `KeyVault` 接口。
- **ACL/Policy Enforcement**：解析策略，将用户/设备映射到允许访问的子网与端口。

### 5. 可观测性与诊断
- **Logging**：基于 spdlog，提供滚动文件、控制台、远程 sink；支持运行时调节级别。
- **Metrics**：以 Prometheus textfile/gRPC exporter 双模式输出，指标包括会话数、RTT、丢包、CPU/内存占用。
- **Tracing**：OpenTelemetry SDK 集成，围绕连接、认证、数据通路打 span。
- **Diagnostics CLI**：`cvpn diag` 调用 Admin RPC，获取会话快照、传输状态、最近错误堆栈。

### 6. CLI 与 Admin RPC
- CLI 命令：`connect`、`disconnect`、`status`、`diag`、`policy reload`。
- CLI 与 service 通过本地 IPC（Windows Named Pipe / Linux Unix Domain Socket）通信，所有请求进入 Control Plane。
- Admin RPC 同时对远程 Ubuntu 节点开放受限接口，支持自动化平台操作。

### 7. 第三方依赖管理
- `third_party/` 用于手动 vendor 关键库；常规情况通过 CPM/FetchContent 拉取 fmt/spdlog/Boost.Asio/OpenSSL/msquic。
- 工具链映射：Windows 默认 g++ (MinGW) 与 MSVC 并存，CMake Preset 选择合适编译器；Linux 服务器使用系统 g++/clang。

## 关键流程
1. **启动**：`cvpn-service` 读取配置 → 初始化日志/度量 → 解析密钥与策略 → 注册传输/认证模块 → 进入事件循环。
2. **建立连接**：CLI 发起 `connect` → Admin RPC 校验身份 → Session Manager 分配虚拟通道 → 选择 Transport Adapter 建隧道 → 完成 ACL/路由下发。
3. **诊断**：CLI 执行 `diag` → 收集运行时指标/最近日志 → 生成 JSON/YAML 输出，并可写入 `logs/diag-<ts>.json`。
4. **热更新配置**：文件 watcher 捕获 `config/cvpn.toml` 变动 → 控制面校验 schema → 在不中断会话情况下向相关模块推送 delta。

## 部署与运行建议
- Windows 侧以服务形式常驻，可结合任务计划程序监控；需要具备管理员权限创建虚拟网卡。
- Ubuntu 服务器跑守护进程（systemd），配置 4 vCPU/8 GB RAM/≥1 Mbps 带宽。
- 日志与指标可转发到现有 Elastic/Prometheus 集群，方便统一观察。
- 构建流水线：本地使用 CMake Preset（Ninja + clang-tidy）验证，CI 在 Windows + Ubuntu 双环境运行单元/集成测试。

## 后续路线
- 接入真正的配置解析器（toml++）与策略引擎。
- 引入 OpenSSL/BoringSSL、msquic，并实现最小可用的 TCP/TLS 隧道。
- 扩展 CLI 与 Admin RPC 的权限模型，为将来的证书体系与集中密钥托管打基础。
