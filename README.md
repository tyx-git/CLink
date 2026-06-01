# CLink

CLink 是一个 **跨平台 daemon + CLI** 的会话隧道项目（Windows / Linux）。

- `clink-server`：核心守护进程（数据面 + 控制面）
- `clink-cli`：本地控制工具（通过 IPC 控制本机 daemon）

> 版本：`1.3.4`  
> 作者：`TTxyz`

---

## 1. 项目是什么

CLink 的设计不是“CLI 直连远端”，而是：

1. `clink-cli` 向本机 `clink-server` 发 IPC 命令（connect/status/disconnect 等）
2. 本机 `clink-server` 再与远端 `clink-server` 建立 TCP/TLS 会话
3. 两端 daemon 负责会话生命周期、转发、重试、日志与观测

适合场景：跨端联机、隧道接入、代理转发、进程注入链路（Windows）。

---

## 2. 目录与二进制

构建后输出在：`Out/`

- `Out/clink-server` / `Out/clink-server.exe`
- `Out/clink-cli` / `Out/clink-cli.exe`

日志默认落地到：

- CLI：默认 `logs/clink-cli.log`
- 服务端：优先使用配置文件 `[[logging.sinks]]` 中启用的文件类 sink 路径
- 若服务端未配置文件类 sink，则回退到平台默认：Windows `logs/clink-win.log`，Linux `logs/clink-linux.log`

默认示例配置 `config/clink.init.toml:58` 当前将服务端日志写到 `logs/clink-daemon.log`

---

## 3. 如何使用
### 3.1 启动远端服务端（Linux）

```bash
cd /mnt/d/Project/CLink
./Out/clink-server --config ./config/clink.init.toml
```

### 3.2 启动本地服务端（Windows）

```powershell
cd D:\Project\CLink
.\Out\clink-server.exe --config .\config\clink.init.toml
```

### 3.3 用 CLI 控制本地 daemon（Windows）

```powershell
cd D:\Project\CLink
.\Out\clink-cli.exe connect --transport tcp --ip <server-ip> --port <port>
.\Out\clink-cli.exe status
.\Out\clink-cli.exe disconnect
```

### 3.4 查看服务端帮助与版本

```powershell
cd D:\Project\CLink
.\Out\clink-server.exe --help
.\Out\clink-server.exe --version
```

> `--help` / `--version` 不会触发 Windows 自动提权。

### 3.5 非管理员本地排查（Windows）

```powershell
cd D:\Project\CLink
$env:CLINK_DISABLE_VIF='1'
.\Out\clink-server.exe --no-elevate --config .\config\clink.init.toml
```

> `--no-elevate` 只跳过自动提权；如需非管理员排查，请同时关闭 VIF。

---

## 4. 环境变量

以下环境变量在当前版本有效：

### 核心控制

- `CLINK_CONFIG_PATH`
  - 指定配置文件路径（server/cli 都支持）

- `CLINK_DISABLE_VIF=1`
  - 禁用虚拟网卡（VIF/TUN）
  - Windows 下还会跳过提权启动逻辑

- `CLINK_DISABLE_PROCESS_MANAGER=1`
  - 禁用 ProcessManager（SOCKS/注入链）

### 连接策略

- `CLINK_ALLOW_SELF_CONNECT_DEBUG=1`
  - 允许自连接调试（仅调试建议）

- `CLINK_FORCE_DISABLE_SELF_CONNECT_DEBUG=1`
  - 强制关闭自连接调试放行

- `CLINK_ALLOW_TRANSPORT_MISMATCH=1`
  - 允许 listener/target 传输类型不一致（调试用途）

### 日志/观测

- `CLINK_TELEMETRY_SAMPLE`
  - `0`：关闭 `tun_to_network/network_to_tun` span
  - `1`：全量
  - `N`：每 N 次采样一次（默认 `64`）

---

## 5. 编译

## 5.1 依赖要求

- CMake `>= 3.24`
- C++20 编译器
- Ninja（推荐）

## 5.2 Windows

```powershell
cd D:\Project\CLink
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target clink-cli clink-server -j 8
```

## 5.3 Linux / WSL

```bash
cd /mnt/d/Project/CLink
cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux --target clink-cli clink-server -j 8
```

## 5.4 使用 CMake Presets（推荐日常开发）

```powershell
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

> `debug` 预设默认开启测试，适合本地迭代；Release 仍建议使用上面的显式命令。

> 不要混用同一个 build 目录给 Windows 和 WSL。

## 6. external 目录需要准备什么

项目优先使用本地 `external/`，找不到才走 CPM 下载。

### 必需（本地放置）

1. `external/asio`
   - 需包含：`external/asio/include/asio.hpp`

2. `external/nlohmann_json`
   - 需包含其一：
     - `external/nlohmann_json/include/nlohmann/json.hpp`
     - `external/nlohmann_json/single_include/nlohmann/json.hpp`

3. `external/spdlog`（可选本地）
   - 需包含：`external/spdlog/CMakeLists.txt`

4. `external/openssl`（当前工程按此路径链接）
   - 头文件：`external/openssl/include/...`
   - 库目录：`external/openssl/lib`
   - 需要可链接的 `ssl` / `crypto`

### Windows 注入相关

5. `external/minhook`（`CLINK_BUILD_CLIENT_HOOK=ON` 时）
   - 需包含其一：
     - `external/minhook/CMakeLists.txt`
     - `external/minhook/include/MinHook.h` + `src/...`

6. `external/wintun`
   - 运行/虚拟网卡路径需要：`external/wintun/bin/amd64/wintun.dll`

### 证书与密钥

- `config/certs/` 仅应放开发/测试证书，不要提交生产证书或真实私钥。
- 需要重建测试证书时，优先使用 `scripts/generate_certs.ps1 -Force`；脚本默认拒绝覆盖已有产物。
- `config/certs/` 默认被 `.gitignore` 忽略，作为本地生成产物目录使用。
- 分享问题复现包时，先清理 `*.key`、日志和任何环境相关凭据。

## 7. 常见问题

### Q1: CLI 提示连接失败，但 server 在跑
- 确认 CLI 连接的是远端监听端口
- 确认远端 listener 端口与命令一致（如 `4433`）
- 查看对应日志文件（win/linux 分开）

### Q2: Windows 断开时出现 `read header error`
- 主动 `disconnect` 触发 socket 关闭时可能出现关闭伴生日志
- 当前版本已做语义降级，优先按会话状态机判断是否异常

### Q3: 为什么 CLI 能跑但没会话
- CLI 仅控制器，不直接承担远程网络会话
- 必须确保本机 `clink-server` 和远端 `clink-server` 都在运行

---
---

## 7. CLI Exit Codes

`clink-cli` uses a 3-level exit-code contract:

- `0` = success
- `1` = failed or rejected
- `2` = success, but restart is required to fully apply config

Common command behavior:

- `status`
  - `0`: daemon/client status is healthy enough and no restart-required drift is reported
  - `1`: status request failed
  - `2`: status succeeded, but `restart_required=true`

- `reload`
  - `0`: reload succeeded and no deferred restart is required
  - `1`: reload failed, or the request was rejected
  - `2`: reload succeeded, but some config remains deferred and needs restart

- `connect` / `disconnect`
  - `0`: request accepted
  - `1`: request failed or was rejected (`accepted=false`)

- `diag`
  - `0`: clean diagnostic result
  - `1`: hard failure (for example daemon unavailable or config unreadable)
  - `2`: warnings only (for example restart-required drift, degraded health, missing logs, missing config)

## 8. Control Status Contract

The control plane uses a structured JSON envelope:

For the canonical shared schema used by daemon, client-local control, and CLI parsing, see `src/share/include/clink/protocol/CONTROL_PLANE_SCHEMA.md`.

```json
{
  "ok": true,
  "command": "status",
  "data": { ... }
}
```

Failure responses use the same envelope shape and still carry structured `data`:

```json
{
  "ok": false,
  "command": "connect",
  "error": "service_not_running",
  "data": {
    "accepted": false,
    "status": "failed",
    "reason": "service_not_running",
    "message": "service_not_running"
  }
}
```

Typical `data` fields returned by `status` / `reload` / `disconnect` / `connect` include:

Reason codes are stable, machine-readable identifiers. Prefer branching on `data.reason` instead of the free-form `error` text.

- Service/runtime: `service_not_running`, `service_shutting_down`, `no_handler`, `handler_exception`, `unknown_command`
- Session policy: `no_session_manager`, `missing_endpoint`, `session_not_disconnected`, `session_not_active`, `self_connect_blocked`
- Connect execution: `transport_mismatch`, `transport_start_failed`, `create_session_exception`, `create_session_exception_unknown`
- Log access: `log_open_failed`
- Windows IPC: `pipe_open_failed`, `pipe_set_mode_failed`, `pipe_write_failed`, `pipe_read_failed`
- Unix IPC: `socket_create_failed`, `socket_connect_failed`, `request_too_large`, `request_write_failed`, `response_length_read_failed`, `response_length_invalid`, `response_read_failed`

- `status`: `disconnected|connecting|connected|disconnecting|rejected|failed|pending`
- `session_id`: current representative session id, or `none`
- `accepted`: whether the command transition was accepted
- `accepted=true`: implied for successful `status` / `reload` / `disconnect` / `logs` responses when no command-specific override is needed
- `reason`: machine-readable rejection/failure reason
- `message`: human-readable detail
- `connect_phase`, `connect_reason`, `connect_message`: last connection lifecycle snapshot
- `active_sessions`: number of active sessions
- `tracked_sessions`: number of tracked sessions including handshaking ones
- `restart_required`: whether a process restart is needed for full config convergence
- `restart_reasons`: list of deferred config domains

Daemon status may also include:

- `health`
- `process_manager`
- `effective_ipc_address`
- `configured_ipc_address`
- `sessions` with per-session `status`

Client-local status may also include:

- `config_reload_supported`
- `config_status`

`logs --tail` and `monitor` will surface status-derived alerts when available.
