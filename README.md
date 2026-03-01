# CLink

CLink 是一个面向 Windows 的连接与代理工具集，包含：

- `clink-server`：服务端守护进程（会话管理、IPC 控制、SOCKS、进程注入桥接）
- `clink-cli`：客户端命令行工具（状态查询、诊断、日志、控制命令）

---

## 目录结构（核心）

- `server/`：服务端核心实现（network/modules/ipc/application）
- `client/`：CLI 与客户端运行时实现
- `server/modules/process_inject/`：服务端注入与 IPC 服务
- `client/modules/process_inject/`：注入 DLL（Winsock Hook）
- `external/`：本地第三方依赖（asio、nlohmann_json、spdlog、openssl 等）
- `Out/`：编译输出目录（exe/dll）

---

## 先决条件

建议环境：

- Windows 10/11
- CMake >= 3.24
- Ninja（推荐）
- MinGW-w64 (GCC 14+) 或 MSVC
- OpenSSL（项目已使用 `external/openssl`）

> 本项目 CMake 已支持优先使用 `external/` 下本地依赖（Asio / nlohmann_json），弱网环境可离线构建。

---

## 构建教程（推荐 Ninja + MinGW）

### 1) 清理目录

```powershell
cd D:\Project\CLink
if (Test-Path .\build) { Remove-Item .\build -Recurse -Force }
if (Test-Path .\Out) { Remove-Item .\Out -Recurse -Force }
New-Item -ItemType Directory -Path .\Out | Out-Null
```

### 2) 配置

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
```

### 3) 编译目标

```powershell
cmake --build build --config Release --target clink-cli clink-server -j 8
```

### 4) 检查输出

```powershell
Get-ChildItem .\Out
```

通常会看到：

- `clink-cli.exe`
- `clink-server.exe`
- 若干 `.dll` / `.dll.a`

---

## `.dll` 与 `.dll.a` 说明

- `.dll`：Windows 动态库，运行时加载
- `.dll.a`：MinGW 导入库（import library），用于链接阶段解析 DLL 导出符号

它们出现在 `Out` 目录是正常现象，尤其是注入/进程管理相关模块。

---

## 运行教程

### 1) 启动服务端

```powershell
.\Out\clink-server.exe
```

### 2) clink-cli 与 clink-server 联动使用

> 建议先开一个终端运行 `clink-server`，再开第二个终端执行 `clink-cli`。

```powershell
# 终端 A：启动服务端
.\Out\clink-server.exe
```

```powershell
# 终端 B：确认 IPC 联通与服务状态
.\Out\clink-cli.exe status
```

```powershell
# 终端 B：发起会话连接（由 server 处理）
.\Out\clink-cli.exe connect

# 查看状态是否变化
.\Out\clink-cli.exe status

# 实时监控
.\Out\clink-cli.exe monitor
```

```powershell
# 终端 B：结束会话
.\Out\clink-cli.exe disconnect

# 重载配置
.\Out\clink-cli.exe reload
```

```powershell
# 查看日志（一次）
.\Out\clink-cli.exe logs

# 持续追踪日志
.\Out\clink-cli.exe logs --tail

# 诊断
.\Out\clink-cli.exe diag

# 加密密钥（写入配置前使用）
.\Out\clink-cli.exe encrypt <your_secret>
```

### 3) 远端地址与端口配置（connect 命令依赖）

> `clink-cli` 控制 `clink-server` 走的是本地 named pipe（`\\.\\pipe\\clink-ipc`）。
> `connect` 的默认策略：
> 1. **优先 TLS**（默认目标 `tls://127.0.0.1:4433`）
> 2. TLS 失败/被拒绝时，可选择是否 **回退 TCP**（`tcp://127.0.0.1:4433`）
> 3. 使用 `--allow-all` 可自动回退（不二次确认）

在 `config/clink.init.toml` 中可配置默认远端：

```toml
# connect 默认远端（当 CLI 未显式覆盖时可参考）
# 建议优先 tls://
client.remote_endpoint = "tls://127.0.0.1:4433"

# TCP 示例
# client.remote_endpoint = "tcp://127.0.0.1:4433"
```

### 4) CLI 参数说明

```text
-c, --config <path>      指定配置文件路径
--ip <address>           connect 时覆盖远端地址（如 192.168.1.10）
--port <port>            connect 时覆盖远端端口（如 4433）
--transport <tcp|tls>    connect 时显式指定协议（默认优先 tls）
--timeout <ms>           连接超时提示参数（传递给 daemon）
--no-self-check          允许跳过自连接检查（调试用途）
--allow-all              TLS 失败时自动回退 TCP（不提示确认）
--tail                   与 logs 命令配合，持续追踪日志

连接行为补充：
- 未显式指定 `--transport` 时：`connect` 总是先尝试 TLS，再决定是否回退 TCP。
- 显式指定 `--transport tls` 或 `--transport tcp` 时：仅使用指定协议，不再自动尝试另一协议。
- 服务端会校验目标协议与 `network.listen_endpoint` 协议是否一致；不一致将返回 `transport_mismatch`。
- 调试时可设置 `CLINK_ALLOW_TRANSPORT_MISMATCH=1` 放开该限制（不建议生产使用）。
encrypt <secret>         对密钥进行 DPAPI 加密
```

示例：

```powershell
# 默认：先尝试 TLS，失败后询问是否回退 TCP
.\Out\clink-cli.exe connect

# 自动允许所有回退行为（含 TLS->TCP 自动重试）
.\Out\clink-cli.exe connect --allow-all

# 显式 TCP（跳过 TLS 优先逻辑）
.\Out\clink-cli.exe connect --transport tcp --ip 127.0.0.1 --port 4433

# 显式 TLS 到远端
.\Out\clink-cli.exe connect --transport tls --ip 10.0.0.8 --port 443
```

### 5) 指定配置文件

```powershell
.\Out\clink-cli.exe -c .\config\clink.init.toml status
```

也可以使用环境变量：

```powershell
$env:CLINK_CONFIG_PATH="D:\Project\CLink\config\clink.init.toml"
.\Out\clink-cli.exe status
```

---

## 常见问题排查

### 1) JSON 相关报错（解析失败 / include 找不到）

请确认：

- 代码使用：`#include <nlohmann/json.hpp>`
- `external/nlohmann_json` 为官方包目录（含 `include/nlohmann/json.hpp`）
- CMake 配置日志中出现本地 nlohmann_json 命中提示

### 2) undefined reference（IPC 工厂函数）

若出现 `create_client/create_server(...)` 未定义：

- 检查 `client/include/clink/core/ipc.hpp` 与 `client/src/ipc.cpp` 函数签名是否一致
- 清理 `build` 后重新 configure + build

### 3) 大量 warning

当前已知存在部分第三方头文件警告噪声（Asio 模板内联）。
优先关注 **FAILED / undefined reference / fatal error** 类型错误。

---

## 测试

```powershell
# Run all tests
ctest --preset debug
```

---

## 当前稳定性状态（简述）

- 基础命令链路：可用
- 注入/转发链路：已具备主路径
- 并发目标：建议以 50 并发为验收，进行持续压测并观察丢包、超时、队列峰值

详见 `report.md` 的审查与建议。

---

## License

(按项目实际许可证补充)
