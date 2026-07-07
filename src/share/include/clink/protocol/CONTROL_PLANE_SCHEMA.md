# 控制平面模式

本文档定义了守护进程、客户端本地应用包装器和 CLI 之间共享的规范化的机器可读控制平面合约。

## 来源

- 字段名、状态值、原因代码、重启域和哨兵值位于 `src/share/include/clink/protocol/control_plane.hpp` 中。
- 线路帧格式和结构化错误信封辅助工具位于 `src/share/include/clink/protocol/ipc_wire.hpp` 中。

## 封装

所有结构化的控制响应均使用相同的信封格式：

```json
{
  "ok": true,
  "command": "status",
  "data": { ... }
}
```

失败响应保持相同的外部结构，并且仍必须提供结构化的 `data`：

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

自动化逻辑应基于 `data.reason` 和 `data.status` 进行分支判断，而非自由文本的 `error` 字段。

## 核心载荷组

- 会话生命周期：`status`、`session_id`、`connect_phase`、`connect_reason`、`connect_message`、`active_sessions`、`tracked_sessions`
- 重启/配置漂移：`restart_required`、`restart_reasons`、`config_reload_supported`、`effective_ipc_address`、`configured_ipc_address`、`config_status`
- 健康/进程管理：`health`、`process_manager.state`、`process_manager.reason`、`process_manager.socks_backend`、`process_manager.socks_available`
- 日志载荷：`content`、`path`

## 重启域/热加载

当前共享的重启域值包括：

- `ipc.address`
- `process_manager.runtime`
- `transport.runtime`
- `logging`

## 生产者和消费者

- 守护进程生产者：`src/server/core/application/application.cpp`
- 客户端本地生产者：`src/client/core/application/application.cpp`
- IPC 辅助工具：`src/share/core/ipc/ipc_message_utils.hpp`、`src/share/core/ipc/ipc_message_utils.hpp`
- CLI 消费者/渲染：`src/client/main.cpp`

在扩展控制平面时，应首先将新的机器可读值添加到 `src/share/include/clink/protocol/control_plane.hpp` 中，然后同步更新生产者和消费者。