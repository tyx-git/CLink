# Control Plane Schema

This document defines the canonical machine-readable control-plane contract shared by the daemon, the client-local application wrapper, and the CLI.

## Source of Truth

- Field names, status values, reason codes, restart domains, and sentinel values live in `src/share/include/clink/protocol/control_plane.hpp`.
- Wire framing and structured error-envelope helpers live in `src/share/include/clink/protocol/ipc_wire.hpp`.

## Envelope

All structured control responses use the same envelope:

```json
{
  "ok": true,
  "command": "status",
  "data": { ... }
}
```

Failures keep the same outer shape and must still provide structured `data`:

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

Automation should branch on `data.reason` and `data.status`, not on the free-form `error` text.

## Core Payload Groups

- Session lifecycle: `status`, `session_id`, `connect_phase`, `connect_reason`, `connect_message`, `active_sessions`, `tracked_sessions`
- Restart/config drift: `restart_required`, `restart_reasons`, `config_reload_supported`, `effective_ipc_address`, `configured_ipc_address`, `config_status`
- Health/process manager: `health`, `process_manager.state`, `process_manager.reason`, `process_manager.socks_backend`, `process_manager.socks_available`
- Log payloads: `content`, `path`

## Restart Domains

The current shared restart-domain values are:

- `ipc.address`
- `process_manager.runtime`
- `transport.runtime`
- `logging`

## Producers and Consumers

- Daemon producer: `src/server/core/application/application.cpp`
- Client-local producer: `src/client/core/application/application.cpp`
- IPC helpers: `src/share/core/ipc/ipc_message_utils.hpp`, `src/share/core/ipc/ipc_message_utils.hpp`
- CLI consumer/rendering: `src/client/main.cpp`

When extending the control plane, add new machine-readable values to `src/share/include/clink/protocol/control_plane.hpp` first, then update producers and consumers together.
