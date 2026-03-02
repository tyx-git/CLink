# CLink

CLink is a daemon + CLI toolset for managing network sessions.

## Components

- `clink-server`
  - The daemon process.
  - Must be running on both sides:
    - **Service side** (the remote endpoint that accepts connections)
    - **Client side** (the local daemon controlled by CLI)
- `clink-cli`
  - A local control tool only.
  - It does **not** connect directly to remote servers by itself.
  - It sends IPC commands to the local `clink-server` daemon.

---

## Build

## Prerequisites

- CMake >= 3.24
- Ninja (recommended)
- C++20 compiler
- OpenSSL (or project-provided external dependencies)

## Windows (PowerShell)

```powershell
cd D:\Project\CLink
cmake -S . -B build-win -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-win -j
```

## Linux / WSL (bash)

```bash
cd /mnt/d/Project/clink
cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j
```

> Important: do not reuse the same build directory between Windows and WSL.
> Use separate directories like `build-win` and `build-linux`.

---

## How to run (cross-platform test)

This is the correct full flow for a Windows client controlling a local daemon and connecting to a Linux service daemon.

## 1) Start Linux service daemon (remote side)

```bash
cd /mnt/d/Project/clink
export CLINK_DISABLE_VIF=1
export CLINK_DISABLE_PROCESS_MANAGER=1
export CLINK_SERIALIZE_NEW_CONNECTION=1
./out/clink-server --config ./config/clink.init.toml
```

Make sure it listens on a reachable endpoint, for example:

- `tcp://0.0.0.0:4433`

## 2) Start Windows client daemon (local side)

Open **Windows Terminal A**:

```powershell
cd D:\Project\CLink
$env:CLINK_DISABLE_VIF="1"
$env:CLINK_DISABLE_PROCESS_MANAGER="1"
$env:CLINK_SERIALIZE_NEW_CONNECTION="1"
.\Out\clink-server.exe
```

## 3) Use CLI to control local daemon

Open **Windows Terminal B**:

```powershell
cd D:\Project\CLink
.\Out\clink-cli.exe connect --transport tcp --ip 172.18.164.77 --port 4433
.\Out\clink-cli.exe status
.\Out\clink-cli.exe monitor
```

Expected behavior:

- `connect` returns `pending` first (engine starts asynchronously)
- `status` then shows `CONNECTED`
- Linux service logs show 1 active session

---

## Key operational rule

`clink-cli` is a **controller**, not a standalone network client.

You must run:

1. `clink-server` on the **client machine** (so CLI has a local daemon to control), and
2. `clink-server` on the **service machine** (to accept network connections).

Without the local client-side daemon, `clink-cli` has nothing to control.

---

## Useful CLI commands

```powershell
.\Out\clink-cli.exe status
.\Out\clink-cli.exe connect --transport tcp --ip <server-ip> --port <port>
.\Out\clink-cli.exe disconnect
.\Out\clink-cli.exe logs
.\Out\clink-cli.exe logs --tail
.\Out\clink-cli.exe monitor
.\Out\clink-cli.exe diag
```

---

## Self-connect policy

By default, self-connect is blocked for safety.

If you intentionally need local loopback testing, set in config:

```toml
[network]
allow_self_connect = true
```

Use only for debugging.
