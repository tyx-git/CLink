## 🧪 Testing

Run the automated test suite using CTest:

```powershell
# Run all tests
ctest --preset debug
```

## 🚀 Release Notes

### v1.2.0 - Zero-Copy Performance Update

This release introduces a major architectural overhaul to the data forwarding plane, achieving **User-Space Zero-Copy** for high-throughput scenarios.

#### Key Features
*   **Zero-Copy Forwarding**: Eliminated memory copies between Virtual Interface (TUN/TAP), Session Manager, and Transport Layer.
*   **Buffer Pool Management**: Implemented `BufferPool` and `Block` infrastructure for efficient, thread-safe memory reuse.
*   **Scatter/Gather I/O**: Refactored `TransportAdapter` (TCP/TLS) to use `asio::async_write` with buffer sequences, removing serialization overhead.
*   **Optimized Reliability**: `ReliabilityEngine` now stores and retransmits `Packet` objects directly, reducing CPU usage during packet loss.
*   **Platform Optimizations**:
    *   **Windows**: Implemented asynchronous overlapped I/O for TAP devices.
    *   **Linux**: Implemented direct `read`/`write` to `BufferPool` blocks for TUN devices.
*   **Process Injection & IPC**: Introduced `clink-hook` DLL and `ProcessIPCServer` for transparent process traffic redirection.
*   **SOCKS5 Transparent Proxy**: Implemented SOCKS5 server and client-side redirection via API hooking.
*   **Process-Level Data Channel**: Established high-performance Named Pipe IPC for direct data transfer, bypassing TCP loopback overhead.

#### Performance Impact
*   Reduced per-packet memory allocations from ~3 to **0** (steady state).
*   Reduced data copies from ~4 to **0** (user-space).
*   Significantly lower CPU usage and GC pressure under high load.

### Updates by TTxyz

*   **Stability & Concurrency Fixes**:
    *   Resolved a deadlock in `ReadLoop` during DLL process detachment.
    *   Fixed thread safety issues in logging by introducing `g_log_mutex`.
    *   Eliminated race conditions in `log_file` access.
    *   Added pre-initialization cleanup for `g_recv_buffers` and `g_socks_sockets` to prevent dirty data.
*   **Data Forwarding Improvements**:
    *   Removed restrictive `!is_socks` checks to ensure all traffic (including DNS and non-SOCKS) is correctly forwarded.
    *   Fixed `SendIpcMessage` ordering to prevent race conditions during connection establishment.
*   **Integration & Routing**:
    *   Integrated `ProcessManager` with `SessionManager`.
    *   Implemented Virtual Interface IP (VIP) binding (`10.8.0.1`) for outgoing SOCKS and IPC proxy connections, ensuring correct traffic routing through the virtual network interface.
*   **Build System**:
    *   Fixed CMake build errors in `policy/engine.hpp` by implementing the missing `get_keys()` method in the client configuration.

## 📄 License
