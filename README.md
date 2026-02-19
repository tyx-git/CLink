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

#### Performance Impact
*   Reduced per-packet memory allocations from ~3 to **0** (steady state).
*   Reduced data copies from ~4 to **0** (user-space).
*   Significantly lower CPU usage and GC pressure under high load.

## 📄 License
