# CLink - High-Performance Secure Network Tunnel

**Author**: TTxyz  
**Date**: 2026-02-16  
**Version**: v1.1.0

**CLink** is a modern, high-performance network tunneling and intranet penetration tool written in C++20. It utilizes advanced virtual networking (TUN/TAP) to provide secure, reliable, and efficient connectivity, enabling seamless access to intranet resources from anywhere.

While technically a Layer 3 VPN (Virtual Private Network) that constructs a secure overlay network, CLink is designed with the simplicity and flexibility required for modern intranet penetration and mesh networking scenarios.

## 🚀 Key Features

*   **Intranet Penetration & Access**: Easily expose or access internal services across NAT/Firewalls without complex port forwarding.
*   **Secure Tunneling**: Built-in TLS 1.3 support for end-to-end encryption.
*   **Reliability Layer**: Custom reliability engine ensuring data delivery over unstable networks (ACK, Retransmission, Flow Control).
*   **Cross-Platform**: Supports Windows (Wintun/TAP) and Linux (TUN/TAP).
*   **Modern C++**: Built with C++20, utilizing `asio` for high-concurrency asynchronous I/O.
*   **Zero-Copy Design**: (In Progress) Optimized data path to minimize memory overhead and maximize throughput.
*   **Modular Architecture**: Flexible adapter system supporting multiple transport protocols (TCP/TLS/QUIC).

## 🛠️ Build Requirements

*   **Compiler**: C++20 compatible compiler (GCC 11+, Clang 14+, MSVC 19.29+).
*   **CMake**: Version 3.20 or higher.
*   **Dependencies**:
    *   OpenSSL (1.1.1 or 3.0+)
    *   Asio (Standalone)
    *   Catch2 (for testing)

## 📦 Building CLink

### Windows (MinGW / MSVC)

We provide a helper script for MinGW environments:

```powershell
# Build everything (Service, CLI, Tests)
python scripts/mingw.py
```

Or using standard CMake:

```powershell
cmake --preset debug
cmake --build --preset debug
```

### Linux

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## 💻 Usage

CLink consists of a background service (`clink-service`) and a command-line interface (`clink-cli`).

### Starting the Server

```bash
./Out/clink-service --config config/clink.sample.toml
```

### Client Connection

```bash
# Connect to a remote CLink server
./Out/clink-cli connect --server <SERVER_IP> --port 443 --token <AUTH_TOKEN>
```

## 📂 Project Structure

*   `src/`: Core source code.
    *   `core/`: Core logic (Session, Network, Config).
    *   `service/`: Daemon/Service entry point.
    *   `cli/`: Command-line tool implementation.
*   `include/`: Public header files.
*   `tests/`: Unit and integration tests (Catch2).
*   `config/`: Configuration files and certificates.
*   `scripts/`: Build and utility scripts.
*   `docs/`: Architecture and design documentation.

## 🧪 Testing

Run the automated test suite:

```powershell
# Run unit tests
./build/debug/tests/clink-network-tests.exe

# Run performance tests
./build/debug/tests/clink-network-perf-tests.exe 10 10
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
