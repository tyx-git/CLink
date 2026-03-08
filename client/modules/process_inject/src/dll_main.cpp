#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <MinHook.h>
#include <iostream>
#include <vector>
#include <mutex>
#include <atomic>
#include <thread>

#include "ipc_protocol.hpp"

#include <deque>
#include <map>

// Link against Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#include <cstdio>
#include <string>

std::string build_log_file_path() {
    char temp_path[MAX_PATH] = {0};
    const DWORD len = GetTempPathA(MAX_PATH, temp_path);
    if (len == 0 || len > MAX_PATH) {
        return "clink_hook_debug.log";
    }

    std::string path(temp_path, temp_path + len);
    if (!path.empty() && path.back() != '\\' && path.back() != '/') {
        path.push_back('\\');
    }
    path += "clink_hook_debug.log";
    return path;
}

void local_debug_log(const std::string& msg) {
    // Output to debugger
    std::string debug_msg = "[CLink] " + msg + "\n";
    OutputDebugStringA(debug_msg.c_str());

    // Fallback local file log (kept for early bootstrap / IPC unavailable cases)
    static const std::string kLogFilePath = build_log_file_path();
    HANDLE hFile = CreateFileA(kLogFilePath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[64];
        SYSTEMTIME st;
        GetLocalTime(&st);
        int len = snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d.%03d - ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        DWORD written = 0;
        WriteFile(hFile, buffer, len, &written, NULL);
        WriteFile(hFile, msg.c_str(), (DWORD)msg.length(), &written, NULL);
        WriteFile(hFile, "\r\n", 2, &written, NULL);

        CloseHandle(hFile);
    }
}

namespace {

using namespace clink::hook::ipc;

// Function pointers for original functions
typedef int (WSAAPI *connect_t)(SOCKET, const struct sockaddr*, int);
typedef int (WSAAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WSAAPI *recv_t)(SOCKET, char*, int, int);
typedef int (WSAAPI *closesocket_t)(SOCKET);

connect_t fpConnect = nullptr;
send_t fpSend = nullptr;
recv_t fpRecv = nullptr;
closesocket_t fpCloseSocket = nullptr;

HANDLE g_pipe = INVALID_HANDLE_VALUE;
std::mutex g_inject_mutex;
std::mutex g_pipe_mutex;
std::mutex g_connect_mutex;
std::mutex g_init_mutex;
std::map<uint64_t, std::deque<char>> g_inject_queues;
constexpr size_t kMaxInjectQueuePerSocket = 256 * 1024; // 256 KB / socket
constexpr uint32_t kMaxIpcBodyBytes = 4 * 1024 * 1024; // 4MB safety cap
std::atomic<bool> g_connected{false};
std::atomic<bool> g_shutting_down{false};
std::atomic<bool> g_hooks_cleaned_up{false};

// Concurrency/pressure metrics (for 50-concurrency stability)
std::atomic<uint64_t> g_ipc_packets_tx{0};
std::atomic<uint64_t> g_ipc_packets_rx{0};
std::atomic<uint64_t> g_ipc_bytes_tx{0};
std::atomic<uint64_t> g_ipc_bytes_rx{0};
std::atomic<uint64_t> g_ipc_timeouts{0};
std::atomic<uint64_t> g_ipc_drops{0};
std::atomic<uint64_t> g_inject_queue_drops{0};

// Lightweight runtime counters for 50-concurrency acceptance
std::atomic<uint64_t> g_ipc_packets_sent{0};
std::atomic<uint64_t> g_ipc_packets_dropped{0};
std::atomic<uint64_t> g_ipc_write_timeouts{0};
std::atomic<uint64_t> g_ipc_bytes_sent{0};
std::atomic<uint64_t> g_ipc_bytes_recv{0};
std::atomic<uint64_t> g_inject_bytes_served{0};
std::atomic<uint64_t> g_inject_queue_peak{0};

struct OutgoingPacket {
    PacketType type;
    uint64_t socket_id;
    std::vector<char> payload;
};

std::mutex g_outgoing_mutex;
std::deque<OutgoingPacket> g_outgoing_queue;
size_t g_outgoing_log_packets = 0;
HANDLE g_hOutgoingEvent = NULL;
HANDLE g_hIpcWriterThread = NULL;
constexpr size_t kMaxOutgoingPackets = 4096;
constexpr size_t kMaxOutgoingLogPackets = 1024;

HANDLE g_hReadThread = NULL;
HANDLE g_hStatsThread = NULL;

DWORD WINAPI ReadLoopThreadProc(LPVOID lpParam);
DWORD WINAPI StatsThreadProc(LPVOID lpParam);
DWORD WINAPI IpcWriterThreadProc(LPVOID lpParam);

bool enqueue_ipc_packet(PacketType type, uint64_t socket_id, const char* data, uint32_t len);

enum class HookLogLevel : uint8_t {
    Info = 1,
    Error = 2
};

void send_unified_log(const std::string& msg, HookLogLevel level = HookLogLevel::Info) {
    std::vector<char> payload;
    payload.reserve(msg.size() + 1);
    payload.push_back(static_cast<char>(level));
    payload.insert(payload.end(), msg.begin(), msg.end());
    enqueue_ipc_packet(PacketType::Log, 0, payload.data(), static_cast<uint32_t>(payload.size()));
}

std::string make_log_message(const std::string& msg) {
    return "pid=" + std::to_string(GetCurrentProcessId()) +
           " tid=" + std::to_string(GetCurrentThreadId()) +
           " " + msg;
}

void bridge_log(const std::string& msg, bool is_error = false) {
    const std::string full_msg = make_log_message(msg);
    if (g_connected && !g_shutting_down) {
        send_unified_log(full_msg, is_error ? HookLogLevel::Error : HookLogLevel::Info);
    }
    local_debug_log(full_msg);
}

void update_queue_peak_locked() {
    uint64_t total = 0;
    for (const auto& kv : g_inject_queues) {
        total += static_cast<uint64_t>(kv.second.size());
    }
    uint64_t peak = g_inject_queue_peak.load();
    while (total > peak && !g_inject_queue_peak.compare_exchange_weak(peak, total)) {
    }
}

void log_runtime_counters(const char* prefix) {
    bridge_log(std::string(prefix) +
        " packets_sent=" + std::to_string(g_ipc_packets_sent.load()) +
        " packets_dropped=" + std::to_string(g_ipc_packets_dropped.load()) +
        " write_timeouts=" + std::to_string(g_ipc_write_timeouts.load()) +
        " bytes_sent=" + std::to_string(g_ipc_bytes_sent.load()) +
        " bytes_recv=" + std::to_string(g_ipc_bytes_recv.load()) +
        " inject_bytes_served=" + std::to_string(g_inject_bytes_served.load()) +
        " inject_queue_peak=" + std::to_string(g_inject_queue_peak.load()) +
        " rx_packets=" + std::to_string(g_ipc_packets_rx.load(std::memory_order_relaxed)) +
        " rx_bytes=" + std::to_string(g_ipc_bytes_rx.load(std::memory_order_relaxed)) +
        " rx_queue_drops=" + std::to_string(g_inject_queue_drops.load(std::memory_order_relaxed)));
}

DWORD WINAPI StatsThreadProc(LPVOID) {
    while (!g_shutting_down) {
        Sleep(5000);
        if (g_shutting_down) break;
        log_runtime_counters("[stats] periodic");
    }
    return 0;
}

DWORD WINAPI ReadLoopThreadProc(LPVOID lpParam) {
    // Keep DLL loaded while this thread is running
    HMODULE hModule = NULL;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN, (LPCTSTR)ReadLoopThreadProc, &hModule)) {
         bridge_log("ReadLoop: GetModuleHandleEx failed", true);
         return 1;
    }

    while (g_connected) {
        PacketHeader header;
        DWORD read;
        OVERLAPPED ov = {0};
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
        if (!ov.hEvent) break;

        bool success = false;
        if (ReadFile(g_pipe, &header, sizeof(header), &read, &ov)) {
            success = true;
        } else if (GetLastError() == ERROR_IO_PENDING) {
            while (g_connected) {
                DWORD wait = WaitForSingleObject(ov.hEvent, 500);
                if (wait == WAIT_OBJECT_0) {
                    if (GetOverlappedResult(g_pipe, &ov, &read, FALSE)) {
                        success = true;
                    }
                    break;
                } else if (wait == WAIT_TIMEOUT) {
                    continue;
                } else {
                    break;
                }
            }
            if (!g_connected) CancelIo(g_pipe);
        }
        
        CloseHandle(ov.hEvent);

        if (!success || read != sizeof(header)) {
            bridge_log("ReadLoop: header read failed success=" + std::to_string(success ? 1 : 0) +
                       " bytes=" + std::to_string(read), true);
            g_connected = false;
            break;
        }

        bridge_log("ReadLoop: header type=" + std::to_string(static_cast<int>(header.type)) +
                   " sid=" + std::to_string(header.socket_id) +
                   " len=" + std::to_string(header.length));

        if (header.magic != IPC_MAGIC) {
            bridge_log("ReadLoop: invalid magic", true);
            break;
        }
        if (header.length > kMaxIpcBodyBytes) {
            bridge_log("ReadLoop: body too large, closing IPC", true);
            g_connected = false;
            break;
        }

        std::vector<char> body(header.length);
        if (header.length > 0) {
            OVERLAPPED ovBody = {0};
            ovBody.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            success = false;
            
            if (ReadFile(g_pipe, body.data(), header.length, &read, &ovBody)) {
                success = true;
            } else if (GetLastError() == ERROR_IO_PENDING) {
                while (g_connected) {
                    DWORD wait = WaitForSingleObject(ovBody.hEvent, 500);
                    if (wait == WAIT_OBJECT_0) {
                        if (GetOverlappedResult(g_pipe, &ovBody, &read, FALSE)) {
                            success = true;
                        }
                        break;
                    } else if (wait == WAIT_TIMEOUT) {
                        continue;
                    } else {
                        break;
                    }
                }
                if (!g_connected) CancelIo(g_pipe);
            }
            CloseHandle(ovBody.hEvent);

            if (!success || read != header.length) {
                bridge_log("ReadLoop: body read failed success=" + std::to_string(success ? 1 : 0) +
                           " bytes=" + std::to_string(read) +
                           " expected=" + std::to_string(header.length), true);
                g_connected = false;
                break;
            }
        }

        if (header.type == PacketType::DataRecv) {
             std::lock_guard<std::mutex> lock(g_inject_mutex);
             auto& queue = g_inject_queues[header.socket_id];
             if (queue.size() + body.size() > kMaxInjectQueuePerSocket) {
                 const size_t allowed = (queue.size() < kMaxInjectQueuePerSocket)
                     ? (kMaxInjectQueuePerSocket - queue.size())
                     : 0;
                 if (allowed > 0) {
                     queue.insert(queue.end(), body.begin(), body.begin() + static_cast<std::ptrdiff_t>(allowed));
                 }
                 const uint64_t dropped = static_cast<uint64_t>(body.size() - allowed);
                 g_inject_queue_drops.fetch_add(dropped, std::memory_order_relaxed);
                 g_ipc_packets_dropped.fetch_add(1, std::memory_order_relaxed);
             }else {
                 queue.insert(queue.end(), body.begin(), body.end());
             }
             g_ipc_packets_rx.fetch_add(1, std::memory_order_relaxed);
             g_ipc_bytes_rx.fetch_add(static_cast<uint64_t>(body.size()), std::memory_order_relaxed);
             g_ipc_bytes_recv += static_cast<uint64_t>(body.size());
             update_queue_peak_locked();
        }
    }
    
    bridge_log("ReadLoop: exiting");
    // Thread exits naturally. Module is intentionally pinned for lifetime safety
    // in injected-process context.
    return 0;
}

void connect_ipc() {
    bridge_log("connect_ipc: starting");
    if (g_shutting_down) {
        bridge_log("connect_ipc: shutting down, aborting");
        return;
    }

    // Avoid duplicate connect attempts/thread races
    std::unique_lock<std::mutex> connect_lock(g_connect_mutex, std::try_to_lock);
    if (!connect_lock.owns_lock()) {
        return;
    }

    {
        std::lock_guard<std::mutex> pipe_lock(g_pipe_mutex);
        if (g_connected && g_pipe != INVALID_HANDLE_VALUE) {
            return;
        }
    }

    // Retry loop for connection - do not hold lock during wait
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 5; ++i) {
        if (g_shutting_down) break;

        bridge_log("connect_ipc: attempt " + std::to_string(i));
        if (WaitNamedPipeA(PIPE_NAME, 500)) {
             hPipe = CreateFileA(
                PIPE_NAME,
                GENERIC_READ | GENERIC_WRITE,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                NULL
            );

            if (hPipe != INVALID_HANDLE_VALUE) {
                bridge_log("connect_ipc: pipe connected");
                break;
            }
            bridge_log("connect_ipc: CreateFile failed, error " + std::to_string(GetLastError()), true);
        }

        Sleep(100);
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
        bridge_log("connect_ipc: failed to connect after retries", true);
        return;
    }

    {
        std::lock_guard<std::mutex> pipe_lock(g_pipe_mutex);
        if (g_shutting_down) {
            CloseHandle(hPipe);
            return;
        }

        if (g_pipe != INVALID_HANDLE_VALUE) {
            CancelIoEx(g_pipe, NULL);
            CloseHandle(g_pipe);
        }
        g_pipe = hPipe;
        g_connected = true;

        if (!g_hReadThread) {
            g_hReadThread = CreateThread(NULL, 0, ReadLoopThreadProc, NULL, 0, NULL);
            if (g_hReadThread) {
                bridge_log("connect_ipc: ReadLoop thread started");
            } else {
                bridge_log("connect_ipc: Failed to create ReadLoop thread", true);
                g_connected = false;
                CloseHandle(g_pipe);
                g_pipe = INVALID_HANDLE_VALUE;
            }
        }
    }
}

bool write_ipc_packet_direct(PacketType type, uint64_t socket_id, const char* data, uint32_t len) {
    if (!g_connected) {
        bridge_log("write_ipc_packet_direct: not connected type=" + std::to_string(static_cast<int>(type)));
        return false;
    }

    std::lock_guard<std::mutex> lock(g_pipe_mutex);

    if (g_pipe == INVALID_HANDLE_VALUE) {
        bridge_log("write_ipc_packet_direct: invalid pipe handle", true);
        return false;
    }

    bridge_log("write_ipc_packet_direct: type=" + std::to_string(static_cast<int>(type)) +
               " sid=" + std::to_string(socket_id) +
               " len=" + std::to_string(len));

    PacketHeader header;
    header.magic = IPC_MAGIC;
    header.type = type;
    header.socket_id = socket_id;
    header.length = len;

    DWORD written = 0;
    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        return false;
    }
    bool header_ok = false;

    if (WriteFile(g_pipe, &header, sizeof(header), &written, &ov)) {
        header_ok = true;
    } else if (GetLastError() == ERROR_IO_PENDING) {
        if (WaitForSingleObject(ov.hEvent, 50) == WAIT_OBJECT_0) {
            header_ok = GetOverlappedResult(g_pipe, &ov, &written, FALSE) == TRUE;
        } else {
            g_ipc_write_timeouts++;
            CancelIo(g_pipe);
        }
    }
    CloseHandle(ov.hEvent);

    if (!header_ok) {
        bridge_log("write_ipc_packet_direct: header write failed", true);
        return false;
    }

    g_ipc_packets_sent++;
    g_ipc_bytes_sent += sizeof(PacketHeader);

    if (len > 0 && data) {
        OVERLAPPED ovBody = {0};
        ovBody.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ovBody.hEvent) {
            return false;
        }
        bool body_ok = false;
        if (WriteFile(g_pipe, data, len, &written, &ovBody)) {
            body_ok = true;
        } else if (GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(ovBody.hEvent, 50) == WAIT_OBJECT_0) {
                body_ok = GetOverlappedResult(g_pipe, &ovBody, &written, FALSE) == TRUE;
            } else {
                g_ipc_write_timeouts++;
                CancelIo(g_pipe);
            }
        }
        CloseHandle(ovBody.hEvent);

        if (body_ok) {
            g_ipc_bytes_sent += len;
        } else {
            bridge_log("write_ipc_packet_direct: body write failed", true);
            return false;
        }
    }

    return true;
}

bool enqueue_ipc_packet(PacketType type, uint64_t socket_id, const char* data, uint32_t len) {
    if (!g_connected || g_shutting_down) {
        g_ipc_packets_dropped++;
        return false;
    }

    OutgoingPacket pkt;
    pkt.type = type;
    pkt.socket_id = socket_id;
    if (len > 0 && data) {
        pkt.payload.assign(data, data + len);
    }

    {
        std::lock_guard<std::mutex> qlock(g_outgoing_mutex);

        const bool is_log = (type == PacketType::Log);
        if (g_outgoing_queue.size() >= kMaxOutgoingPackets) {
            if (!is_log) {
                for (auto it = g_outgoing_queue.begin(); it != g_outgoing_queue.end(); ++it) {
                    if (it->type == PacketType::Log) {
                        g_outgoing_queue.erase(it);
                        if (g_outgoing_log_packets > 0) {
                            --g_outgoing_log_packets;
                        }
                        break;
                    }
                }
            }

            if (g_outgoing_queue.size() >= kMaxOutgoingPackets) {
                g_ipc_packets_dropped++;
                return false;
            }
        }

        if (is_log && g_outgoing_log_packets >= kMaxOutgoingLogPackets) {
            g_ipc_packets_dropped++;
            return false;
        }

        g_outgoing_queue.push_back(std::move(pkt));
        if (is_log) {
            ++g_outgoing_log_packets;
        }
    }

    if (g_hOutgoingEvent) {
        SetEvent(g_hOutgoingEvent);
    }
    return true;
}

DWORD WINAPI IpcWriterThreadProc(LPVOID) {
    while (!g_shutting_down) {
        if (g_hOutgoingEvent) {
            WaitForSingleObject(g_hOutgoingEvent, 100);
        } else {
            Sleep(10);
        }

        while (!g_shutting_down) {
            OutgoingPacket pkt;
            {
                std::lock_guard<std::mutex> qlock(g_outgoing_mutex);
                if (g_outgoing_queue.empty()) {
                    break;
                }
                pkt = std::move(g_outgoing_queue.front());
                if (g_outgoing_queue.front().type == PacketType::Log && g_outgoing_log_packets > 0) {
                    --g_outgoing_log_packets;
                }
                g_outgoing_queue.pop_front();
            }

            const char* payload_ptr = pkt.payload.empty() ? nullptr : pkt.payload.data();
            const uint32_t payload_len = static_cast<uint32_t>(pkt.payload.size());
            if (!write_ipc_packet_direct(pkt.type, pkt.socket_id, payload_ptr, payload_len)) {
                connect_ipc();
                if (g_connected && write_ipc_packet_direct(pkt.type, pkt.socket_id, payload_ptr, payload_len)) {
                    continue;
                }
                g_ipc_packets_dropped++;
            }
        }
    }
    return 0;
}

int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    const uint64_t sid = static_cast<uint64_t>(s);
    // Notify daemon about connection attempt
    if (name && name->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)name;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);

        std::string info = std::string(ip) + ":" + std::to_string(ntohs(sin->sin_port));
        enqueue_ipc_packet(PacketType::Connect, sid, info.c_str(), (uint32_t)info.length());
        bridge_log("hook.connect socket_id=" + std::to_string(sid) + " target=" + info);
    } else {
        bridge_log("hook.connect socket_id=" + std::to_string(sid) + " target=<unsupported sockaddr>", true);
    }

    return fpConnect(s, name, namelen);
}

int WSAAPI DetourSend(SOCKET s, const char* buf, int len, int flags) {
    const uint64_t sid = static_cast<uint64_t>(s);
    int ret = fpSend(s, buf, len, flags);
    if (ret > 0) {
        enqueue_ipc_packet(PacketType::DataSend, sid, buf, static_cast<uint32_t>(ret));
        bridge_log("hook.send socket_id=" + std::to_string(sid) + " bytes=" + std::to_string(ret));
    }
    return ret;
}

int WSAAPI DetourRecv(SOCKET s, char* buf, int len, int flags) {
    const uint64_t sid = static_cast<uint64_t>(s);
    {
        std::lock_guard<std::mutex> lock(g_inject_mutex);
        auto it = g_inject_queues.find(sid);
        if (it != g_inject_queues.end() && !it->second.empty()) {
            int copied = 0;
            while (!it->second.empty() && copied < len) {
                buf[copied++] = it->second.front();
                it->second.pop_front();
            }
            bridge_log("hook.recv.injected socket_id=" + std::to_string(sid) + " bytes=" + std::to_string(copied));
            return copied;
        }
    }

    int ret = fpRecv(s, buf, len, flags);
    if (ret > 0) {
        enqueue_ipc_packet(PacketType::DataRecv, sid, buf, static_cast<uint32_t>(ret));
        bridge_log("hook.recv socket_id=" + std::to_string(sid) + " bytes=" + std::to_string(ret));
    }
    return ret;
}

int WSAAPI DetourCloseSocket(SOCKET s) {
    const uint64_t sid = static_cast<uint64_t>(s);
    {
        std::lock_guard<std::mutex> lock(g_inject_mutex);
        g_inject_queues.erase(sid);
    }
    enqueue_ipc_packet(PacketType::Disconnect, sid, nullptr, 0);
    bridge_log("hook.disconnect socket_id=" + std::to_string(sid));
    if (fpCloseSocket) {
        return fpCloseSocket(s);
    }
    return SOCKET_ERROR;
}

void InitializeHooks() {
    bridge_log("InitializeHooks: starting");
    
    if (g_shutting_down) return;
    
    connect_ipc();

    if (!g_hOutgoingEvent) {
        g_hOutgoingEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    }
    if (!g_hIpcWriterThread && g_hOutgoingEvent) {
        g_hIpcWriterThread = CreateThread(NULL, 0, IpcWriterThreadProc, NULL, 0, NULL);
        if (!g_hIpcWriterThread) {
            bridge_log("InitializeHooks: Failed to create IPC writer thread", true);
        }
    }

    if (!g_hStatsThread) {
        g_hStatsThread = CreateThread(NULL, 0, StatsThreadProc, NULL, 0, NULL);
        if (!g_hStatsThread) {
            bridge_log("InitializeHooks: Failed to create stats thread", true);
        }
    }

    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_shutting_down) {
        bridge_log("InitializeHooks: shutting down, aborting hook install");
        return;
    }

    if (MH_Initialize() != MH_OK) {
        bridge_log("MH_Initialize failed", true);
        return;
    }
    bridge_log("MH_Initialize success");

    const MH_STATUS h1 = MH_CreateHookApi(L"Ws2_32.dll", "connect", (LPVOID)DetourConnect, (LPVOID*)&fpConnect);
    const MH_STATUS h2 = MH_CreateHookApi(L"Ws2_32.dll", "send", (LPVOID)DetourSend, (LPVOID*)&fpSend);
    const MH_STATUS h3 = MH_CreateHookApi(L"Ws2_32.dll", "recv", (LPVOID)DetourRecv, (LPVOID*)&fpRecv);
    const MH_STATUS h4 = MH_CreateHookApi(L"Ws2_32.dll", "closesocket", (LPVOID)DetourCloseSocket, (LPVOID*)&fpCloseSocket);

    if (h1 != MH_OK || h2 != MH_OK || h3 != MH_OK || h4 != MH_OK) {
        bridge_log("MH_CreateHookApi failed", true);
        MH_Uninitialize();
        return;
    }

    if (g_shutting_down) {
        MH_Uninitialize();
        return;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        bridge_log("MH_EnableHook failed", true);
        MH_Uninitialize();
        return;
    }
    bridge_log("MH_EnableHook success");
}

void UninitializeHooks() {
    bridge_log("UninitializeHooks: starting");
    bool expected = false;
    if (!g_hooks_cleaned_up.compare_exchange_strong(expected, true)) {
        bridge_log("UninitializeHooks: already cleaned up");
        return;
    }

    g_shutting_down = true;
    g_connected = false;

    if (g_hOutgoingEvent) {
        SetEvent(g_hOutgoingEvent);
    }

    if (g_hStatsThread) {
        WaitForSingleObject(g_hStatsThread, 300);
        CloseHandle(g_hStatsThread);
        g_hStatsThread = NULL;
    }

    if (g_hIpcWriterThread) {
        WaitForSingleObject(g_hIpcWriterThread, 200);
        CloseHandle(g_hIpcWriterThread);
        g_hIpcWriterThread = NULL;
    }

    if (g_hOutgoingEvent) {
        CloseHandle(g_hOutgoingEvent);
        g_hOutgoingEvent = NULL;
    }

    {
        std::lock_guard<std::mutex> qlock(g_outgoing_mutex);
        g_outgoing_queue.clear();
        g_outgoing_log_packets = 0;
    }

    if (g_pipe != INVALID_HANDLE_VALUE) {
        bridge_log("UninitializeHooks: closing pipe");
        // Try to cancel I/O first (best effort)
        CancelIoEx(g_pipe, NULL);
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }

    if (g_hReadThread) {
        bridge_log("UninitializeHooks: waiting read thread exit");
        DWORD wait_rc = WaitForSingleObject(g_hReadThread, 500);
        if (wait_rc == WAIT_TIMEOUT) {
            bridge_log("UninitializeHooks: read thread wait timeout, closing handle", true);
        }
        CloseHandle(g_hReadThread);
        g_hReadThread = NULL;
    }
    bridge_log("UninitializeHooks: read thread cleanup done");

    std::lock_guard<std::mutex> lock(g_init_mutex);
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    fpConnect = nullptr;
    fpSend = nullptr;
    fpRecv = nullptr;
    fpCloseSocket = nullptr;
    bridge_log("UninitializeHooks: hooks disabled");
}

extern "C" __declspec(dllexport) void DisableHooks() {
    UninitializeHooks();
}

} // namespace

DWORD WINAPI InitThreadProc(LPVOID lpParam) {
    InitializeHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    (void)hModule;
    (void)lpReserved;
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        bridge_log("DLL_PROCESS_ATTACH: creating init thread");
        // Use CreateThread instead of std::thread to avoid C++ runtime initialization issues in DllMain
        {
            HANDLE hThread = CreateThread(NULL, 0, InitThreadProc, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            } else {
                bridge_log("Failed to create init thread");
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        bridge_log("DLL_PROCESS_DETACH");
        if (lpReserved != NULL) {
            // Process termination. Do not perform cleanup that might deadlock or crash.
            bridge_log("Process termination, skipping cleanup");
            break; 
        }
        UninitializeHooks();
        break;
    }
    return TRUE;
}
