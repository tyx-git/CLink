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

void debug_log(const std::string& msg) {
    // Output to debugger
    std::string debug_msg = "[CLink] " + msg + "\n";
    OutputDebugStringA(debug_msg.c_str());

    // Output to file using Win32 API to avoid C++ stream locks
    HANDLE hFile = CreateFileA("D:\\Project\\CLink\\clink_hook_debug.log", 
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
std::mutex g_init_mutex;
std::map<uint64_t, std::deque<char>> g_inject_queues;
constexpr size_t kMaxInjectQueuePerSocket = 256 * 1024; // 256 KB / socket
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

HANDLE g_hReadThread = NULL;
HANDLE g_hStatsThread = NULL;

DWORD WINAPI ReadLoopThreadProc(LPVOID lpParam);
DWORD WINAPI StatsThreadProc(LPVOID lpParam);

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
    debug_log(std::string(prefix) +
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
         debug_log("ReadLoop: GetModuleHandleEx failed");
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
            g_connected = false;
            break;
        }

        if (header.magic != IPC_MAGIC) break;

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
    
    debug_log("ReadLoop: exiting");
    // If we pinned the module, we don't need FreeLibraryAndExitThread to keep it alive?
    // Wait, GET_MODULE_HANDLE_EX_FLAG_PIN prevents FreeLibrary from unloading it until process exit.
    // This is safer for preventing crashes, but means we can't truly unload.
    // However, for an injected DLL, leaking it until process exit is often acceptable if unloading is crash-prone.
    // If the user wants to unload cleanly, we should use normal refcounting.
    // Let's use normal refcounting + FreeLibraryAndExitThread.
    
    // But wait, if I use PIN, FreeLibrary won't work.
    // If I don't use PIN, FreeLibrary works.
    // Let's stick to PIN for stability first. If user complains about leak, we can fix.
    // Actually, `FreeLibraryAndExitThread` requires we own a refcount.
    // If we use PIN, the refcount is incremented and pinned.
    
    return 0;
}

void connect_ipc() {
    debug_log("connect_ipc: starting");
    if (g_shutting_down) {
        debug_log("connect_ipc: shutting down, aborting");
        return;
    }

    if (g_connected) {
        return;
    }

    // Retry loop for connection - do not hold lock during wait
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 5; ++i) {
        if (g_shutting_down) break;
        
        debug_log("connect_ipc: attempt " + std::to_string(i));
        // Wait for pipe availability
        if (WaitNamedPipeA(PIPE_NAME, 500)) {
             // Pipe available, try to open
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
                debug_log("connect_ipc: pipe connected");
                break;
            }
            debug_log("connect_ipc: CreateFile failed, error " + std::to_string(GetLastError()));
        } else {
             debug_log("connect_ipc: WaitNamedPipe failed or timed out: " + std::to_string(GetLastError()));
        }
        
        Sleep(100);
    }

    if (hPipe != INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(g_pipe_mutex);
        if (g_shutting_down) {
            CloseHandle(hPipe);
            return;
        }
        
        if (g_pipe != INVALID_HANDLE_VALUE) {
             CloseHandle(g_pipe);
        }
        g_pipe = hPipe;
        g_connected = true;
        
        if (g_hReadThread) {
            DWORD exitCode = 0;
            if (GetExitCodeThread(g_hReadThread, &exitCode) && exitCode == STILL_ACTIVE) {
                // Thread is still running, do nothing? Or should we restart it?
                // If it's running, it might be stuck on old pipe.
                // But we just closed the old pipe (if it was valid).
                // Actually we close g_pipe handle, but ReadFile uses it.
                // It should fail.
            } else {
                CloseHandle(g_hReadThread);
                g_hReadThread = NULL;
            }
        }

        if (!g_hReadThread) {
            g_hReadThread = CreateThread(NULL, 0, ReadLoopThreadProc, NULL, 0, NULL);
            if (g_hReadThread) {
                debug_log("connect_ipc: ReadLoop thread started");
            } else {
                debug_log("connect_ipc: Failed to create ReadLoop thread");
            }
        }
    } else {
        debug_log("connect_ipc: failed to connect after retries");
    }
}

void send_ipc_packet(PacketType type, uint64_t socket_id, const char* data, uint32_t len) {
    if (!g_connected) {
        g_ipc_packets_dropped++;
        return;
    }

    std::lock_guard<std::mutex> lock(g_pipe_mutex);

    if (g_pipe == INVALID_HANDLE_VALUE) {
        g_ipc_packets_dropped++;
        return;
    }
    
    PacketHeader header;
    header.magic = IPC_MAGIC;
    header.type = type;
    header.socket_id = socket_id;
    header.length = len;

    DWORD written = 0;
    OVERLAPPED ov = {0};
    ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) {
        g_ipc_packets_dropped++;
        return;
    }
    bool header_ok = false;
    
    if (WriteFile(g_pipe, &header, sizeof(header), &written, &ov)) {
        header_ok = true;
    } else if (GetLastError() == ERROR_IO_PENDING) {
        // Use a timeout to prevent blocking the application thread
        if (WaitForSingleObject(ov.hEvent, 50) == WAIT_OBJECT_0) {
            header_ok = GetOverlappedResult(g_pipe, &ov, &written, FALSE) == TRUE;
        } else {
            g_ipc_write_timeouts++;
            CancelIo(g_pipe);
        }
    }
    CloseHandle(ov.hEvent);

    if (!header_ok) {
        g_ipc_packets_dropped++;
        return;
    }

    g_ipc_packets_sent++;
    g_ipc_bytes_sent += sizeof(PacketHeader);

    if (len > 0 && data) {
        OVERLAPPED ovBody = {0};
        ovBody.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ovBody.hEvent) {
            g_ipc_packets_dropped++;
            return;
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
        }else {
            g_ipc_packets_dropped++;
        }
    }
}

int WSAAPI DetourConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    // Notify daemon about connection attempt
    if (name->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)name;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);
        
        std::string info = std::string(ip) + ":" + std::to_string(ntohs(sin->sin_port));
        send_ipc_packet(PacketType::Connect, (uint64_t)s, info.c_str(), (uint32_t)info.length());
    }

    return fpConnect(s, name, namelen);
}

int WSAAPI DetourSend(SOCKET s, const char* buf, int len, int flags) {
    int ret = fpSend(s, buf, len, flags);
    if (ret > 0) {
        send_ipc_packet(PacketType::DataSend, (uint64_t)s, buf, ret);
    }
    return ret;
}

int WSAAPI DetourRecv(SOCKET s, char* buf, int len, int flags) {
    {
        std::lock_guard<std::mutex> lock(g_inject_mutex);
        auto it = g_inject_queues.find((uint64_t)s);
        if (it != g_inject_queues.end() && !it->second.empty()) {
            int copied = 0;
            while (!it->second.empty() && copied < len) {
                buf[copied++] = it->second.front();
                it->second.pop_front();
            }
            return copied;
        }
    }

    int ret = fpRecv(s, buf, len, flags);
    if (ret > 0) {
        send_ipc_packet(PacketType::DataRecv, (uint64_t)s, buf, ret);
    }
    return ret;
}

int WSAAPI DetourCloseSocket(SOCKET s) {
    {
        std::lock_guard<std::mutex> lock(g_inject_mutex);
        g_inject_queues.erase(static_cast<uint64_t>(s));
    }
    send_ipc_packet(PacketType::Disconnect, static_cast<uint64_t>(s), nullptr, 0);
    if (fpCloseSocket) {
        return fpCloseSocket(s);
    }
    return SOCKET_ERROR;
}

void InitializeHooks() {
    debug_log("InitializeHooks: starting");
    
    if (g_shutting_down) return;
    
    connect_ipc();

    std::lock_guard<std::mutex> lock(g_init_mutex);
    if (g_shutting_down) {
        debug_log("InitializeHooks: shutting down, aborting hook install");
        return;
    }

    if (MH_Initialize() != MH_OK) {
        debug_log("MH_Initialize failed");
        return;
    }
    debug_log("MH_Initialize success");

    MH_CreateHookApi(L"Ws2_32.dll", "connect", (LPVOID)DetourConnect, (LPVOID*)&fpConnect);
    MH_CreateHookApi(L"Ws2_32.dll", "send", (LPVOID)DetourSend, (LPVOID*)&fpSend);
    MH_CreateHookApi(L"Ws2_32.dll", "recv", (LPVOID)DetourRecv, (LPVOID*)&fpRecv);
    MH_CreateHookApi(L"Ws2_32.dll", "closesocket", (LPVOID)DetourCloseSocket, (LPVOID*)&fpCloseSocket);

    if (g_shutting_down) {
        MH_Uninitialize();
        return;
    }

    MH_EnableHook(MH_ALL_HOOKS);
    debug_log("MH_EnableHook success");
}

void UninitializeHooks() {
    debug_log("UninitializeHooks: starting");
    bool expected = false;
    if (!g_hooks_cleaned_up.compare_exchange_strong(expected, true)) {
        debug_log("UninitializeHooks: already cleaned up");
        return;
    }

    g_shutting_down = true;
    g_connected = false;
    
    if (g_pipe != INVALID_HANDLE_VALUE) {
        debug_log("UninitializeHooks: closing pipe");
        // Try to cancel I/O first (best effort)
        CancelIoEx(g_pipe, NULL);
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }

    if (g_hReadThread) {
        debug_log("UninitializeHooks: closing read thread handle");
        CloseHandle(g_hReadThread);
        g_hReadThread = NULL;
    }
    debug_log("UninitializeHooks: read thread signaled (not joined)");

    std::lock_guard<std::mutex> lock(g_init_mutex);
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    debug_log("UninitializeHooks: hooks disabled");
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
        debug_log("DLL_PROCESS_ATTACH: creating init thread");
        // Use CreateThread instead of std::thread to avoid C++ runtime initialization issues in DllMain
        {
            HANDLE hThread = CreateThread(NULL, 0, InitThreadProc, NULL, 0, NULL);
            if (hThread) {
                CloseHandle(hThread);
            } else {
                debug_log("Failed to create init thread");
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        debug_log("DLL_PROCESS_DETACH");
        if (lpReserved != NULL) {
            // Process termination. Do not perform cleanup that might deadlock or crash.
            debug_log("Process termination, skipping cleanup");
            break; 
        }
        UninitializeHooks();
        break;
    }
    return TRUE;
}
