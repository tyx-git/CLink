#include "hook_manager.hpp"
#include "ipc_protocol.hpp"
#include <MinHook.h>
#include <cstdio>
#include <sstream>
#include <vector>
#include <algorithm>

namespace clink::hook {

HookManager::SendFn HookManager::original_send = nullptr;
HookManager::RecvFn HookManager::original_recv = nullptr;
HookManager::WSASendFn HookManager::original_WSASend = nullptr;
HookManager::WSARecvFn HookManager::original_WSARecv = nullptr;
HookManager::ConnectFn HookManager::original_connect = nullptr;
HookManager::WSAConnectFn HookManager::original_WSAConnect = nullptr;

HookManager& HookManager::instance() {
    static HookManager instance;
    return instance;
}

void HookManager::log_error(const std::string& msg) {
    std::string full_msg = "[CLink-Hook] " + msg + "\n";
    OutputDebugStringA(full_msg.c_str());
    fprintf(stderr, "%s", full_msg.c_str());
}

bool HookManager::initialize() {
    if (initialized_) return true;

    if (MH_Initialize() != MH_OK) {
        log_error("MinHook initialization failed");
        return false;
    }

    // Hook send
    if (MH_CreateHookApi(L"ws2_32.dll", "send", (LPVOID)&hooked_send, (LPVOID*)&original_send) != MH_OK) {
        log_error("Failed to hook send");
    }

    // Hook recv
    if (MH_CreateHookApi(L"ws2_32.dll", "recv", (LPVOID)&hooked_recv, (LPVOID*)&original_recv) != MH_OK) {
        log_error("Failed to hook recv");
    }

    // Hook WSASend
    if (MH_CreateHookApi(L"ws2_32.dll", "WSASend", (LPVOID)&hooked_WSASend, (LPVOID*)&original_WSASend) != MH_OK) {
        log_error("Failed to hook WSASend");
    }

    // Hook WSARecv
    if (MH_CreateHookApi(L"ws2_32.dll", "WSARecv", (LPVOID)&hooked_WSARecv, (LPVOID*)&original_WSARecv) != MH_OK) {
        log_error("Failed to hook WSARecv");
    }

    // Hook connect
    if (MH_CreateHookApi(L"ws2_32.dll", "connect", (LPVOID)&hooked_connect, (LPVOID*)&original_connect) != MH_OK) {
        log_error("Failed to hook connect");
    }

    // Hook WSAConnect
    if (MH_CreateHookApi(L"ws2_32.dll", "WSAConnect", (LPVOID)&hooked_WSAConnect, (LPVOID*)&original_WSAConnect) != MH_OK) {
        log_error("Failed to hook WSAConnect");
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        log_error("Failed to enable hooks");
        return false;
    }

    connect_ipc();

    initialized_ = true;
    log_error("Initialized successfully");
    return true;
}

void HookManager::shutdown() {
    if (!initialized_) return;

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();

    std::lock_guard<std::mutex> lock(pipe_mutex_);
    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe_handle_);
        pipe_handle_ = INVALID_HANDLE_VALUE;
    }
    ipc_connected_ = false;

    initialized_ = false;
}

void HookManager::connect_ipc() {
    // Try to connect to named pipe
    for (int i = 0; i < 5; ++i) {
        HANDLE hPipe = CreateFileA(
            ipc::PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hPipe != INVALID_HANDLE_VALUE) {
            {
                std::lock_guard<std::mutex> lock(pipe_mutex_);
                pipe_handle_ = hPipe;
                ipc_connected_ = true;
            }
            log_error("Connected to IPC pipe");
            
            // Send Connect packet with socket_id 0 to indicate DLL attached
            // Note: send_ipc_message acquires pipe_mutex_, so we must not hold it here
            send_ipc_message((uint8_t)ipc::PacketType::Connect, 0, nullptr, 0);
            
            // Start read loop
            stop_read_thread_ = false;
            read_thread_ = std::thread([this]() { read_loop(); });
            read_thread_.detach(); // Detach for now as we don't have clean shutdown
            
            break;
        }

        if (GetLastError() != ERROR_PIPE_BUSY) {
            // log_error("Could not open pipe: " + std::to_string(GetLastError()));
            // Don't log too much on failure to avoid spam
        } else {
            if (!WaitNamedPipeA(ipc::PIPE_NAME, 2000)) {
                // log_error("WaitNamedPipe failed");
            }
        }
        Sleep(100);
    }
}

void HookManager::read_loop() {
    while (!stop_read_thread_) {
        ipc::PacketHeader header;
        DWORD read;
        DWORD bytesAvail = 0;

        // Use PeekNamedPipe to check for data availability
        // This avoids blocking on ReadFile which would prevent WriteFile from proceeding
        // on the same synchronous handle.
        if (!PeekNamedPipe(pipe_handle_, NULL, 0, NULL, &bytesAvail, NULL)) {
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                break;
            }
            // Other error, maybe pipe closed
            log_error("PeekNamedPipe failed: " + std::to_string(GetLastError()));
            break;
        }

        if (bytesAvail < sizeof(header)) {
            // Not enough data for header, sleep and retry
            Sleep(10);
            continue;
        }
        
        // Read header
        if (!ReadFile(pipe_handle_, &header, sizeof(header), &read, NULL)) {
            if (GetLastError() != ERROR_BROKEN_PIPE) {
                log_error("ReadFile failed: " + std::to_string(GetLastError()));
            }
            break;
        }
        
        if (read == 0) continue;
        
        if (header.magic != ipc::IPC_MAGIC) {
            log_error("Invalid magic");
            break;
        }
        
        // Read body
        std::vector<char> body;
        if (header.length > 0) {
            // Wait for body data
            while (true) {
                if (!PeekNamedPipe(pipe_handle_, NULL, 0, NULL, &bytesAvail, NULL)) {
                     break;
                }
                if (bytesAvail >= header.length) break;
                Sleep(1);
            }
            
            body.resize(header.length);
            if (!ReadFile(pipe_handle_, body.data(), header.length, &read, NULL)) {
                log_error("ReadFile body failed");
                break;
            }
        }
        
        if (header.type == ipc::PacketType::DataRecv) {
            std::lock_guard<std::mutex> lock(injection_mutex_);
            auto& buffer = injection_buffers_[header.socket_id];
            buffer.insert(buffer.end(), body.begin(), body.end());
            // log_error("Injected " + std::to_string(body.size()) + " bytes for socket " + std::to_string(header.socket_id));
        }
    }
}

void HookManager::send_ipc_message(uint8_t type, uint64_t socket_id, const void* data, size_t size) {
    std::lock_guard<std::mutex> lock(pipe_mutex_);
    if (!ipc_connected_ || pipe_handle_ == INVALID_HANDLE_VALUE) {
        log_error("Pipe not connected, cannot send message");
        return;
    }

    ipc::PacketHeader header;
    header.magic = ipc::IPC_MAGIC;
    header.type = static_cast<ipc::PacketType>(type);
    header.socket_id = socket_id;
    header.length = static_cast<uint32_t>(size);

    DWORD written;
    // Write header
    if (!WriteFile(pipe_handle_, &header, sizeof(header), &written, NULL)) {
        log_error("WriteFile header failed: " + std::to_string(GetLastError()));
        CloseHandle(pipe_handle_);
        pipe_handle_ = INVALID_HANDLE_VALUE;
        ipc_connected_ = false;
        return;
    }

    // Write body if exists
    if (size > 0 && data) {
        if (!WriteFile(pipe_handle_, data, static_cast<DWORD>(size), &written, NULL)) {
             log_error("WriteFile body failed: " + std::to_string(GetLastError()));
             CloseHandle(pipe_handle_);
             pipe_handle_ = INVALID_HANDLE_VALUE;
             ipc_connected_ = false;
        }
    }
}

int WSAAPI HookManager::hooked_send(SOCKET s, const char* buf, int len, int flags) {
    int ret = original_send(s, buf, len, flags);
    if (ret > 0) {
        instance().send_ipc_message((uint8_t)ipc::PacketType::DataSend, (uint64_t)s, buf, ret);
    }
    return ret;
}

int WSAAPI HookManager::hooked_recv(SOCKET s, char* buf, int len, int flags) {
    // Check injection buffer
    {
        std::lock_guard<std::mutex> lock(instance().injection_mutex_);
        auto it = instance().injection_buffers_.find(s);
        if (it != instance().injection_buffers_.end() && !it->second.empty()) {
            auto& buffer = it->second;
            int copy_len = std::min(len, (int)buffer.size());
            
            memcpy(buf, buffer.data(), copy_len);
            
            if (!(flags & MSG_PEEK)) {
                buffer.erase(buffer.begin(), buffer.begin() + copy_len);
                if (buffer.empty()) {
                    instance().injection_buffers_.erase(it);
                }
            }
            
            // Log injection usage
            // instance().log_error("Returned " + std::to_string(copy_len) + " injected bytes");
            return copy_len;
        }
    }

    int ret = original_recv(s, buf, len, flags);
    if (ret > 0) {
        instance().send_ipc_message((uint8_t)ipc::PacketType::DataRecv, (uint64_t)s, buf, ret);
    }
    return ret;
}

int WSAAPI HookManager::hooked_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int ret = original_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    
    // Only capture if immediate success or IO_PENDING?
    // If we want to capture what was requested to be sent:
    if (ret == 0 || (ret == SOCKET_ERROR && WSAGetLastError() == WSA_IO_PENDING)) {
        for (DWORD i = 0; i < dwBufferCount; ++i) {
             instance().send_ipc_message((uint8_t)ipc::PacketType::DataSend, (uint64_t)s, lpBuffers[i].buf, lpBuffers[i].len);
        }
    }
    
    return ret;
}

int WSAAPI HookManager::hooked_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int ret = original_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    
    if (ret == 0 && lpNumberOfBytesRecvd && *lpNumberOfBytesRecvd > 0) {
        // Iterate and capture up to *lpNumberOfBytesRecvd
        DWORD total = *lpNumberOfBytesRecvd;
        for (DWORD i = 0; i < dwBufferCount && total > 0; ++i) {
            DWORD to_capture = (total > lpBuffers[i].len) ? lpBuffers[i].len : total;
            instance().send_ipc_message((uint8_t)ipc::PacketType::DataRecv, (uint64_t)s, lpBuffers[i].buf, to_capture);
            total -= to_capture;
        }
    }
    
    return ret;
}

int WSAAPI HookManager::hooked_connect(SOCKET s, const struct sockaddr* name, int namelen) {
    instance().log_error("hooked_connect called");
    int ret = original_connect(s, name, namelen);
    if (ret == 0 || (ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;
        
        if (name->sa_family == AF_INET) {
            const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(name);
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(sin->sin_port);
        } else if (name->sa_family == AF_INET6) {
            const struct sockaddr_in6* sin6 = reinterpret_cast<const struct sockaddr_in6*>(name);
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(sin6->sin6_port);
        }
        
        std::string addr_str = std::string(ip_str) + ":" + std::to_string(port);
        instance().log_error("Sending connect IPC: " + addr_str);
        instance().send_ipc_message((uint8_t)ipc::PacketType::Connect, (uint64_t)s, addr_str.c_str(), addr_str.length());
    }
    return ret;
}

int WSAAPI HookManager::hooked_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS) {
    int ret = original_WSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    if (ret == 0 || (ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK)) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        uint16_t port = 0;
        
        if (name->sa_family == AF_INET) {
            const struct sockaddr_in* sin = reinterpret_cast<const struct sockaddr_in*>(name);
            inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            port = ntohs(sin->sin_port);
        } else if (name->sa_family == AF_INET6) {
            const struct sockaddr_in6* sin6 = reinterpret_cast<const struct sockaddr_in6*>(name);
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
            port = ntohs(sin6->sin6_port);
        }
        
        std::string addr_str = std::string(ip_str) + ":" + std::to_string(port);
        instance().send_ipc_message((uint8_t)ipc::PacketType::Connect, (uint64_t)s, addr_str.c_str(), addr_str.length());
    }
    return ret;
}

} // namespace clink::hook
