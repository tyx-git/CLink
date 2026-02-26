#pragma once

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <atomic>
#include <memory>
#include <vector>
#include <mutex>
#include <string>
#include <map>
#include <thread>

namespace clink::hook {

class HookManager {
public:
    static HookManager& instance();

    bool initialize();
    void shutdown();

    // Hook functions
    static int WSAAPI hooked_send(SOCKET s, const char* buf, int len, int flags);
    static int WSAAPI hooked_recv(SOCKET s, char* buf, int len, int flags);
    static int WSAAPI hooked_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
    static int WSAAPI hooked_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecv, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
    static int WSAAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen);
    static int WSAAPI hooked_WSAConnect(SOCKET s, const struct sockaddr* name, int namelen, LPWSABUF lpCallerData, LPWSABUF lpCalleeData, LPQOS lpSQOS, LPQOS lpGQOS);

private:
    HookManager() = default;
    ~HookManager() = default;

    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    void connect_ipc();
    void read_loop();
    void send_ipc_message(uint8_t type, uint64_t socket_id, const void* data, size_t size);
    
    // Helper to format error message
    void log_error(const std::string& msg);

    std::atomic<bool> initialized_{false};
    std::atomic<bool> ipc_connected_{false};
    HANDLE pipe_handle_{INVALID_HANDLE_VALUE};
    std::mutex pipe_mutex_;
    
    // Injection buffers
    std::mutex injection_mutex_;
    std::map<SOCKET, std::vector<char>> injection_buffers_;
    
    // Read thread
    std::thread read_thread_;
    std::atomic<bool> stop_read_thread_{false};

    // Original function pointers
    typedef int (WSAAPI *SendFn)(SOCKET, const char*, int, int);
    typedef int (WSAAPI *RecvFn)(SOCKET, char*, int, int);
    typedef int (WSAAPI *WSASendFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    typedef int (WSAAPI *WSARecvFn)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    typedef int (WSAAPI *ConnectFn)(SOCKET, const struct sockaddr*, int);
    typedef int (WSAAPI *WSAConnectFn)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);

    static SendFn original_send;
    static RecvFn original_recv;
    static WSASendFn original_WSASend;
    static WSARecvFn original_WSARecv;
    static ConnectFn original_connect;
    static WSAConnectFn original_WSAConnect;
};

} // namespace clink::hook
