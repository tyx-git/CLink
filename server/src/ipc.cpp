#include "server/include/clink/core/ipc.hpp"
#include "server/include/clink/core/logging/logger.hpp"

#include <iostream>
#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>
#include <sddl.h>
#include <chrono>

namespace {
    constexpr char kShutdownCommand[] = "__clink_shutdown__";

std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

struct PipeSecurityAttributes {
    SECURITY_ATTRIBUTES attributes{};
    PSECURITY_DESCRIPTOR descriptor{nullptr};

    PipeSecurityAttributes() {
        attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        attributes.bInheritHandle = FALSE;
        attributes.lpSecurityDescriptor = nullptr;
        const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
            attributes.lpSecurityDescriptor = descriptor;
        }
    }

    ~PipeSecurityAttributes() {
        if (descriptor) {
            LocalFree(descriptor);
        }
    }

    SECURITY_ATTRIBUTES* get() {
        return attributes.lpSecurityDescriptor ? &attributes : nullptr;
    }
};
} // anonymous namespace

namespace clink::core::ipc {

    class WindowsIpcServer : public IpcServer {
public:
    WindowsIpcServer(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}
    ~WindowsIpcServer() {
        stop();
    }

    void start(const std::string& address) override {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) {
            return;
        }
        
        address_ = address;
        // Convert address to wstring for Windows API
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, waddr.data(), len);
            waddress_ = std::wstring(waddr.data());
        }

        if (waddress_.empty()) {
            if (logger_) logger_->error(std::string("[ipc] failed to convert address to wide string: ") + address_);
            // Revert running state and return
            running_.store(false);
            return;
        }

        server_thread_ = std::thread(&WindowsIpcServer::run_server, this);
    }
    
    void stop() override {
        if (!running_.exchange(false)) {
            return;
        }

        signal_shutdown();

        if (server_thread_.joinable()) {
            server_thread_.join();
        }

        HANDLE handle = hPipe_.exchange(INVALID_HANDLE_VALUE);
        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
    
    void set_handler(std::function<Message(const Message&)> handler) override {
        handler_ = std::move(handler);
    }

private:
    void run_server() {
        while (running_) {
            // Re-create pipe for each connection or if it doesn't exist
            PipeSecurityAttributes sa;
            HANDLE hPipe = CreateNamedPipeW(
                waddress_.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096, 0, sa.get());

            if (hPipe == INVALID_HANDLE_VALUE) {
                if (logger_) {
                    logger_->error(std::string("[ipc] failed to create pipe: ") + std::to_string(GetLastError()));
                } else {
                    std::cerr << "[ipc] failed to create pipe: " << GetLastError() << std::endl;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            hPipe_ = hPipe;

            // Wait for client to connect
            if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                if (running_) {
                    std::thread([this, hPipe]() {
                        process_client(hPipe);
                    }).detach();
                    continue;
                }
            }

            // Disconnect and close (only for failed/aborted accept path)
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
    }

    void process_client(HANDLE hCurrentPipe) {
        static std::atomic<uint64_t> req_counter{0};

        char buffer[4096];
        DWORD bytesRead;
        if (hCurrentPipe == INVALID_HANDLE_VALUE) return;

        std::string raw;
        bool success = false;

        do {
            if (ReadFile(hCurrentPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                raw.append(buffer, bytesRead);
                success = true;
                break;
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_MORE_DATA) {
                    raw.append(buffer, bytesRead);
                } else {
                    if (logger_) logger_->error(std::string("[ipc] read request failed (error ") + std::to_string(err) + ")");
                    DisconnectNamedPipe(hCurrentPipe);
                    CloseHandle(hCurrentPipe);
                    return;
                }
            }
        } while (true);

        if (success) {
            // Basic protocol: COMMAND|PAYLOAD
            auto sep = raw.find('|');
            Message req{MessageType::Request, "", ""};
            if (sep != std::string::npos) {
                req.command = raw.substr(0, sep);
                req.payload = raw.substr(sep + 1);
            } else {
                req.command = raw;
            }

            const uint64_t req_id = ++req_counter;
            if (logger_) {
                logger_->info("[ipc.req.start] id=" + std::to_string(req_id) +
                              " command=" + req.command +
                              " payload_bytes=" + std::to_string(req.payload.size()));
            }

            if (req.command == kShutdownCommand) {
                if (logger_) logger_->info("[ipc.req.end] id=" + std::to_string(req_id) + " command=shutdown");
                DisconnectNamedPipe(hCurrentPipe);
                CloseHandle(hCurrentPipe);
                return;
            }

            Message resp;
            if (handler_) {
                try {
                    resp = handler_(req);
                } catch (const std::exception& ex) {
                    if (logger_) logger_->error(std::string("[ipc] handler threw exception: ") + ex.what());
                    resp = Message{MessageType::Response, req.command, std::string("{\"ok\":false,\"command\":\"") + req.command + "\",\"error\":\"handler exception: " + ex.what() + "\"}"};
                } catch (...) {
                    if (logger_) logger_->error("[ipc] handler threw unknown exception");
                    resp = Message{MessageType::Response, req.command, std::string("{\"ok\":false,\"command\":\"") + req.command + "\",\"error\":\"handler unknown error\"}"};
                }
            } else {
                if (logger_) logger_->error(std::string("[ipc] no handler set for request: ") + req.command);
                resp = Message{MessageType::Response, req.command, std::string("{\"ok\":false,\"command\":\"") + req.command + "\",\"error\":\"no handler\"}"};
            }

            std::string out = resp.command + "|" + resp.payload;
            const char* data = out.data();
            size_t remaining = out.size();
            DWORD bytesWritten = 0;
            bool write_ok = true;

            while (remaining > 0) {
                if (WriteFile(hCurrentPipe, data, static_cast<DWORD>(remaining), &bytesWritten, NULL)) {
                    if (bytesWritten == 0) {
                        write_ok = false;
                        if (logger_) logger_->error("[ipc] write returned success with zero bytes, aborting response write");
                        break;
                    }
                    data += bytesWritten;
                    remaining -= bytesWritten;
                    continue;
                }

                DWORD err = GetLastError();
                if (err == ERROR_OPERATION_ABORTED) {
                    continue;
                }

                write_ok = false;
                if (logger_) {
                    logger_->error(std::string("[ipc.resp.write.fail] id=") + std::to_string(req_id) +
                                  " command=" + req.command +
                                  " payload_bytes=" + std::to_string(resp.payload.size()) +
                                  " error=" + std::to_string(err));
                }
                break;
            }

            if (write_ok) {
                if (!FlushFileBuffers(hCurrentPipe)) {
                    DWORD err = GetLastError();
                    if (logger_) {
                        logger_->error(std::string("[ipc.resp.flush.fail] id=") + std::to_string(req_id) +
                                      " command=" + req.command +
                                      " error=" + std::to_string(err));
                    }
                } else if (logger_) {
                    logger_->info(std::string("[ipc.resp.write.ok] id=") + std::to_string(req_id) +
                                  " command=" + req.command +
                                  " payload_bytes=" + std::to_string(resp.payload.size()));
                }
            }

            if (logger_) {
                logger_->info(std::string("[ipc.req.end] id=") + std::to_string(req_id) + " command=" + req.command);
            }
        }

        DisconnectNamedPipe(hCurrentPipe);
        CloseHandle(hCurrentPipe);
    }

    std::shared_ptr<logging::Logger> logger_;
    std::string address_;
    std::wstring waddress_;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
    std::function<Message(const Message&)> handler_;
    std::atomic<HANDLE> hPipe_{INVALID_HANDLE_VALUE};

    void signal_shutdown() {
        if (server_thread_.joinable()) {
            HANDLE thread_handle = reinterpret_cast<HANDLE>(server_thread_.native_handle());
            if (thread_handle) {
                using CancelSyncIoFn = BOOL(WINAPI*)(HANDLE);
                static CancelSyncIoFn cancel_fn = nullptr;
                if (!cancel_fn) {
                    HMODULE hMod = GetModuleHandleW(L"kernel32.dll");
                    if (hMod) {
                        FARPROC proc = GetProcAddress(hMod, "CancelSynchronousIo");
                        if (proc) {
                            cancel_fn = reinterpret_cast<CancelSyncIoFn>(reinterpret_cast<void*>(proc));
                        }
                    }
                }
                if (cancel_fn) {
                    cancel_fn(thread_handle);
                }
            }
        }

        if (waddress_.empty()) {
            return;
        }

        for (int attempt = 0; attempt < 5; ++attempt) {
            HANDLE hClient = CreateFileW(
                waddress_.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);

            if (hClient != INVALID_HANDLE_VALUE) {
                std::string shutdown_frame = std::string(kShutdownCommand) + "|";
                DWORD written = 0;
                if (!WriteFile(hClient, shutdown_frame.c_str(), static_cast<DWORD>(shutdown_frame.size()), &written, NULL)) {
                    DWORD err = GetLastError();
                    if (logger_) logger_->error(std::string("[ipc] failed to send shutdown frame (error ") + std::to_string(err) + ")");
                }
                CloseHandle(hClient);
                break;
            }

            DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            } else if (err == ERROR_PIPE_BUSY) {
                WaitNamedPipeW(waddress_.c_str(), 50);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
};

class WindowsIpcClient : public IpcClient {
public:
    WindowsIpcClient(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}
    void connect(const std::string& address) override {
        address_ = address;
        // Convert address to wstring for Windows API
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, waddr.data(), len);
            waddress_ = std::wstring(waddr.data());
        }
    }
    
    void disconnect() override {
    }
    
    Message send_request(const Message& request) override {
        auto make_error_payload = [&](const std::string& msg) {
            return std::string("{\"ok\":false,\"command\":\"") + json_escape(request.command) + "\",\"error\":\"" + json_escape(msg) + "\"}";
        };

        HANDLE hPipe = INVALID_HANDLE_VALUE;
        int retries = 5;

        while (retries > 0) {
            hPipe = CreateFileW(
                waddress_.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);

            if (hPipe != INVALID_HANDLE_VALUE) break;

            DWORD err = GetLastError();
            if (err == ERROR_PIPE_BUSY) {
                if (!WaitNamedPipeW(waddress_.c_str(), 100)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            retries--;
        }

        if (hPipe == INVALID_HANDLE_VALUE) {
            DWORD lastErr = GetLastError();
            std::string errMsg = "command=" + request.command + " failed to open pipe " + address_ +
                                 " (error " + std::to_string(lastErr) + ")";
            if (lastErr == 2) errMsg += " - service might not be running";
            if (logger_) logger_->error(errMsg);
            return {MessageType::Response, request.command, make_error_payload(errMsg)};
        }

        DWORD dwMode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
            DWORD err = GetLastError();
            if (logger_) logger_->error(std::string("[ipc] failed to set pipe mode (error ") + std::to_string(err) + ")");
            CloseHandle(hPipe);
            return {MessageType::Response, request.command, make_error_payload("failed to set pipe mode")};
        }

        std::string out = request.command + "|" + request.payload;
        const char* write_ptr = out.data();
        size_t remaining = out.size();
        DWORD bytesWritten = 0;

        while (remaining > 0) {
            if (!WriteFile(hPipe, write_ptr, static_cast<DWORD>(remaining), &bytesWritten, NULL)) {
                DWORD err = GetLastError();
                if (err == ERROR_OPERATION_ABORTED) {
                    continue;
                }
                if (logger_) logger_->error(std::string("[ipc] failed to write to pipe (error ") + std::to_string(err) + ")");
                CloseHandle(hPipe);
                return {MessageType::Response, request.command, make_error_payload("failed to write to pipe (error " + std::to_string(err) + ")")};
            }

            if (bytesWritten == 0) {
                CloseHandle(hPipe);
                return {MessageType::Response, request.command, make_error_payload("write returned zero bytes")};
            }

            write_ptr += bytesWritten;
            remaining -= bytesWritten;
        }

        std::string raw;
        char buffer[4096];
        DWORD bytesRead = 0;
        Message resp{MessageType::Response, request.command, ""};

        bool success = false;
        do {
            if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                raw.append(buffer, bytesRead);
                success = true;
                break;
            }

            DWORD err = GetLastError();
            if (err == ERROR_MORE_DATA) {
                raw.append(buffer, bytesRead);
                continue;
            }

            if (logger_) logger_->error(std::string("[ipc] failed to read from pipe (error ") + std::to_string(err) + ")");
            if (err == ERROR_BROKEN_PIPE) {
                resp.payload = make_error_payload("daemon closed pipe before response (error=109)");
            } else {
                resp.payload = make_error_payload("failed to read from pipe (error " + std::to_string(err) + ")");
            }
            CloseHandle(hPipe);
            return resp;
        } while (true);

        if (success) {
            auto sep = raw.find('|');
            if (sep != std::string::npos) {
                resp.payload = raw.substr(sep + 1);
            } else {
                resp.payload = raw;
            }
        }

        CloseHandle(hPipe);
        return resp;
    }

private:
    std::shared_ptr<logging::Logger> logger_;
    std::string address_;
    std::wstring waddress_;
};

std::unique_ptr<IpcServer> create_server(std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<WindowsIpcServer>(std::move(logger));
}

std::unique_ptr<IpcClient> create_client(std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<WindowsIpcClient>(std::move(logger));
}

} // namespace clink::core::ipc
