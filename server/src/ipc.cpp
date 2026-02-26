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
                    process_client();
                }
            }

            // Disconnect and close
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
    }

    void process_client() {
        char buffer[4096];
        DWORD bytesRead;
        // Use the current handle stored in hPipe_
        HANDLE hCurrentPipe = hPipe_.load();
        if (hCurrentPipe == INVALID_HANDLE_VALUE) return;

        std::string raw;
        bool success = false;
        
        do {
            if (ReadFile(hCurrentPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                raw.append(buffer, bytesRead);
                success = true;
                break;
            } else {
                if (GetLastError() == ERROR_MORE_DATA) {
                    raw.append(buffer, bytesRead);
                } else {
                    return; // Error
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

            // Enhanced debugging to see received commands
            // std::cout << "[ipc] server received: " << req.command << std::endl;

            if (req.command == kShutdownCommand) {
                return;
            }

            Message resp;
            if (handler_) {
                try {
                    resp = handler_(req);
                } catch (const std::exception& ex) {
                    if (logger_) logger_->error(std::string("[ipc] handler threw exception: ") + ex.what());
                    resp = Message{MessageType::Response, req.command, std::string("{\"error\": \"") + ex.what() + "\"}"};
                } catch (...) {
                    if (logger_) logger_->error("[ipc] handler threw unknown exception");
                    resp = Message{MessageType::Response, req.command, "{\"error\": \"handler unknown error\"}"};
                }
            } else {
                if (logger_) logger_->error(std::string("[ipc] no handler set for request: ") + req.command);
                resp = Message{MessageType::Response, req.command, "{\"error\": \"no handler\"}"};
            }

            std::string out = resp.command + "|" + resp.payload;
            DWORD bytesWritten;
            if (WriteFile(hCurrentPipe, out.c_str(), static_cast<DWORD>(out.length()), &bytesWritten, NULL)) {
                FlushFileBuffers(hCurrentPipe);
            } else {
                DWORD err = GetLastError();
                if (logger_) logger_->error(std::string("[ipc] failed to write response to client (error ") + std::to_string(err) + ")");
            }
        }
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
                static CancelSyncIoFn cancel_fn = reinterpret_cast<CancelSyncIoFn>(
                    GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CancelSynchronousIo"));
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
            std::string errMsg = "failed to open pipe " + address_ + " (error " + std::to_string(lastErr) + ")";
            if (lastErr == 2) errMsg += " - service might not be running";
            logger_->error(errMsg);
            return {MessageType::Response, request.command, "{\"error\": \"" + errMsg + "\"}"};
        }

        // Set pipe to message mode
        DWORD dwMode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
            DWORD err = GetLastError();
            if (logger_) logger_->error(std::string("[ipc] failed to set pipe mode (error ") + std::to_string(err) + ")");
            CloseHandle(hPipe);
            return {MessageType::Response, request.command, "{\"error\": \"failed to set pipe mode\"}"};
        }

        std::string out = request.command + "|" + request.payload;
        DWORD bytesWritten;
        if (!WriteFile(hPipe, out.c_str(), static_cast<DWORD>(out.length()), &bytesWritten, NULL)) {
            DWORD err = GetLastError();
            if (logger_) logger_->error(std::string("[ipc] failed to write to pipe (error ") + std::to_string(err) + ")");
            CloseHandle(hPipe);
            return {MessageType::Response, request.command, "{\"error\": \"failed to write to pipe\"}"};
        }

        std::string raw;
        char buffer[4096];
        DWORD bytesRead;
        Message resp{MessageType::Response, request.command, ""};
        
        // Read loop for message mode
        bool success = false;
        do {
            if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                raw.append(buffer, bytesRead);
                success = true;
                break; // Finished reading
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_MORE_DATA) {
                    raw.append(buffer, bytesRead);
                    // Continue reading
                } else {
                        if (logger_) logger_->error(std::string("[ipc] failed to read from pipe (error ") + std::to_string(err) + ")");
                        resp.payload = "{\"error\": \"failed to read from pipe (error " + std::to_string(err) + ")\"}";
                        CloseHandle(hPipe);
                        return resp;
                }
            }
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
