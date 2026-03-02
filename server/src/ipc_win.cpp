#include "server/include/clink/core/ipc.hpp"
#include "server/include/clink/core/logging/logger.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>
#include <sddl.h>

namespace {
constexpr char kShutdownCommand[] = "__clink_shutdown__";
constexpr auto kHandlerTimeout = std::chrono::seconds(5);

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
}

namespace clink::core::ipc {

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
        if (descriptor) LocalFree(descriptor);
    }

    SECURITY_ATTRIBUTES* get() {
        return attributes.lpSecurityDescriptor ? &attributes : nullptr;
    }
};

class WindowsIpcServer : public IpcServer {
public:
    explicit WindowsIpcServer(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}
    ~WindowsIpcServer() override { stop(); }

    void start(const std::string& address) override {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;

        address_ = address;
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, waddr.data(), len);
            waddress_ = std::wstring(waddr.data());
        }

        if (waddress_.empty()) {
            running_.store(false);
            if (logger_) logger_->error("[ipc] invalid pipe address");
            return;
        }

        server_thread_ = std::thread(&WindowsIpcServer::run_server, this);
    }

    void stop() override {
        if (!running_.exchange(false)) return;
        signal_shutdown();
        if (server_thread_.joinable()) server_thread_.join();

        HANDLE handle = hPipe_.exchange(INVALID_HANDLE_VALUE);
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }

    void set_handler(std::function<Message(const Message&)> handler) override { handler_ = std::move(handler); }

private:
    void run_server() {
        while (running_) {
            PipeSecurityAttributes sa;
            HANDLE hPipe = CreateNamedPipeW(
                waddress_.c_str(), PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, sa.get());

            if (hPipe == INVALID_HANDLE_VALUE) {
                if (logger_) logger_->error("[ipc] failed to create pipe");
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            hPipe_ = hPipe;
            if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                if (running_) process_client(hPipe);
            }

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
    }

    void process_client(HANDLE hPipe) {
        char buffer[4096];
        DWORD bytesRead = 0;
        if (!ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) return;

        std::string raw(buffer, buffer + bytesRead);
        auto sep = raw.find('|');
        Message req{MessageType::Request, sep == std::string::npos ? raw : raw.substr(0, sep),
                    sep == std::string::npos ? "" : raw.substr(sep + 1)};

        if (req.command == kShutdownCommand) return;

        const auto request_id = next_request_id_.fetch_add(1) + 1;
        if (logger_) logger_->info("[ipc.req.start] id=" + std::to_string(request_id) + " command=" + req.command +
                                   " payload_bytes=" + std::to_string(req.payload.size()));

        Message resp;
        if (!handler_) {
            resp = Message{MessageType::Response, req.command, "{\"ok\":false,\"error\":\"no handler\"}"};
            if (logger_) logger_->warn("[ipc.handler.exit] id=" + std::to_string(request_id) + " status=error reason=no_handler");
        } else {
            if (logger_) logger_->info("[ipc.handler.enter] id=" + std::to_string(request_id));
            try {
                auto fut = std::async(std::launch::async, [this, req]() {
                    return handler_(req);
                });

                if (fut.wait_for(kHandlerTimeout) == std::future_status::timeout) {
                    if (logger_) logger_->error("[ipc.req.timeout] id=" + std::to_string(request_id) +
                                                " command=" + req.command +
                                                " timeout_ms=" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(kHandlerTimeout).count()));
                    resp = Message{MessageType::Response,
                                   req.command,
                                   std::string("{\"ok\":false,\"command\":\"") + json_escape(req.command) +
                                       "\",\"error\":\"ipc handler timeout\"}"};
                    if (logger_) logger_->warn("[ipc.handler.exit] id=" + std::to_string(request_id) + " status=error reason=timeout");
                } else {
                    resp = fut.get();
                    if (logger_) logger_->info("[ipc.handler.exit] id=" + std::to_string(request_id) + " status=ok");
                }
            } catch (const std::exception& ex) {
                resp = {MessageType::Response, req.command,
                        std::string("{\"ok\":false,\"command\":\"") + json_escape(req.command) +
                            "\",\"error\":\"" + json_escape(ex.what()) + "\"}"};
                if (logger_) logger_->error("[ipc.handler.exit] id=" + std::to_string(request_id) +
                                            " status=error exception=" + std::string(ex.what()));
            }
        }

        std::string out = resp.command + "|" + resp.payload;
        DWORD bytesWritten = 0;
        if (WriteFile(hPipe, out.data(), static_cast<DWORD>(out.size()), &bytesWritten, NULL)) {
            if (logger_) {
                logger_->info("[ipc.resp.write.ok] id=" + std::to_string(request_id) +
                              " command=" + req.command +
                              " payload_bytes=" + std::to_string(resp.payload.size()));
                logger_->info("[ipc.req.end] id=" + std::to_string(request_id) + " command=" + req.command);
            }
            FlushFileBuffers(hPipe);
        } else if (logger_) {
            logger_->error("[ipc.resp.write.failed] id=" + std::to_string(request_id) +
                           " command=" + req.command +
                           " error=" + std::to_string(GetLastError()));
        }
    }

    void signal_shutdown() {
        if (waddress_.empty()) return;
        HANDLE hClient = CreateFileW(waddress_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hClient != INVALID_HANDLE_VALUE) {
            std::string shutdown_frame = std::string(kShutdownCommand) + "|";
            DWORD written = 0;
            WriteFile(hClient, shutdown_frame.c_str(), static_cast<DWORD>(shutdown_frame.size()), &written, NULL);
            CloseHandle(hClient);
        }
    }

    std::shared_ptr<logging::Logger> logger_;
    std::string address_;
    std::wstring waddress_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> next_request_id_{0};
    std::thread server_thread_;
    std::function<Message(const Message&)> handler_;
    std::atomic<HANDLE> hPipe_{INVALID_HANDLE_VALUE};
};

class WindowsIpcClient : public IpcClient {
public:
    explicit WindowsIpcClient(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}

    void connect(const std::string& address) override {
        address_ = address;
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, waddr.data(), len);
            waddress_ = std::wstring(waddr.data());
        }
    }

    void disconnect() override {}

    Message send_request(const Message& request) override {
        auto err = [&](const std::string& msg) {
            return Message{MessageType::Response, request.command,
                           std::string("{\"ok\":false,\"command\":\"") + json_escape(request.command) +
                               "\",\"error\":\"" + json_escape(msg) + "\"}"};
        };

        HANDLE hPipe = CreateFileW(waddress_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe == INVALID_HANDLE_VALUE) return err("failed to open pipe");

        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(hPipe, &mode, NULL, NULL)) {
            CloseHandle(hPipe);
            return err("failed to set pipe mode");
        }

        std::string out = request.command + "|" + request.payload;
        DWORD written = 0;
        if (!WriteFile(hPipe, out.data(), static_cast<DWORD>(out.size()), &written, NULL)) {
            CloseHandle(hPipe);
            return err("failed to write request");
        }

        char buf[4096];
        DWORD read = 0;
        if (!ReadFile(hPipe, buf, sizeof(buf), &read, NULL)) {
            CloseHandle(hPipe);
            return err("failed to read response");
        }

        CloseHandle(hPipe);
        std::string raw(buf, buf + read);
        auto sep = raw.find('|');
        return {MessageType::Response, request.command, sep == std::string::npos ? raw : raw.substr(sep + 1)};
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
