#include "src/client/core/ipc/ipc.hpp"
#include "src/share/core/ipc/ipc_message_utils.hpp"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <windows.h>

namespace {
namespace control_plane = clink::protocol::control_plane;

constexpr char kShutdownCommand[] = "__clink_shutdown__";
constexpr DWORD kMaxIpcMessageSize = 1024 * 1024;

bool write_exact(HANDLE handle, const void* data, DWORD size) {
    const char* cursor = static_cast<const char*>(data);
    DWORD remaining = size;
    while (remaining > 0) {
        DWORD written = 0;
        if (!WriteFile(handle, cursor, remaining, &written, NULL)) {
            return false;
        }
        if (written == 0) {
            SetLastError(ERROR_WRITE_FAULT);
            return false;
        }
        cursor += written;
        remaining -= written;
    }
    return true;
}

bool read_exact(HANDLE handle, void* data, DWORD size) {
    char* cursor = static_cast<char*>(data);
    DWORD remaining = size;
    while (remaining > 0) {
        DWORD read = 0;
        if (!ReadFile(handle, cursor, remaining, &read, NULL)) {
            return false;
        }
        if (read == 0) {
            SetLastError(ERROR_BROKEN_PIPE);
            return false;
        }
        cursor += read;
        remaining -= read;
    }
    return true;
}

bool write_frame(HANDLE handle, const std::string& payload) {
    if (payload.empty() || payload.size() > kMaxIpcMessageSize) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    const DWORD length = static_cast<DWORD>(payload.size());
    return write_exact(handle, &length, sizeof(length)) && write_exact(handle, payload.data(), length);
}

bool read_frame(HANDLE handle, std::string& payload) {
    DWORD length = 0;
    if (!read_exact(handle, &length, sizeof(length))) {
        return false;
    }
    if (length == 0 || length > kMaxIpcMessageSize) {
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    payload.resize(length);
    return read_exact(handle, payload.data(), length);
}
}  // namespace

namespace clink::core::ipc {

class WindowsIpcServer : public IpcServer {
public:
    ~WindowsIpcServer() override {
        stop();
    }

    void start(const std::string& address) override {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) {
            return;
        }

        address_ = address;
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(static_cast<size_t>(len));
            MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, waddr.data(), len);
            waddress_ = std::wstring(waddr.data());
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
            HANDLE hPipe = CreateNamedPipeW(
                waddress_.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                NULL);

            if (hPipe == INVALID_HANDLE_VALUE) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            hPipe_ = hPipe;

            if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
                if (running_) {
                    process_client(hPipe);
                }
            }

            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
    }

    void process_client(HANDLE hCurrentPipe) {
        if (hCurrentPipe == INVALID_HANDLE_VALUE) {
            return;
        }

        std::string raw;
        if (!read_frame(hCurrentPipe, raw)) {
            return;
        }

        Message req = detail::parse_wire_request(raw);

        if (req.command == kShutdownCommand) {
            return;
        }

        Message resp;
        if (handler_) {
            try {
                resp = handler_(req);
            } catch (const std::exception& ex) {
                resp = detail::make_error_response(req,
                                                   "handler exception: " + std::string(ex.what()),
                                                   control_plane::kReasonHandlerException);
            } catch (...) {
                resp = detail::make_error_response(req,
                                                   "handler unknown error",
                                                   control_plane::kReasonHandlerException);
            }
        } else {
            resp = detail::make_error_response(req, "no handler", control_plane::kReasonNoHandler);
        }

        std::string out = detail::build_wire_message(resp.command, resp.payload);
        if (!write_frame(hCurrentPipe, out)) {
            return;
        }

        FlushFileBuffers(hCurrentPipe);
    }

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
                0,
                NULL,
                OPEN_EXISTING,
                0,
                NULL);

            if (hClient != INVALID_HANDLE_VALUE) {
                std::string shutdown_frame = std::string(kShutdownCommand) + "|";
                write_frame(hClient, shutdown_frame);
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

    std::string address_;
    std::wstring waddress_;
    std::atomic<bool> running_{false};
    std::thread server_thread_;
    std::function<Message(const Message&)> handler_;
    std::atomic<HANDLE> hPipe_{INVALID_HANDLE_VALUE};
};

class WindowsIpcClient : public IpcClient {
public:
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
        auto make_error_payload = [&](const std::string& msg, const std::string& reason = std::string{}) {
            return detail::build_error_payload(request.command, msg, reason);
        };

        auto should_retry_once = [&](const std::string& cmd) {
            return cmd == "status" || cmd == "logs";
        };

        auto send_once = [&](bool allow_retry_hint) -> Message {
            HANDLE hPipe = INVALID_HANDLE_VALUE;
            int retries = 5;

            while (retries > 0) {
                hPipe = CreateFileW(
                    waddress_.c_str(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL);

                if (hPipe != INVALID_HANDLE_VALUE) {
                    break;
                }

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
                std::string reason = control_plane::kReasonPipeOpenFailed;
                if (lastErr == ERROR_FILE_NOT_FOUND || lastErr == ERROR_PATH_NOT_FOUND) {
                    reason = control_plane::kReasonServiceNotRunning;
                    errMsg += " - service might not be running";
                }
                return detail::make_error_response(request, errMsg, reason);
            }

            DWORD dwMode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
                CloseHandle(hPipe);
                return detail::make_error_response(request,
                                                   "command=" + request.command + " failed to set pipe mode",
                                                   control_plane::kReasonPipeSetModeFailed);
            }

            std::string out = detail::build_wire_message(request.command, request.payload);
            if (!write_frame(hPipe, out)) {
                const DWORD err = GetLastError();
                CloseHandle(hPipe);
                return detail::make_error_response(request,
                                                   "command=" + request.command + " failed to write to pipe (error " +
                                                       std::to_string(err) + ")",
                                                   control_plane::kReasonPipeWriteFailed);
            }

            std::string raw;
            Message resp{MessageType::Response, request.command, ""};

            if (!read_frame(hPipe, raw)) {
                const DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE) {
                    std::string msg = "daemon closed pipe before response (command=" + request.command + ", error=109)";
                    if (request.command == "connect") {
                        msg += " - check daemon logs last 50 lines";
                    } else if (allow_retry_hint) {
                        msg += " - retrying once";
                    }
                    resp.payload = make_error_payload(msg, control_plane::kReasonPipeReadFailed);
                } else {
                    resp.payload = make_error_payload("command=" + request.command + " failed to read from pipe (error " +
                                                     std::to_string(err) + ")",
                                                     control_plane::kReasonPipeReadFailed);
                }

                CloseHandle(hPipe);
                return resp;
            }

            resp.payload = detail::extract_wire_payload(raw);

            CloseHandle(hPipe);
            return resp;
        };

        auto first = send_once(should_retry_once(request.command));
        if (!should_retry_once(request.command)) {
            return first;
        }

        if (first.payload.find("error=109") == std::string::npos) {
            return first;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        auto second = send_once(false);
        if (second.payload.find("\"ok\":false") != std::string::npos && second.payload.find("error=109") != std::string::npos) {
            return first;
        }
        return second;
    }

private:
    std::string address_;
    std::wstring waddress_;
};

std::unique_ptr<IpcServer> create_server(std::shared_ptr<logging::Logger> /*logger*/) {
    return std::make_unique<WindowsIpcServer>();
}

std::unique_ptr<IpcServer> create_server() {
    return create_server(nullptr);
}

std::unique_ptr<IpcClient> create_client(std::shared_ptr<logging::Logger> /*logger*/) {
    return std::make_unique<WindowsIpcClient>();
}

}  // namespace clink::core::ipc
