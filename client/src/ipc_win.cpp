#include "client/include/clink/core/ipc.hpp"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <windows.h>

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
        char buffer[4096];
        DWORD bytesRead = 0;

        bool read_ok = false;
        do {
            if (ReadFile(hCurrentPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                raw.append(buffer, bytesRead);
                read_ok = true;
                break;
            }

            DWORD err = GetLastError();
            if (err == ERROR_MORE_DATA) {
                raw.append(buffer, bytesRead);
                continue;
            }
            return;
        } while (true);

        if (!read_ok) {
            return;
        }

        auto sep = raw.find('|');
        Message req{MessageType::Request, "", ""};
        if (sep != std::string::npos) {
            req.command = raw.substr(0, sep);
            req.payload = raw.substr(sep + 1);
        } else {
            req.command = raw;
        }

        if (req.command == kShutdownCommand) {
            return;
        }

        Message resp;
        if (handler_) {
            try {
                resp = handler_(req);
            } catch (const std::exception& ex) {
                resp = Message{MessageType::Response,
                               req.command,
                               std::string("{\"ok\":false,\"command\":\"") + req.command +
                                   "\",\"error\":\"handler exception: " + ex.what() + "\"}"};
            } catch (...) {
                resp = Message{MessageType::Response,
                               req.command,
                               std::string("{\"ok\":false,\"command\":\"") + req.command +
                                   "\",\"error\":\"handler unknown error\"}"};
            }
        } else {
            resp = Message{MessageType::Response,
                           req.command,
                           std::string("{\"ok\":false,\"command\":\"") + req.command +
                               "\",\"error\":\"no handler\"}"};
        }

        std::string out = resp.command + "|" + resp.payload;
        const char* write_ptr = out.data();
        size_t remaining = out.size();
        DWORD bytesWritten = 0;

        while (remaining > 0) {
            if (!WriteFile(hCurrentPipe, write_ptr, static_cast<DWORD>(remaining), &bytesWritten, NULL)) {
                DWORD err = GetLastError();
                if (err == ERROR_OPERATION_ABORTED) {
                    continue;
                }
                return;
            }

            if (bytesWritten == 0) {
                return;
            }

            write_ptr += bytesWritten;
            remaining -= bytesWritten;
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
                DWORD written = 0;
                WriteFile(hClient, shutdown_frame.c_str(), static_cast<DWORD>(shutdown_frame.size()), &written, NULL);
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
        auto make_error_payload = [&](const std::string& msg) {
            return std::string("{\"ok\":false,\"command\":\"") + json_escape(request.command) + "\",\"error\":\"" +
                   json_escape(msg) + "\"}";
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
                if (lastErr == 2) errMsg += " - service might not be running";
                return {MessageType::Response, request.command, make_error_payload(errMsg)};
            }

            DWORD dwMode = PIPE_READMODE_MESSAGE;
            if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
                CloseHandle(hPipe);
                return {MessageType::Response,
                        request.command,
                        make_error_payload("command=" + request.command + " failed to set pipe mode")};
            }

            std::string out = request.command + "|" + request.payload;
            const char* write_ptr = out.data();
            size_t remaining = out.size();
            DWORD bytesWritten = 0;

            while (remaining > 0) {
                if (!WriteFile(hPipe, write_ptr, static_cast<DWORD>(remaining), &bytesWritten, NULL)) {
                    const DWORD err = GetLastError();
                    if (err == ERROR_OPERATION_ABORTED) {
                        continue;
                    }
                    CloseHandle(hPipe);
                    return {MessageType::Response,
                            request.command,
                            make_error_payload("command=" + request.command + " failed to write to pipe (error " +
                                               std::to_string(err) + ")")};
                }

                if (bytesWritten == 0) {
                    CloseHandle(hPipe);
                    return {MessageType::Response,
                            request.command,
                            make_error_payload("command=" + request.command + " write returned zero bytes")};
                }

                write_ptr += bytesWritten;
                remaining -= bytesWritten;
            }

            std::string raw;
            char buffer[4096];
            DWORD bytesRead = 0;
            Message resp{MessageType::Response, request.command, ""};

            bool read_ok = false;
            do {
                if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
                    raw.append(buffer, bytesRead);
                    read_ok = true;
                    break;
                }

                const DWORD err = GetLastError();
                if (err == ERROR_MORE_DATA) {
                    raw.append(buffer, bytesRead);
                    continue;
                }

                if (err == ERROR_BROKEN_PIPE) {
                    std::string msg = "daemon closed pipe before response (command=" + request.command + ", error=109)";
                    if (request.command == "connect") {
                        msg += " - check daemon logs last 50 lines";
                    } else if (allow_retry_hint) {
                        msg += " - retrying once";
                    }
                    resp.payload = make_error_payload(msg);
                } else {
                    resp.payload = make_error_payload("command=" + request.command + " failed to read from pipe (error " +
                                                     std::to_string(err) + ")");
                }

                CloseHandle(hPipe);
                return resp;
            } while (true);

            if (read_ok) {
                auto sep = raw.find('|');
                if (sep != std::string::npos) {
                    resp.payload = raw.substr(sep + 1);
                } else {
                    resp.payload = raw;
                }
            }

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
