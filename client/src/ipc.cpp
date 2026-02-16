#include "clink/core/ipc.hpp"

#include <iostream>
#include <windows.h>
#include <thread>
#include <atomic>
#include <vector>

namespace clink::core::ipc {

class WindowsIpcServer : public IpcServer {
public:
    ~WindowsIpcServer() {
        stop();
    }

    void start(const std::string& address) override {
        if (running_) return;
        
        address_ = address;
        // Convert address to wstring for Windows API
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(len);
            MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, waddr.data(), len);
            waddress_ = std::wstring(waddr.data());
        }

        running_ = true;
        server_thread_ = std::thread(&WindowsIpcServer::run_server, this);
    }
    
    void stop() override {
        running_ = false;
        if (hPipe_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(hPipe_, NULL);
            CloseHandle(hPipe_);
            hPipe_ = INVALID_HANDLE_VALUE;
        }
        if (server_thread_.joinable()) {
            server_thread_.join();
        }
    }
    
    void set_handler(std::function<Message(const Message&)> handler) override {
        handler_ = std::move(handler);
    }

private:
    void run_server() {
        while (running_) {
            // Re-create pipe for each connection or if it doesn't exist
            HANDLE hPipe = CreateNamedPipeW(
                waddress_.c_str(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                4096, 4096, 0, NULL);

            if (hPipe == INVALID_HANDLE_VALUE) {
                std::cerr << "[ipc] failed to create pipe: " << GetLastError() << std::endl;
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

        if (ReadFile(hCurrentPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            std::string raw(buffer);
            
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

            Message resp = handler_ ? handler_(req) : Message{MessageType::Response, req.command, "{\"error\": \"no handler\"}"};
            
            std::string out = resp.command + "|" + resp.payload;
            DWORD bytesWritten;
            if (WriteFile(hCurrentPipe, out.c_str(), static_cast<DWORD>(out.length()), &bytesWritten, NULL)) {
                FlushFileBuffers(hCurrentPipe);
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
        // Convert address to wstring for Windows API
        int len = MultiByteToWideChar(CP_UTF8, 0, address_.c_str(), -1, NULL, 0);
        if (len > 0) {
            std::vector<wchar_t> waddr(len);
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
            return {MessageType::Response, request.command, "{\"error\": \"" + errMsg + "\"}"};
        }

        // Set pipe to message mode
        DWORD dwMode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL)) {
            CloseHandle(hPipe);
            return {MessageType::Response, request.command, "{\"error\": \"failed to set pipe mode\"}"};
        }

        std::string out = request.command + "|" + request.payload;
        DWORD bytesWritten;
        if (!WriteFile(hPipe, out.c_str(), static_cast<DWORD>(out.length()), &bytesWritten, NULL)) {
            CloseHandle(hPipe);
            return {MessageType::Response, request.command, "{\"error\": \"failed to write to pipe\"}"};
        }

        char buffer[4096];
        DWORD bytesRead;
        Message resp{MessageType::Response, request.command, ""};
        
        // Use synchronous ReadFile for now, but with message mode it should return after one message
        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0';
            std::string raw(buffer);
            auto sep = raw.find('|');
            if (sep != std::string::npos) {
                resp.payload = raw.substr(sep + 1);
            } else {
                resp.payload = raw;
            }
        } else {
            resp.payload = "{\"error\": \"failed to read from pipe (error " + std::to_string(GetLastError()) + ")\"}";
        }

        CloseHandle(hPipe);
        return resp;
    }

private:
    std::string address_;
    std::wstring waddress_;
};

std::unique_ptr<IpcServer> create_server() {
    return std::make_unique<WindowsIpcServer>();
}

std::unique_ptr<IpcClient> create_client() {
    return std::make_unique<WindowsIpcClient>();
}

} // namespace clink::core::ipc
