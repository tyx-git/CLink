#include "server/include/clink/core/ipc.hpp"
#include "server/include/clink/core/logging/logger.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <functional>
#include <future>
#include <string>
#include <thread>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
constexpr char kShutdownCommand[] = "__clink_shutdown__";
constexpr auto kHandlerTimeout = std::chrono::seconds(5);
constexpr uint32_t kMaxIpcMessageSize = 1 * 1024 * 1024; // 1MB hard limit

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

bool read_full(int fd, void* buf, size_t len) {
    auto* p = static_cast<char*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        const ssize_t n = ::read(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += static_cast<size_t>(n);
        remaining -= static_cast<size_t>(n);
    }
    return true;
}

bool write_full(int fd, const void* buf, size_t len) {
    const auto* p = static_cast<const char*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
        const ssize_t n = ::write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        p += static_cast<size_t>(n);
        remaining -= static_cast<size_t>(n);
    }
    return true;
}
}

namespace clink::core::ipc {

class UnixIpcServer : public IpcServer {
public:
    explicit UnixIpcServer(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}
    ~UnixIpcServer() override { stop(); }

    void start(const std::string& address) override {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;

        socket_path_ = address.empty() ? "/tmp/clink-ipc.sock" : address;
        if (std::filesystem::exists(socket_path_)) {
            std::error_code ec;
            std::filesystem::remove(socket_path_, ec);
        }

        server_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd_ < 0) {
            running_.store(false);
            if (logger_) logger_->error("[ipc] failed to create unix socket");
            return;
        }

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path_.c_str());

        if (::bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            if (logger_) logger_->error("[ipc] failed to bind unix socket");
            ::close(server_fd_);
            server_fd_ = -1;
            running_.store(false);
            return;
        }

        if (::listen(server_fd_, 16) < 0) {
            if (logger_) logger_->error("[ipc] failed to listen unix socket");
            ::close(server_fd_);
            server_fd_ = -1;
            running_.store(false);
            return;
        }

        server_thread_ = std::thread(&UnixIpcServer::run_server, this);
    }

    void stop() override {
        if (!running_.exchange(false)) return;

        if (server_fd_ >= 0) {
            ::shutdown(server_fd_, SHUT_RDWR);
            ::close(server_fd_);
            server_fd_ = -1;
        }

        if (server_thread_.joinable()) server_thread_.join();

        if (!socket_path_.empty() && std::filesystem::exists(socket_path_)) {
            std::error_code ec;
            std::filesystem::remove(socket_path_, ec);
        }
    }

    void set_handler(std::function<Message(const Message&)> handler) override { handler_ = std::move(handler); }

private:
    void run_server() {
        while (running_) {
            int client_fd = ::accept(server_fd_, nullptr, nullptr);
            if (client_fd < 0) {
                if (!running_) break;
                continue;
            }
            std::thread(&UnixIpcServer::process_client, this, client_fd).detach();
        }
    }

    void process_client(int client_fd) {
        uint32_t net_len = 0;
        if (!read_full(client_fd, &net_len, sizeof(net_len))) {
            ::close(client_fd);
            return;
        }

        const uint32_t total_len = ntohl(net_len);
        if (total_len == 0 || total_len > kMaxIpcMessageSize) {
            ::close(client_fd);
            return;
        }

        std::string raw;
        raw.resize(total_len);
        if (!read_full(client_fd, raw.data(), raw.size())) {
            ::close(client_fd);
            return;
        }

        auto sep = raw.find('|');
        Message req{MessageType::Request, sep == std::string::npos ? raw : raw.substr(0, sep),
                    sep == std::string::npos ? "" : raw.substr(sep + 1)};

        if (req.command == kShutdownCommand) {
            ::close(client_fd);
            return;
        }

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
        const uint32_t total_len = static_cast<uint32_t>(out.size());
        uint32_t net_len = htonl(total_len);

        bool write_ok = write_full(client_fd, &net_len, sizeof(net_len));
        if (write_ok) {
            write_ok = write_full(client_fd, out.data(), out.size());
            if (!write_ok && logger_) {
                logger_->warn("[ipc] failed to write unix socket response");
            }
        } else if (logger_) {
            logger_->warn("[ipc] failed to write unix socket response length");
        }

        if (write_ok && logger_) {
            logger_->info("[ipc.resp.write.ok] id=" + std::to_string(request_id) +
                          " command=" + req.command +
                          " payload_bytes=" + std::to_string(resp.payload.size()));
            logger_->info("[ipc.req.end] id=" + std::to_string(request_id) + " command=" + req.command);
        }

        ::close(client_fd);
    }

    std::shared_ptr<logging::Logger> logger_;
    std::function<Message(const Message&)> handler_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> next_request_id_{0};
    int server_fd_{-1};
    std::string socket_path_;
    std::thread server_thread_;
};

class UnixIpcClient : public IpcClient {
public:
    explicit UnixIpcClient(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}

    void connect(const std::string& address) override { socket_path_ = address.empty() ? "/tmp/clink-ipc.sock" : address; }
    void disconnect() override {}

    Message send_request(const Message& request) override {
        auto err = [&](const std::string& msg) {
            return Message{MessageType::Response, request.command,
                           std::string("{\"ok\":false,\"command\":\"") + json_escape(request.command) +
                               "\",\"error\":\"" + json_escape(msg) + "\"}"};
        };

        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return err("failed to create socket");

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path_.c_str());

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(fd);
            return err("failed to connect unix socket");
        }

        std::string out = request.command + "|" + request.payload;
        if (out.size() == 0 || out.size() > kMaxIpcMessageSize) {
            ::close(fd);
            return err("request too large");
        }

        const uint32_t total_len = static_cast<uint32_t>(out.size());
        uint32_t net_len = htonl(total_len);
        if (!write_full(fd, &net_len, sizeof(net_len)) || !write_full(fd, out.data(), out.size())) {
            ::close(fd);
            return err("failed to write request");
        }

        uint32_t resp_net_len = 0;
        if (!read_full(fd, &resp_net_len, sizeof(resp_net_len))) {
            ::close(fd);
            return err("failed to read response length");
        }

        const uint32_t resp_len = ntohl(resp_net_len);
        if (resp_len == 0 || resp_len > kMaxIpcMessageSize) {
            ::close(fd);
            return err("invalid response length");
        }

        std::string raw;
        raw.resize(resp_len);
        if (!read_full(fd, raw.data(), raw.size())) {
            ::close(fd);
            return err("failed to read response");
        }

        ::close(fd);
        auto sep = raw.find('|');
        return {MessageType::Response, request.command, sep == std::string::npos ? raw : raw.substr(sep + 1)};
    }

private:
    std::shared_ptr<logging::Logger> logger_;
    std::string socket_path_{"/tmp/clink-ipc.sock"};
};

std::unique_ptr<IpcServer> create_server(std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<UnixIpcServer>(std::move(logger));
}

std::unique_ptr<IpcClient> create_client(std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<UnixIpcClient>(std::move(logger));
}

} // namespace clink::core::ipc
