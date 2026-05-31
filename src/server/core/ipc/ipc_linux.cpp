#include "src/server/core/ipc/ipc.hpp"
#include "src/share/core/ipc/ipc_message_utils.hpp"
#include "src/share/core/logging/logger.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace {
namespace control_plane = clink::protocol::control_plane;

constexpr char kShutdownCommand[] = "__clink_shutdown__";
constexpr uint32_t kMaxIpcMessageSize = 1 * 1024 * 1024; // 1MB hard limit

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

        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> lock(worker_mutex_);
            workers.swap(worker_threads_);
        }
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }

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
            std::lock_guard<std::mutex> lock(worker_mutex_);
            worker_threads_.emplace_back(&UnixIpcServer::process_client, this, client_fd);
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

        Message req = detail::parse_wire_request(raw);

        if (req.command == kShutdownCommand) {
            ::close(client_fd);
            return;
        }

        const auto request_id = next_request_id_.fetch_add(1) + 1;
        if (logger_) {
            logger_->debug("[ipc.req.start] id=" + std::to_string(request_id) +
                           " command=" + req.command +
                           " payload_bytes=" + std::to_string(req.payload.size()));
        }

        Message resp;
        if (!handler_) {
            resp = detail::make_error_response(req, "no handler", control_plane::kReasonNoHandler);
            if (logger_) logger_->warn("[ipc.handler.exit] id=" + std::to_string(request_id) + " status=error reason=no_handler");
        } else {
            try {
                resp = handler_(req);
                if (logger_) {
                    logger_->debug("[ipc.handler.exit] id=" + std::to_string(request_id) +
                                   " status=ok command=" + req.command);
                }
            } catch (const std::exception& ex) {
                resp = detail::make_error_response(req, ex.what(), control_plane::kReasonHandlerException);
                if (logger_) logger_->error("[ipc.handler.exit] id=" + std::to_string(request_id) +
                                            " status=error exception=" + std::string(ex.what()));
            } catch (...) {
                resp = detail::make_error_response(req, "handler unknown error", control_plane::kReasonHandlerException);
                if (logger_) logger_->error("[ipc.handler.exit] id=" + std::to_string(request_id) +
                                            " status=error exception=unknown");
            }
        }

        std::string out = detail::build_wire_message(resp.command, resp.payload);
        const uint32_t response_len = static_cast<uint32_t>(out.size());
        uint32_t response_net_len = htonl(response_len);

        bool write_ok = write_full(client_fd, &response_net_len, sizeof(response_net_len));
        if (write_ok) {
            write_ok = write_full(client_fd, out.data(), out.size());
            if (write_ok) {
                if (logger_) {
                    logger_->debug("[ipc.req.end] id=" + std::to_string(request_id) +
                                   " status=ok command=" + req.command);
                }
            } else if (logger_) {
                const int err = errno;
                logger_->warn("[ipc.resp.write.failed] id=" + std::to_string(request_id) +
                              " command=" + req.command +
                              " error=" + std::to_string(err));
                logger_->warn("[ipc.req.end] id=" + std::to_string(request_id) +
                              " status=write_failed command=" + req.command);
            }
        } else if (logger_) {
            const int err = errno;
            logger_->warn("[ipc.resp.write.failed] id=" + std::to_string(request_id) +
                          " command=" + req.command +
                          " error=" + std::to_string(err));
            logger_->warn("[ipc.req.end] id=" + std::to_string(request_id) +
                          " status=write_failed command=" + req.command);
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
    std::mutex worker_mutex_;
    std::vector<std::thread> worker_threads_;
};

class UnixIpcClient : public IpcClient {
public:
    explicit UnixIpcClient(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}

    void connect(const std::string& address) override { socket_path_ = address.empty() ? "/tmp/clink-ipc.sock" : address; }
    void disconnect() override {}

    Message send_request(const Message& request) override {
        auto err = [&](const std::string& msg) {
            return detail::make_error_response(request, msg);
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

        std::string out = detail::build_wire_message(request.command, request.payload);
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
        return {MessageType::Response, request.command, detail::extract_wire_payload(raw)};
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
