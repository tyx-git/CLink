// ===== Linux IPC 实现：Unix Domain Socket =====
// IpcServer：bind + listen + accept 循环 + 每连接独立线程处理
// IpcClient：connect 连接 + read/write 同步阻塞
// Socket 路径默认 /tmp/clink-ipc.sock，可通过配置 ipc.address 覆盖

#include "src/share/core/ipc/ipc.hpp"
#include "src/share/core/ipc/ipc_message_utils.hpp"
#include "src/share/core/logging/logger.hpp"

#include <asio.hpp>
#include <asio/local/stream_protocol.hpp>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
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

// ---------------------------------------------------------------------------
// Async Unix IPC Server (Asio-based, no thread leak)
// ---------------------------------------------------------------------------
class AsyncUnixIpcServer : public IpcServer,
                           public std::enable_shared_from_this<AsyncUnixIpcServer> {
public:
    AsyncUnixIpcServer(asio::io_context& io, std::shared_ptr<logging::Logger> logger)
        : io_context_(io)
        , strand_(asio::make_strand(io))
        , acceptor_(io)
        , logger_(std::move(logger)) {}

    ~AsyncUnixIpcServer() override {
        running_.store(false);
        std::error_code ec;
        acceptor_.cancel(ec);
        acceptor_.close(ec);
        if (!socket_path_.empty() && std::filesystem::exists(socket_path_)) {
            std::filesystem::remove(socket_path_, ec);
        }
    }

    void start(const std::string& address) override {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;

        socket_path_ = address.empty() ? "/tmp/clink-ipc.sock" : address;
        if (std::filesystem::exists(socket_path_)) {
            std::error_code ec;
            std::filesystem::remove(socket_path_, ec);
        }

        std::error_code ec;
        acceptor_.open(asio::local::stream_protocol(), ec);
        if (ec) {
            running_.store(false);
            if (logger_) logger_->error("[ipc] failed to open acceptor: " + ec.message());
            return;
        }

        acceptor_.set_option(asio::local::stream_protocol::acceptor::reuse_address(true), ec);
        acceptor_.bind(asio::local::stream_protocol::endpoint(socket_path_), ec);
        if (ec) {
            acceptor_.close();
            running_.store(false);
            if (logger_) logger_->error("[ipc] failed to bind: " + ec.message());
            return;
        }

        acceptor_.listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            acceptor_.close();
            running_.store(false);
            if (logger_) logger_->error("[ipc] failed to listen: " + ec.message());
            return;
        }

        start_accept();
    }

    void stop() override {
        if (!running_.exchange(false)) return;

        auto self = shared_from_this();
        asio::post(strand_, [self] {
            std::error_code ec;
            self->acceptor_.cancel(ec);
            self->acceptor_.close(ec);
        });

        // Wait for io_context to drain pending handlers
        // (the io_context is owned externally, we just close our acceptor)

        if (!socket_path_.empty() && std::filesystem::exists(socket_path_)) {
            std::error_code ec;
            std::filesystem::remove(socket_path_, ec);
        }
    }

    void set_handler(std::function<Message(const Message&)> handler) override {
        handler_ = std::move(handler);
    }

private:
    void start_accept() {
        auto self = shared_from_this();
        acceptor_.async_accept(
            asio::bind_executor(strand_,
                [this, self](std::error_code ec, asio::local::stream_protocol::socket socket) {
                    if (ec || !running_) {
                        return;
                    }
                    handle_client(std::move(socket));
                    start_accept();
                }));
    }

    void handle_client(asio::local::stream_protocol::socket socket) {
        // Read frame length (4 bytes, network order)
        auto len_buf = std::make_shared<uint32_t>(0);
        auto socket_ptr = std::make_shared<asio::local::stream_protocol::socket>(std::move(socket));

        asio::async_read(*socket_ptr,
            asio::buffer(len_buf.get(), sizeof(uint32_t)),
            asio::bind_executor(strand_,
                [this, self = shared_from_this(), socket_ptr, len_buf]
                (std::error_code ec, std::size_t /*bytes*/) {
                    if (ec) return;

                    const uint32_t total_len = ntohl(*len_buf);
                    if (total_len == 0 || total_len > kMaxIpcMessageSize) return;

                    auto raw = std::make_shared<std::string>(total_len, '\0');
                    asio::async_read(*socket_ptr,
                        asio::buffer(raw->data(), raw->size()),
                        asio::bind_executor(strand_,
                            [this, self, socket_ptr, raw]
                            (std::error_code ec2, std::size_t /*bytes*/) {
                                if (ec2) return;
                                process_request(socket_ptr, *raw);
                            }));
                }));
    }

    void process_request(std::shared_ptr<asio::local::stream_protocol::socket> socket,
                         const std::string& raw) {
        Message req = detail::parse_wire_request(raw);

        if (req.command == kShutdownCommand) {
            std::error_code ec;
            socket->close(ec);
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

        auto out = std::make_shared<std::string>(detail::build_wire_message(resp.command, resp.payload));
        auto resp_len = std::make_shared<uint32_t>(htonl(static_cast<uint32_t>(out->size())));

        // Write response length + payload
        auto write_buf = std::make_shared<std::vector<asio::const_buffer>>();
        write_buf->push_back(asio::buffer(resp_len.get(), sizeof(uint32_t)));
        write_buf->push_back(asio::buffer(out->data(), out->size()));

        asio::async_write(*socket, *write_buf,
            asio::bind_executor(strand_,
                [this, self = shared_from_this(), socket, resp_len, out, request_id, cmd = req.command]
                (std::error_code ec, std::size_t /*bytes*/) {
                    if (ec) {
                        if (logger_) {
                            logger_->warn("[ipc.resp.write.failed] id=" + std::to_string(request_id) +
                                          " command=" + cmd + " error=" + ec.message());
                        }
                    } else if (logger_) {
                        logger_->debug("[ipc.req.end] id=" + std::to_string(request_id) +
                                       " status=ok command=" + cmd);
                    }
                    std::error_code close_ec;
                    socket->close(close_ec);
                }));
    }

    asio::io_context& io_context_;
    asio::strand<asio::io_context::executor_type> strand_;
    asio::local::stream_protocol::acceptor acceptor_;
    std::shared_ptr<logging::Logger> logger_;
    std::function<Message(const Message&)> handler_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> next_request_id_{0};
    std::string socket_path_;
};

class AsyncUnixIpcServerHandle : public IpcServer {
public:
    AsyncUnixIpcServerHandle(asio::io_context& io, std::shared_ptr<logging::Logger> logger)
        : impl_(std::make_shared<AsyncUnixIpcServer>(io, std::move(logger))) {}

    ~AsyncUnixIpcServerHandle() override { impl_->stop(); }

    void start(const std::string& address) override { impl_->start(address); }
    void stop() override { impl_->stop(); }
    void set_handler(std::function<Message(const Message&)> handler) override {
        impl_->set_handler(std::move(handler));
    }

private:
    std::shared_ptr<AsyncUnixIpcServer> impl_;
};

// ---------------------------------------------------------------------------
// Thread-based Unix IPC Server (legacy, used when no io_context provided)
// ---------------------------------------------------------------------------
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
            }
        } else if (logger_) {
            const int err = errno;
            logger_->warn("[ipc.resp.write.failed] id=" + std::to_string(request_id) +
                          " command=" + req.command +
                          " error=" + std::to_string(err));
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

// ---------------------------------------------------------------------------
// Unix IPC Client (connect-per-request)
// ---------------------------------------------------------------------------
class UnixIpcClient : public IpcClient {
public:
    explicit UnixIpcClient(std::shared_ptr<logging::Logger> logger) : logger_(std::move(logger)) {}

    void connect(const std::string& address) override { socket_path_ = address.empty() ? "/tmp/clink-ipc.sock" : address; }
    void disconnect() override {}

    Message send_request(const Message& request) override {
        auto err = [&](const std::string& msg, const std::string& reason = std::string{}) {
            return detail::make_error_response(request, msg, reason);
        };

        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            const int err_no = errno;
            return err("failed to create socket (error " + std::to_string(err_no) + ")",
                       control_plane::kReasonSocketCreateFailed);
        }

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path_.c_str());

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            const int err_no = errno;
            ::close(fd);
            std::string reason = control_plane::kReasonSocketConnectFailed;
            if (err_no == ENOENT || err_no == ECONNREFUSED) {
                reason = control_plane::kReasonServiceNotRunning;
            }
            return err("failed to connect unix socket (error " + std::to_string(err_no) + ")", reason);
        }

        std::string out = detail::build_wire_message(request.command, request.payload);
        if (out.empty() || out.size() > kMaxIpcMessageSize) {
            ::close(fd);
            return err("request too large", control_plane::kReasonRequestTooLarge);
        }

        const uint32_t out_len = static_cast<uint32_t>(out.size());
        uint32_t out_net_len = htonl(out_len);
        if (!write_full(fd, &out_net_len, sizeof(out_net_len)) || !write_full(fd, out.data(), out.size())) {
            const int err_no = errno;
            ::close(fd);
            return err("failed to write request (error " + std::to_string(err_no) + ")",
                       control_plane::kReasonRequestWriteFailed);
        }

        uint32_t resp_net_len = 0;
        if (!read_full(fd, &resp_net_len, sizeof(resp_net_len))) {
            const int err_no = errno;
            ::close(fd);
            return err("failed to read response length (error " + std::to_string(err_no) + ")",
                       control_plane::kReasonResponseLengthReadFailed);
        }

        const uint32_t resp_len = ntohl(resp_net_len);
        if (resp_len == 0 || resp_len > kMaxIpcMessageSize) {
            ::close(fd);
            return err("invalid response length", control_plane::kReasonResponseLengthInvalid);
        }

        std::string raw;
        raw.resize(resp_len);
        if (!read_full(fd, raw.data(), raw.size())) {
            const int err_no = errno;
            ::close(fd);
            return err("failed to read response (error " + std::to_string(err_no) + ")",
                       control_plane::kReasonResponseReadFailed);
        }

        ::close(fd);
        return {MessageType::Response, request.command, detail::extract_wire_payload(raw)};
    }

private:
    std::shared_ptr<logging::Logger> logger_;
    std::string socket_path_{"/tmp/clink-ipc.sock"};
};

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------
std::unique_ptr<IpcServer> create_server(std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<UnixIpcServer>(std::move(logger));
}

std::unique_ptr<IpcServer> create_server() {
    return create_server(nullptr);
}

std::unique_ptr<IpcServer> create_server(asio::io_context& io, std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<AsyncUnixIpcServerHandle>(io, std::move(logger));
}

std::unique_ptr<IpcClient> create_client(std::shared_ptr<logging::Logger> logger) {
    return std::make_unique<UnixIpcClient>(std::move(logger));
}

} // namespace clink::core::ipc
