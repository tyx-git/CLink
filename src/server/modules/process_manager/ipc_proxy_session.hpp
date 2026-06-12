#pragma once

#ifdef _WIN32

#include <array>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

#include <asio.hpp>

#include "src/share/core/logging/logger.hpp"
#include "src/server/core/network/session_manager.hpp"
#include "src/server/core/network/vip_bind.hpp"
#include "src/server/modules/process_inject/include/process_ipc_server.hpp" // For IPCConnection

namespace clink::server::modules {

class IpcProxySession : public std::enable_shared_from_this<IpcProxySession> {
public:
    IpcProxySession(asio::io_context& io_context,
                    std::shared_ptr<clink::hook::IPCConnection> ipc_conn,
                    uint64_t socket_id,
                    std::shared_ptr<clink::core::logging::Logger> logger,
                    std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr)
        : remote_socket_(io_context),
          resolver_(io_context),
          ipc_conn_(ipc_conn),
          socket_id_(socket_id),
          logger_(std::move(logger)),
          session_manager_(std::move(session_manager)) {}

    ~IpcProxySession() {
        close();
    }

    void start(const std::string& host, uint16_t port) {
        auto self = shared_from_this();
        resolver_.async_resolve(host, std::to_string(port),
            [this, self, host, port](std::error_code ec, asio::ip::tcp::resolver::results_type results) {
                if (ec) {
                    if (logger_) {
                        logger_->warn("Failed to resolve target {}:{}: {}", host, port, ec.message());
                    }
                    close();
                    return;
                }

                auto connect_results = results;

                if (session_manager_) {
                    const std::string vip = session_manager_->get_virtual_interface_address();
                    auto bind_addr = clink::core::network::parse_bind_address(vip, logger_, "[ipc.proxy]");
                    if (bind_addr) {
                        auto filtered = clink::core::network::filter_results_for_bind_address(results, *bind_addr);
                        if (filtered.empty()) {
                            if (logger_) {
                                logger_->warn("[ipc.proxy] no remote endpoints match VIP address family vip={}", bind_addr->to_string());
                            }
                        } else if (clink::core::network::bind_socket_to_virtual_interface(remote_socket_, *bind_addr, logger_, "[ipc.proxy]")) {
                            connect_results = std::move(filtered);
                        }
                    }
                }

                asio::async_connect(remote_socket_, connect_results,
                    [this, self, host, port](std::error_code connect_ec, asio::ip::tcp::endpoint) {
                        if (connect_ec) {
                            if (logger_) {
                                logger_->warn("Failed to connect to target {}:{}: {}", host, port, connect_ec.message());
                            }
                            close();
                            return;
                        }

                        {
                            std::lock_guard<std::mutex> lock(mutex_);
                            connected_ = true;
                        }

                        if (logger_) {
                            logger_->debug("Connected to target {}:{} for socket {}", host, port, socket_id_);
                        }
                        do_read();
                        schedule_write_if_needed();
                    });
            });
    }

    void send_data(const std::vector<char>& data) {
        bool overflow = false;
        std::size_t queued_snapshot = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (closed_) {
                return;
            }

            if (queued_bytes_ + data.size() > kMaxQueuedBytes) {
                overflow = true;
                queued_snapshot = queued_bytes_;
            } else {
                outbox_.push_back(data);
                queued_bytes_ += data.size();
            }
        }

        if (overflow) {
            if (logger_) {
                logger_->warn("IPC proxy queue overflow for socket {}: queued={} incoming={} limit={}",
                              socket_id_, queued_snapshot, data.size(), kMaxQueuedBytes);
            }
            close();
            return;
        }

        schedule_write_if_needed();
    }

    void set_close_handler(std::function<void(uint64_t)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        close_handler_ = std::move(handler);
    }

    void close() {
        std::function<void(uint64_t)> handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (closed_) {
                return;
            }
            closed_ = true;
            connected_ = false;
            write_in_progress_ = false;
            queued_bytes_ = 0;
            outbox_.clear();
            handler = std::move(close_handler_);
        }

        asio::error_code ec;
        resolver_.cancel();
        if (remote_socket_.is_open()) {
            remote_socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            remote_socket_.close(ec);
        }

        if (handler) {
            handler(socket_id_);
        }
    }

private:
    void do_read() {
        auto self = shared_from_this();
        remote_socket_.async_read_some(asio::buffer(buffer_),
            [this, self](std::error_code ec, std::size_t length) {
                if (ec) {
                    if (ec != asio::error::operation_aborted && logger_) {
                        logger_->debug("Remote connection closed for socket {}: {}", socket_id_, ec.message());
                    }
                    close();
                    return;
                }

                if (auto conn = ipc_conn_.lock()) {
                    std::vector<char> data(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(length));
                    conn->write_packet(clink::hook::ipc::PacketType::DataRecv, socket_id_, data);
                } else {
                    close();
                    return;
                }

                do_read();
            });
    }

    void schedule_write_if_needed() {
        std::shared_ptr<std::vector<char>> chunk;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (closed_ || !connected_ || write_in_progress_ || outbox_.empty()) {
                return;
            }
            write_in_progress_ = true;
            chunk = std::make_shared<std::vector<char>>(outbox_.front());
        }

        auto self = shared_from_this();
        asio::async_write(remote_socket_, asio::buffer(*chunk),
            [this, self, chunk](std::error_code ec, std::size_t) {
                bool continue_write = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    write_in_progress_ = false;

                    if (!ec) {
                        if (!outbox_.empty()) {
                            queued_bytes_ -= outbox_.front().size();
                            outbox_.pop_front();
                        }
                        continue_write = connected_ && !closed_ && !outbox_.empty();
                    }
                }

                if (ec) {
                    if (logger_) {
                        logger_->warn("Write failed for socket {}: {}", socket_id_, ec.message());
                    }
                    close();
                    return;
                }

                if (continue_write) {
                    schedule_write_if_needed();
                }
            });
    }

    std::mutex mutex_;
    asio::ip::tcp::socket remote_socket_;
    asio::ip::tcp::resolver resolver_;
    std::weak_ptr<clink::hook::IPCConnection> ipc_conn_;
    uint64_t socket_id_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    std::array<char, 8192> buffer_{};
    std::deque<std::vector<char>> outbox_;
    std::function<void(uint64_t)> close_handler_;
    static constexpr std::size_t kMaxQueuedBytes = 4 * 1024 * 1024;
    std::size_t queued_bytes_ = 0;
    bool closed_ = false;
    bool connected_ = false;
    bool write_in_progress_ = false;
};

} // namespace clink::server::modules

#endif // _WIN32
