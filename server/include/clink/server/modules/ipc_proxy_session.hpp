#pragma once

#ifdef _WIN32

#include <memory>
#include <mutex>
#include <asio.hpp>
#include <vector>
#include <deque>
#include "server/include/clink/core/logging/logger.hpp"
#include "server/include/clink/core/network/session_manager.hpp"
#include "process_ipc_server.hpp" // For IPCConnection

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
                if (!ec) {
                    if (session_manager_) {
                         std::string vip = session_manager_->get_virtual_interface_address();
                         if (!vip.empty()) {
                             asio::error_code bind_ec;
                             remote_socket_.open(asio::ip::tcp::v4(), bind_ec);
                             if (!bind_ec) {
                                 remote_socket_.bind(asio::ip::tcp::endpoint(asio::ip::make_address(vip), 0), bind_ec);
                             }
                         }
                    }
                    asio::async_connect(remote_socket_, results,
                        [this, self, host, port](std::error_code ec, asio::ip::tcp::endpoint) {
                            if (!ec) {
                                std::lock_guard<std::recursive_mutex> lock(mutex_);
                                connected_ = true;
                                logger_->debug("Connected to target {}:{} for socket {}", host, port, socket_id_);
                                do_read();
                                if (!outbox_.empty()) {
                                    do_write();
                                }
                            } else {
                                logger_->warn("Failed to connect to target {}:{}: {}", host, port, ec.message());
                                close();
                            }
                        });
                } else {
                    logger_->warn("Failed to resolve target {}:{}: {}", host, port, ec.message());
                    close();
                }
            });
    }

    void send_data(const std::vector<char>& data) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        bool write_in_progress = !outbox_.empty();
        outbox_.push_back(data);
        if (connected_ && !write_in_progress) {
            do_write();
        }
    }

    void set_close_handler(std::function<void(uint64_t)> handler) {
        close_handler_ = std::move(handler);
    }

    void close() {
        if (closed_) return;
        closed_ = true;

        if (remote_socket_.is_open()) {
            asio::error_code ec;
            remote_socket_.close(ec);
        }
        
        if (close_handler_) {
            close_handler_(socket_id_);
        }
    }

private:
    std::recursive_mutex mutex_;

    void do_read() {
        auto self = shared_from_this();
        remote_socket_.async_read_some(asio::buffer(buffer_),
            [this, self](std::error_code ec, std::size_t length) {
                if (!ec) {
                    if (auto conn = ipc_conn_.lock()) {
                        std::vector<char> data(buffer_.begin(), buffer_.begin() + length);
                        conn->write_packet(clink::hook::ipc::PacketType::DataRecv, socket_id_, data);
                    } else {
                        close();
                        return;
                    }
                    do_read();
                } else {
                    if (ec != asio::error::operation_aborted) {
                        logger_->debug("Remote connection closed for socket {}: {}", socket_id_, ec.message());
                    }
                    close();
                }
            });
    }

    void do_write() {
        // Assumes mutex_ is locked by caller
        auto self = shared_from_this();
        asio::async_write(remote_socket_, asio::buffer(outbox_.front()),
            [this, self](std::error_code ec, std::size_t) {
                std::lock_guard<std::recursive_mutex> lock(mutex_);
                if (!ec) {
                    outbox_.pop_front();
                    if (!outbox_.empty()) {
                        do_write();
                    }
                } else {
                    logger_->warn("Write failed for socket {}: {}", socket_id_, ec.message());
                    close();
                }
            });
    }

    asio::ip::tcp::socket remote_socket_;
    asio::ip::tcp::resolver resolver_;
    std::weak_ptr<clink::hook::IPCConnection> ipc_conn_;
    uint64_t socket_id_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    std::array<char, 8192> buffer_;
    std::deque<std::vector<char>> outbox_;
    std::function<void(uint64_t)> close_handler_;
    bool closed_ = false;
    bool connected_ = false;
};

} // namespace clink::server::modules

#endif // _WIN32
