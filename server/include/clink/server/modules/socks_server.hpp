#pragma once

#include <asio.hpp>
#include <memory>
#include <string>
#include <vector>
#include <array>
#include "server/include/clink/core/logging/logger.hpp"
#include "server/include/clink/core/network/session_manager.hpp"

namespace clink::server::modules {

class SocksSession : public std::enable_shared_from_this<SocksSession> {
public:
    SocksSession(asio::io_context& io_context, asio::ip::tcp::socket socket, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    void start();

private:
    void do_handshake();
    void do_request();
    void do_connect(std::string host, std::string port);
    void do_bridge();
    void do_read_client();
    void do_read_remote();
    void close();

    asio::io_context& io_context_;
    asio::ip::tcp::socket client_socket_;
    asio::ip::tcp::socket remote_socket_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    std::array<uint8_t, 8192> client_buffer_;
    std::array<uint8_t, 8192> remote_buffer_;
    std::string remote_host_;
    uint16_t remote_port_ = 0;
};

class SocksServer {
public:
    SocksServer(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    ~SocksServer();

    bool start(uint16_t port = 0);
    void stop();
    uint16_t port() const;

private:
    void do_accept();

    asio::io_context& io_context_;
    asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    uint16_t port_ = 0;
};

} // namespace clink::server::modules
