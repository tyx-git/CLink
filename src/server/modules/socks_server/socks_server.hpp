#pragma once

#include <asio.hpp>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <array>
#include <thread>
#include <atomic>
#include "src/share/core/logging/logger.hpp"
#include "src/server/core/network/session_manager.hpp"

namespace clink::server::modules {

bool should_bind_to_virtual_interface_for_socks(const std::string& vip);

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

class SocksServer : public std::enable_shared_from_this<SocksServer> {
public:
    enum class Backend {
        None,
        Asio,
        WinSock
    };

    SocksServer(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    ~SocksServer();

    bool start(uint16_t port = 0, const std::string& backend = "auto");
    void stop();
    uint16_t port() const;
    Backend backend() const noexcept { return backend_; }

private:
    void do_accept();
    void close_acceptor();

#ifdef _WIN32
    bool start_winsock_backend(uint16_t port);
    void stop_winsock_backend();
    void winsock_accept_loop();
#endif

    asio::io_context& io_context_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    uint16_t port_ = 0;
    Backend backend_ = Backend::None;

#ifdef _WIN32
    std::atomic<bool> winsock_running_{false};
    std::thread winsock_accept_thread_;
    uintptr_t winsock_listen_socket_ = 0;
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> winsock_work_guard_;
#endif
};

} // namespace clink::server::modules
