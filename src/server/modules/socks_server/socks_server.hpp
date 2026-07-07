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

// SocksSession：处理单个 SOCKS5 连接的生命周期
// 状态机：handshake → request → connect → bridge（双向转发）
class SocksSession : public std::enable_shared_from_this<SocksSession> {
public:
    SocksSession(asio::io_context& io_context, asio::ip::tcp::socket socket, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    void start();

private:
    void do_handshake();            // SOCKS5 握手：协商认证方式
    void do_request();              // 解析客户端请求（目标地址+端口）
    void do_connect(std::string host, std::string port); // 连接目标服务器
    void do_bridge();               // 双向桥接转发数据
    void do_read_client();          // 从客户端读取数据发往远端
    void do_read_remote();          // 从远端读取数据发回客户端
    void close();                   // 关闭连接

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

// SOCKS5 服务端：监听端口、接受连接、创建 SocksSession
class SocksServer : public std::enable_shared_from_this<SocksServer> {
public:
    enum class Backend {
        None,     // 未启动
        Asio,     // Asio 异步后端（默认）
        WinSock   // Windows 原生 Socket API 后端（auto 降级用）
    };

    SocksServer(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    ~SocksServer();

    bool start(uint16_t port = 0, const std::string& backend = "auto"); // 启动：auto 模式尝试 Asio 失败则回退 WinSock
    void stop();
    uint16_t port() const;
    Backend backend() const noexcept { return backend_; }

private:
    void do_accept();               // Asio 异步 accept 循环
    void close_acceptor();          // 关闭 acceptor

#ifdef _WIN32
    bool start_winsock_backend(uint16_t port);  // WinSock 后端：独立线程 accept
    void stop_winsock_backend();
    void winsock_accept_loop();                 // WinSock accept 线程主循环
#endif

    asio::io_context& io_context_;
    std::unique_ptr<asio::ip::tcp::acceptor> acceptor_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    uint16_t port_ = 0;
    Backend backend_ = Backend::None;

#ifdef _WIN32
    std::atomic<bool> winsock_running_{false};
    std::shared_ptr<std::atomic<bool>> winsock_accepting_{std::make_shared<std::atomic<bool>>(false)};
    std::thread winsock_accept_thread_;
    uintptr_t winsock_listen_socket_ = 0;
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> winsock_work_guard_;
#endif
};

} // namespace clink::server::modules
