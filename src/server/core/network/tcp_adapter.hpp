#pragma once

#include "src/server/core/network/transport_adapter.hpp"
#include "src/server/core/network/transport_listener.hpp"
#include "src/share/core/logging/logger.hpp"
#include <memory>
#include <string>
#include <asio.hpp>
#include <atomic>
#include "src/server/core/memory/buffer_pool.hpp"

namespace clink::core::network {

// TCP 传输适配器：基于 Asio 异步读写，支撑数据面 TCP 隧道
class TcpTransportAdapter : public TransportAdapter, public std::enable_shared_from_this<TcpTransportAdapter> {
public:
    explicit TcpTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    
    /**
     * @brief 内部使用：从已建立的 socket 创建适配器
     */
    TcpTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, asio::ip::tcp::socket socket);
    
    ~TcpTransportAdapter() override;

    std::string_view type() const noexcept override { return "tcp"; }

    void start();                                           // 开始接收（用于 listener accept 的连接）
    std::error_code start(const std::string& endpoint) override;    // 作为客户端连接到远端 endpoint
    void stop() override;
    std::error_code send(const uint8_t* data, size_t size) override;
    std::error_code send(const Packet& packet) override;
    void on_receive(ReceiveCallback callback) override;
    void on_receive(ZeroCopyReceiveCallback callback) override;
    
    bool is_connected() const noexcept override;
    std::string_view remote_endpoint() const noexcept override { return remote_endpoint_; }

private:
    void do_receive();
    void do_read_header();
    void do_read_body(std::shared_ptr<memory::Block> block, uint16_t payload_size);
    bool validate_payload_size(uint16_t payload_size);

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    ReceiveCallback receive_callback_;
    ZeroCopyReceiveCallback zero_copy_receive_callback_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};

    asio::ip::tcp::socket socket_;
    std::string remote_endpoint_;
    std::vector<uint8_t> receive_buffer_;
};

// TCP 监听器：accept 新连接并创建 TcpTransportAdapter
class TcpTransportListener : public TransportListener, public std::enable_shared_from_this<TcpTransportListener> {
public:
    explicit TcpTransportListener(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    ~TcpTransportListener() override;

    std::string_view type() const noexcept override { return "tcp"; }

    std::error_code listen(const std::string& endpoint) override;
    void stop() override;
    void on_connection(NewConnectionCallback callback) override;

private:
    void do_accept();

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    NewConnectionCallback connection_callback_;
    std::atomic<bool> running_{false};
    
    asio::ip::tcp::acceptor acceptor_;
    std::string listen_endpoint_;
};

} // namespace clink::core::network
