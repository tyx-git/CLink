#pragma once

#include "server/include/clink/core/network/transport_adapter.hpp"
#include "server/include/clink/core/network/transport_listener.hpp"
#include "server/include/clink/core/logging/logger.hpp"
#include <memory>
#include <string>
#include <asio.hpp>
#include <atomic>
#include "server/include/clink/core/memory/buffer_pool.hpp"

namespace clink::core::network {

/**
 * @brief 基础 TCP 传输适配器实现 (Asynchronous)
 */
class TcpTransportAdapter : public TransportAdapter, public std::enable_shared_from_this<TcpTransportAdapter> {
public:
    explicit TcpTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    
    /**
     * @brief 内部使用：从已建立的 socket 创建适配器
     */
    TcpTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, asio::ip::tcp::socket socket);
    
    ~TcpTransportAdapter() override;

    std::string_view type() const noexcept override { return "tcp"; }

    void start(); // Start receiving (for accepted connections)
    std::error_code start(const std::string& endpoint) override;
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

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    ReceiveCallback receive_callback_;
    ZeroCopyReceiveCallback zero_copy_receive_callback_;
    std::atomic<bool> running_{false};
    
    asio::ip::tcp::socket socket_;
    std::string remote_endpoint_;
    std::vector<uint8_t> receive_buffer_;
};

/**
 * @brief 基础 TCP 监听器实现 (Asynchronous)
 */
class TcpTransportListener : public TransportListener {
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
