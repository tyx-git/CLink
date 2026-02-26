#pragma once

#include "server/include/clink/core/network/transport_adapter.hpp"
#include "server/include/clink/core/network/transport_listener.hpp"
#include "server/include/clink/core/logging/logger.hpp"
#include <memory>
#include <string>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <atomic>
#include <deque>
#include <variant>
#include "server/include/clink/core/memory/buffer_pool.hpp"

namespace clink::core::network {

/**
 * @brief 基于 Asio SSL 的 TLS 传输适配器实现 (Asynchronous)
 */
class TlsTransportAdapter : public TransportAdapter, public std::enable_shared_from_this<TlsTransportAdapter> {
public:
    explicit TlsTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    
    /**
     * @brief 内部使用：从已建立的 SSL stream 创建适配器
     */
    TlsTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, 
                        asio::ssl::stream<asio::ip::tcp::socket> stream,
                        std::shared_ptr<asio::ssl::context> ssl_ctx = nullptr);
    
    ~TlsTransportAdapter() override;

    std::string_view type() const noexcept override { return "tls"; }

    std::error_code start(const std::string& endpoint) override;
    void stop() override;
    std::error_code send(const uint8_t* data, size_t size) override;
    std::error_code send(const Packet& packet) override;
    void on_receive(ReceiveCallback callback) override { receive_callback_ = std::move(callback); }
    void on_receive(ZeroCopyReceiveCallback callback) override { zero_copy_callback_ = std::move(callback); }
    bool is_connected() const noexcept override;
    std::string_view remote_endpoint() const noexcept override { return remote_endpoint_; }

    // Start receiving for accepted connection
    void start_accepted();

    // 配置证书路径
    void set_certificates(const std::string& ca_cert, const std::string& client_cert, const std::string& client_key);

    // 设置绑定的证书指纹 (SHA256)
    void set_pinned_certificate_hash(const std::string& hash) { pinned_cert_hash_ = hash; }

private:
    void do_handshake();
    void do_receive();
    void do_write();
    bool verify_certificate(bool preverified, asio::ssl::verify_context& ctx);

    asio::io_context& io_context_;
    asio::any_io_executor strand_;
    std::shared_ptr<logging::Logger> logger_;
    std::string remote_endpoint_;
    ReceiveCallback receive_callback_;
    ZeroCopyReceiveCallback zero_copy_callback_;
    std::atomic<bool> running_{false};
    
    std::string ca_cert_path_;
    std::string client_cert_path_;
    std::string client_key_path_;
    std::string pinned_cert_hash_;
    
    std::shared_ptr<asio::ssl::context> ssl_ctx_;
    std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> stream_;
    std::vector<uint8_t> receive_buffer_;
    std::shared_ptr<clink::core::memory::Block> zero_copy_buffer_;
    using WriteItem = std::variant<std::vector<uint8_t>, Packet>;
    std::deque<WriteItem> write_queue_;
    std::atomic<bool> handshake_complete_{false};
};

/**
 * @brief 基于 Asio SSL 的 TLS 监听器实现 (Asynchronous)
 */
class TlsTransportListener : public TransportListener, public std::enable_shared_from_this<TlsTransportListener> {
public:
    explicit TlsTransportListener(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    ~TlsTransportListener() override;

    std::string_view type() const noexcept override { return "tls"; }

    std::error_code listen(const std::string& endpoint) override;
    void stop() override;
    void on_connection(NewConnectionCallback callback) override;

    void set_certificates(const std::string& ca_cert, const std::string& server_cert, const std::string& server_key);
    void set_pinned_certificate_hash(const std::string& hash) { pinned_cert_hash_ = hash; }
    
    // Add local_endpoint accessor
    std::string local_endpoint() const;

private:
    void do_accept();

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    NewConnectionCallback connection_callback_;
    std::atomic<bool> running_{false};
    
    std::string ca_cert_path_;
    std::string server_cert_path_;
    std::string server_key_path_;
    std::string pinned_cert_hash_;

    std::shared_ptr<asio::ssl::context> ssl_ctx_;
    asio::ip::tcp::acceptor acceptor_;
    std::string listen_endpoint_;
};

} // namespace clink::core::network
