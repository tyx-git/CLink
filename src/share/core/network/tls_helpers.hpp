#pragma once

#include <string>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>

// TLS 通用工具函数：证书加载、端点解析、证书 pin 校验
// 被 TlsTransportAdapter 和 TlsTransportListener 调用
namespace clink::core::network::tls_shared {

bool parse_endpoint_host_port(const std::string& endpoint, std::string& host, int& port) noexcept; // 解析 "host:port"
std::string format_endpoint(const asio::ip::tcp::endpoint& endpoint);    // 格式化端点为字符串

template <typename Socket>
std::string remote_endpoint_or_unknown(const Socket& socket) {           // 安全获取远端端点（异常时返回 unknown）
    try {
        return format_endpoint(socket.remote_endpoint());
    } catch (...) {
        return "unknown";
    }
}

void apply_server_context_options(asio::ssl::context& ssl_ctx);          // 配置服务端 SSL 上下文选项
void load_certificate_chain_and_key(asio::ssl::context& ssl_ctx,         // 加载证书链和私钥
    const std::string& cert_path, const std::string& key_path);
std::string current_certificate_subject(asio::ssl::verify_context& ctx); // 获取当前证书的 Subject
std::string current_verify_error_message(asio::ssl::verify_context& ctx); // 获取证书校验错误信息

// 校验证书的 SHA256 指纹是否和预期 pin 值一致
bool verify_pinned_certificate_hash(const std::string& pinned_cert_hash,
    asio::ssl::verify_context& ctx, std::string* actual_hex_digest = nullptr);

// 综合校验：先走 OpenSSL 标准链校验（preverified），若通过再检查 pin
bool verify_certificate_with_optional_pin(const std::string& pinned_cert_hash,
    bool preverified, asio::ssl::verify_context& ctx,
    std::string* actual_hex_digest = nullptr);

}  // namespace clink::core::network::tls_shared
