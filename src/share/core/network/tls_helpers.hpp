#pragma once

#include <string>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>

namespace clink::core::network::tls_shared {

bool parse_endpoint_host_port(const std::string& endpoint, std::string& host, int& port) noexcept;

std::string format_endpoint(const asio::ip::tcp::endpoint& endpoint);

template <typename Socket>
std::string remote_endpoint_or_unknown(const Socket& socket) {
    try {
        return format_endpoint(socket.remote_endpoint());
    } catch (...) {
        return "unknown";
    }
}

void apply_server_context_options(asio::ssl::context& ssl_ctx);
void load_certificate_chain_and_key(asio::ssl::context& ssl_ctx, const std::string& cert_path, const std::string& key_path);
std::string current_certificate_subject(asio::ssl::verify_context& ctx);
std::string current_verify_error_message(asio::ssl::verify_context& ctx);

bool verify_pinned_certificate_hash(const std::string& pinned_cert_hash,
                                    asio::ssl::verify_context& ctx,
                                    std::string* actual_hex_digest = nullptr);

bool verify_certificate_with_optional_pin(const std::string& pinned_cert_hash,
                                          bool preverified,
                                          asio::ssl::verify_context& ctx,
                                          std::string* actual_hex_digest = nullptr);

}  // namespace clink::core::network::tls_shared
