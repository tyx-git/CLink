#include "src/share/core/network/tls_helpers.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <cstdio>
#include <string_view>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace clink::core::network::tls_shared {

bool parse_endpoint_host_port(const std::string& endpoint, std::string& host, int& port) noexcept {
    if (endpoint.empty()) {
        return false;
    }

    std::string_view port_view;
    if (endpoint.front() == '[') {
        const std::size_t right_bracket = endpoint.find(']');
        if (right_bracket == std::string::npos || right_bracket + 2 > endpoint.size() || endpoint[right_bracket + 1] != ':') {
            return false;
        }

        host = endpoint.substr(1, right_bracket - 1);
        port_view = std::string_view{endpoint}.substr(right_bracket + 2);
    } else {
        const std::size_t colon_pos = endpoint.rfind(':');
        if (colon_pos == std::string::npos) {
            return false;
        }

        host = endpoint.substr(0, colon_pos);
        port_view = std::string_view{endpoint}.substr(colon_pos + 1);
    }

    int parsed_port = 0;
    const auto parse_result = std::from_chars(port_view.data(), port_view.data() + port_view.size(), parsed_port);
    if (parse_result.ec != std::errc{} || parse_result.ptr != port_view.data() + port_view.size() || parsed_port <= 0 || parsed_port > 65535) {
        return false;
    }

    port = parsed_port;
    return true;
}

std::string format_endpoint(const asio::ip::tcp::endpoint& endpoint) {
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

void apply_server_context_options(asio::ssl::context& ssl_ctx) {
    ssl_ctx.set_options(
        asio::ssl::context::default_workarounds |
        asio::ssl::context::no_sslv2 |
        asio::ssl::context::single_dh_use
    );
}

void load_certificate_chain_and_key(asio::ssl::context& ssl_ctx, const std::string& cert_path, const std::string& key_path) {
    ssl_ctx.use_certificate_chain_file(cert_path);
    ssl_ctx.use_private_key_file(key_path, asio::ssl::context::pem);
}

std::string current_certificate_subject(asio::ssl::verify_context& ctx) {
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    if (!cert) {
        return {};
    }

    char subject[256]{};
    if (!X509_NAME_oneline(X509_get_subject_name(cert), subject, static_cast<int>(sizeof(subject)))) {
        return {};
    }
    return subject;
}

std::string current_verify_error_message(asio::ssl::verify_context& ctx) {
    const int err = X509_STORE_CTX_get_error(ctx.native_handle());
    return X509_verify_cert_error_string(err);
}

bool verify_pinned_certificate_hash(const std::string& pinned_cert_hash,
                                    asio::ssl::verify_context& ctx,
                                    std::string* actual_hex_digest) {
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    if (!cert) {
        return false;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len) <= 0) {
        return false;
    }

    std::string hex_digest;
    hex_digest.reserve(md_len * 2);
    for (unsigned int i = 0; i < md_len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", md[i]);
        hex_digest += buf;
    }

    if (actual_hex_digest) {
        *actual_hex_digest = hex_digest;
    }

    std::string pinned = pinned_cert_hash;
    std::transform(pinned.begin(), pinned.end(), pinned.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    pinned.erase(std::remove(pinned.begin(), pinned.end(), ':'), pinned.end());

    return hex_digest == pinned;
}

bool verify_certificate_with_optional_pin(const std::string& pinned_cert_hash,
                                          bool preverified,
                                          asio::ssl::verify_context& ctx,
                                          std::string* actual_hex_digest) {
    if (!pinned_cert_hash.empty()) {
        return verify_pinned_certificate_hash(pinned_cert_hash, ctx, actual_hex_digest);
    }

    return preverified;
}

}  // namespace clink::core::network::tls_shared
