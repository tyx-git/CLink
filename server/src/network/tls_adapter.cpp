#include "clink/core/network/tls_adapter.hpp"
#include <chrono>
#include <vector>
#include <algorithm>
#include <openssl/x509.h>
#include <openssl/evp.h>

namespace clink::core::network {

// --- TlsTransportAdapter ---

TlsTransportAdapter::TlsTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), strand_(asio::make_strand(io_context)), logger_(std::move(logger)), receive_buffer_(8192) {
    handshake_complete_ = false;
}

TlsTransportAdapter::TlsTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, 
                                        asio::ssl::stream<asio::ip::tcp::socket> stream,
                                        std::shared_ptr<asio::ssl::context> ssl_ctx)
    : io_context_(io_context), strand_(stream.get_executor()), logger_(std::move(logger)), 
      ssl_ctx_(std::move(ssl_ctx)),
      stream_(std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(stream))),
      receive_buffer_(8192) {
    handshake_complete_ = true; // Accepted connections are already handshaked
    running_ = true;
    try {
        auto endpoint = stream_->lowest_layer().remote_endpoint();
        remote_endpoint_ = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
    } catch (...) {
        remote_endpoint_ = "unknown";
    }
}

void TlsTransportAdapter::start_accepted() {
    asio::post(strand_, [this, self = shared_from_this()]() {
        do_receive();
    });
}

TlsTransportAdapter::~TlsTransportAdapter() {
    stop();
}

void TlsTransportAdapter::set_certificates(const std::string& ca_cert, const std::string& client_cert, const std::string& client_key) {
    ca_cert_path_ = ca_cert;
    client_cert_path_ = client_cert;
    client_key_path_ = client_key;
}

std::error_code TlsTransportAdapter::start(const std::string& endpoint) {
    if (running_) return {};

    remote_endpoint_ = endpoint;
    
    // Parse endpoint
    size_t colon_pos = endpoint.find(':');
    if (colon_pos == std::string::npos) {
        return std::make_error_code(std::errc::invalid_argument);
    }

    std::string ip = endpoint.substr(0, colon_pos);
    int port = std::stoi(endpoint.substr(colon_pos + 1));

    // Initialize SSL context for client
    ssl_ctx_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    
    if (!ca_cert_path_.empty()) {
        ssl_ctx_->load_verify_file(ca_cert_path_);
        ssl_ctx_->set_verify_mode(asio::ssl::verify_peer);
        ssl_ctx_->set_verify_callback(std::bind(&TlsTransportAdapter::verify_certificate, this, std::placeholders::_1, std::placeholders::_2));
    } else {
        ssl_ctx_->set_verify_mode(asio::ssl::verify_none);
    }

    if (!client_cert_path_.empty() && !client_key_path_.empty()) {
        ssl_ctx_->use_certificate_chain_file(client_cert_path_);
        ssl_ctx_->use_private_key_file(client_key_path_, asio::ssl::context::pem);
    }

    asio::ip::tcp::socket socket(strand_);
    stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(socket), *ssl_ctx_);

    asio::ip::tcp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(ip, std::to_string(port));

    std::error_code ec;
    asio::connect(stream_->lowest_layer(), endpoints, ec);
    if (ec) {
        if (logger_) logger_->error("[tls] failed to connect to " + endpoint + ": " + ec.message());
        return ec;
    }

    running_ = true;
    do_handshake();
    return {};
}

void TlsTransportAdapter::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (logger_) {
            logger_->info("[tls] stopping adapter");
        }
        if (stream_) {
            std::error_code ec;
            stream_->lowest_layer().close(ec);
        }
    }
}

std::error_code TlsTransportAdapter::send(const uint8_t* data, size_t size) {
    if (!running_) return std::make_error_code(std::errc::not_connected);
    
    std::vector<uint8_t> buffer(data, data + size);
    auto self = shared_from_this();
    
    asio::post(strand_, [this, self, buffer = std::move(buffer)]() mutable {
        bool write_in_progress = !write_queue_.empty();
        write_queue_.push_back(std::move(buffer));
        if (!write_in_progress && handshake_complete_) {
            do_write();
        }
    });
    
    return {};
}

void TlsTransportAdapter::do_write() {
    auto self = shared_from_this();
    asio::async_write(*stream_,
        asio::buffer(write_queue_.front()),
        asio::bind_executor(strand_, [this, self](std::error_code ec, std::size_t /*length*/) {
            if (!ec) {
                write_queue_.pop_front();
                if (!write_queue_.empty()) {
                    do_write();
                }
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) logger_->error("[tls] send failed: " + ec.message());
                stop();
            }
        }));
}

bool TlsTransportAdapter::is_connected() const noexcept {
    return running_.load() && stream_ && stream_->lowest_layer().is_open();
}

void TlsTransportAdapter::do_handshake() {
    auto self = shared_from_this();
    stream_->async_handshake(asio::ssl::stream_base::client,
        asio::bind_executor(strand_, [this, self](std::error_code ec) {
            if (!ec) {
                if (logger_) logger_->info("[tls] SSL client handshake successful with " + remote_endpoint_);
                handshake_complete_ = true;
                if (!write_queue_.empty()) {
                    do_write();
                }
                do_receive();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) logger_->error("[tls] SSL client handshake failed: " + ec.message());
                stop();
            }
        }));
}

void TlsTransportAdapter::do_receive() {
    auto self = shared_from_this();
    stream_->async_read_some(asio::buffer(receive_buffer_),
        asio::bind_executor(strand_, [this, self](std::error_code ec, std::size_t length) {
            if (!ec) {
                // if (logger_) logger_->info("[tls] received " + std::to_string(length) + " bytes");
                if (receive_callback_) {
                    receive_callback_(receive_buffer_.data(), length);
                } else {
                    if (logger_) logger_->warn("[tls] received data but no callback set");
                }
                do_receive();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) {
                    logger_->info("[tls] connection closed or error: " + ec.message());
                }
                stop();
            }
        }));
}

bool TlsTransportAdapter::verify_certificate(bool preverified, asio::ssl::verify_context& ctx) {
    if (!pinned_cert_hash_.empty()) {
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        if (!cert) return false;

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        if (X509_digest(cert, EVP_sha256(), md, &md_len) <= 0) {
            return false;
        }

        std::string hex_digest;
        hex_digest.reserve(md_len * 2);
        for (unsigned int i = 0; i < md_len; ++i) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", md[i]);
            hex_digest += buf;
        }

        std::string pinned = pinned_cert_hash_;
        std::transform(pinned.begin(), pinned.end(), pinned.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        pinned.erase(std::remove(pinned.begin(), pinned.end(), ':'), pinned.end());

        if (hex_digest != pinned) {
            if (logger_) logger_->error("[tls] certificate binding verification failed. expected: " + pinned + ", got: " + hex_digest);
            return false;
        }
    }
    return preverified;
}

// --- TlsTransportListener ---

TlsTransportListener::TlsTransportListener(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), logger_(std::move(logger)), 
      ssl_ctx_(std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server)),
      acceptor_(io_context) {
    
    ssl_ctx_->set_options(
        asio::ssl::context::default_workarounds |
        asio::ssl::context::no_sslv2 |
        asio::ssl::context::single_dh_use
    );
}

TlsTransportListener::~TlsTransportListener() {
    stop();
}

void TlsTransportListener::set_certificates(const std::string& ca_cert, const std::string& server_cert, const std::string& server_key) {
    ca_cert_path_ = ca_cert;
    server_cert_path_ = server_cert;
    server_key_path_ = server_key;

    if (!ca_cert_path_.empty()) {
        ssl_ctx_->load_verify_file(ca_cert_path_);
        ssl_ctx_->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    }

    if (!server_cert_path_.empty() && !server_key_path_.empty()) {
        ssl_ctx_->use_certificate_chain_file(server_cert_path_);
        ssl_ctx_->use_private_key_file(server_key_path_, asio::ssl::context::pem);
    }
}

std::string TlsTransportListener::local_endpoint() const {
    if (!running_) return "";
    try {
        auto ep = acceptor_.local_endpoint();
        return ep.address().to_string() + ":" + std::to_string(ep.port());
    } catch (...) {
        return "";
    }
}

std::error_code TlsTransportListener::listen(const std::string& endpoint) {
    if (running_) return {};

    listen_endpoint_ = endpoint;
    
    size_t colon_pos = endpoint.find(':');
    if (colon_pos == std::string::npos) return std::make_error_code(std::errc::invalid_argument);
    
    std::string ip = endpoint.substr(0, colon_pos);
    int port = std::stoi(endpoint.substr(colon_pos + 1));

    asio::ip::tcp::endpoint asio_endpoint(asio::ip::make_address(ip), static_cast<unsigned short>(port));
    
    std::error_code ec;
    acceptor_.open(asio_endpoint.protocol(), ec);
    if (ec) return ec;

    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec) return ec;

    acceptor_.bind(asio_endpoint, ec);
    if (ec) return ec;

    acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) return ec;

    running_ = true;

    if (logger_) {
        logger_->info("[tls] listening on " + endpoint + " (SSL/TLS ready)");
    }

    do_accept();
    return {};
}

void TlsTransportListener::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (logger_) {
            logger_->info("[tls] stopping listener on " + listen_endpoint_);
        }
        std::error_code ec;
        acceptor_.close(ec);
    }
}

void TlsTransportListener::on_connection(NewConnectionCallback callback) {
    connection_callback_ = std::move(callback);
}

void TlsTransportListener::do_accept() {
    auto self = shared_from_this();
    acceptor_.async_accept(asio::make_strand(io_context_),
        [this, self](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                auto stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(socket), *ssl_ctx_);
                
                stream->async_handshake(asio::ssl::stream_base::server,
                    [this, self, stream](std::error_code ec) {
                        if (!ec) {
                            if (logger_) logger_->info("[tls] SSL server handshake successful");
                            if (connection_callback_) {
                                auto adapter = std::make_shared<TlsTransportAdapter>(io_context_, logger_, std::move(*stream), ssl_ctx_);
                                adapter->start_accepted();
                                connection_callback_(std::move(adapter));
                            }
                        } else {
                            if (logger_) {
                                logger_->error("[tls] SSL server handshake failed: " + ec.message());
                            }
                        }
                    });
                
                do_accept();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) {
                    logger_->error("[tls] accept error: " + ec.message());
                }
            }
        });
}

} // namespace clink::core::network