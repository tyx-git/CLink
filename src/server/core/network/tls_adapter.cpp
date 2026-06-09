#include "src/server/core/network/tls_adapter.hpp"
#include "src/share/core/network/tls_helpers.hpp"
#include <chrono>
#include <vector>
#include <asio/steady_timer.hpp>

namespace clink::core::network {

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
    remote_endpoint_ = tls_shared::remote_endpoint_or_unknown(stream_->lowest_layer());
}

void TlsTransportAdapter::start_accepted() {
    asio::post(io_context_, [this, self = shared_from_this()]() {
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
    if (logger_) logger_->info("[tls] stage=start status=begin endpoint=" + endpoint);

    remote_endpoint_ = endpoint;
    
    // Parse endpoint
    std::string ip;
    int port = 0;
    if (!tls_shared::parse_endpoint_host_port(endpoint, ip, port)) {
        return std::make_error_code(std::errc::invalid_argument);
    }

    // Initialize SSL context for client
    try {
        ssl_ctx_ = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    } catch (const std::exception& e) {
        if (logger_) logger_->error(std::string("[tls] stage=ssl_ctx status=failed msg=") + e.what());
        return std::make_error_code(std::errc::not_enough_memory);
    }
    
    if (!ca_cert_path_.empty()) {
        try {
            ssl_ctx_->load_verify_file(ca_cert_path_);
            ssl_ctx_->set_verify_callback([this](bool preverified, asio::ssl::verify_context& ctx) {
                if (logger_) logger_->info(std::string("[tls] stage=verify status=begin preverified=") + (preverified ? "true" : "false"));
                if (!preverified) {
                    const std::string subject = tls_shared::current_certificate_subject(ctx);
                    if (!subject.empty()) {
                        if (logger_) logger_->warn(std::string("[tls] stage=verify status=failed subject=") + subject);
                    }
                    if (logger_) logger_->warn(std::string("[tls] stage=verify status=failed err=") + tls_shared::current_verify_error_message(ctx));
                }
                return this->verify_certificate(preverified, ctx);
            });
            ssl_ctx_->set_verify_mode(asio::ssl::verify_peer);
        } catch (const std::exception& e) {
            if (logger_) logger_->error(std::string("[tls] stage=ca_cert status=failed msg=") + e.what());
            return std::make_error_code(std::errc::invalid_argument);
        }
    } else if (!pinned_cert_hash_.empty()) {
        ssl_ctx_->set_verify_callback([this](bool preverified, asio::ssl::verify_context& ctx) {
            return this->verify_certificate(preverified, ctx);
        });
        ssl_ctx_->set_verify_mode(asio::ssl::verify_peer);
    } else {
        if (logger_) logger_->warn("[tls] stage=verify status=disabled role=client reason=no_ca_or_pin");
        ssl_ctx_->set_verify_mode(asio::ssl::verify_none);
    }

    if (!client_cert_path_.empty() && !client_key_path_.empty()) {
        try {
            tls_shared::load_certificate_chain_and_key(*ssl_ctx_, client_cert_path_, client_key_path_);
        } catch (const std::exception& e) {
             if (logger_) logger_->error(std::string("[tls] stage=client_certs status=failed msg=") + e.what());
             return std::make_error_code(std::errc::invalid_argument);
        }
    }

    asio::ip::tcp::socket socket(io_context_);
    stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(socket), *ssl_ctx_);

    asio::ip::tcp::resolver resolver(io_context_);
    asio::ip::tcp::resolver::results_type endpoints;
    try {
        endpoints = resolver.resolve(ip, std::to_string(port));
    } catch (const std::exception& e) {
        if (logger_) logger_->error("[tls] stage=resolve status=failed endpoint=" + endpoint + " msg=" + e.what());
        return std::make_error_code(std::errc::host_unreachable);
    }

    std::error_code ec;
    asio::connect(stream_->lowest_layer(), endpoints, ec);
    if (ec) {
        if (logger_) logger_->error("[tls] stage=connect status=failed endpoint=" + endpoint + " msg=" + ec.message());
        return ec;
    }
    
    stream_->lowest_layer().set_option(asio::ip::tcp::no_delay(true));

    running_ = true;
    // Async handshake to avoid blocking
    auto self = shared_from_this();
    asio::post(io_context_, [this, self]() {
        if (!stream_) {
            if (logger_) logger_->error("[tls] stage=handshake status=failed detail=stream_null");
            return;
        }
        if (!ssl_ctx_) {
            if (logger_) logger_->error("[tls] stage=handshake status=failed detail=ssl_ctx_null");
            return;
        }
        if (logger_) logger_->info("[tls] stage=handshake status=begin");
        do_handshake();
    });
    return {};
}

void TlsTransportAdapter::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (logger_) {
            logger_->info("[tls] stage=stop status=begin");
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
    
    asio::post(io_context_, [this, self, buffer = std::move(buffer)]() mutable {
        bool write_in_progress = !write_queue_.empty();
        write_queue_.emplace_back(std::move(buffer));
        if (!write_in_progress && handshake_complete_) {
            do_write();
        }
    });
    
    return {};
}

std::error_code TlsTransportAdapter::send(const Packet& packet) {
    if (!running_) return std::make_error_code(std::errc::not_connected);
    
    // Make a copy of the packet (shares the block)
    Packet pkt_copy = packet;
    pkt_copy.finalize(); // Ensure checksum is calculated
    auto self = shared_from_this();
    
    asio::post(io_context_, [this, self, pkt = std::move(pkt_copy)]() mutable {
        bool write_in_progress = !write_queue_.empty();
        write_queue_.emplace_back(std::move(pkt));
        if (!write_in_progress && handshake_complete_) {
            do_write();
        }
    });
    
    return {};
}

void TlsTransportAdapter::do_write() {
    auto self = shared_from_this();
    
    auto write_handler = [this, self](std::error_code ec, std::size_t /*length*/) {
        if (!ec) {
            write_queue_.pop_front();
            if (!write_queue_.empty()) {
                do_write();
            }
        } else if (ec != asio::error::operation_aborted) {
            if (logger_) logger_->error("[tls] stage=send status=failed msg=" + ec.message());
            stop();
        }
    };

    if (std::holds_alternative<Packet>(write_queue_.front())) {
        const auto& pkt = std::get<Packet>(write_queue_.front());
        // serialize_to_buffers returns vector of const_buffer, which is copyable and valid as long as pkt is alive
        asio::async_write(*stream_, pkt.serialize_to_buffers(), write_handler);
    } else {
        const auto& data = std::get<std::vector<uint8_t>>(write_queue_.front());
        asio::async_write(*stream_, asio::buffer(data), write_handler);
    }
}

bool TlsTransportAdapter::is_connected() const noexcept {
    return running_.load() && handshake_complete_.load() && stream_ && stream_->lowest_layer().is_open();
}

void TlsTransportAdapter::do_handshake() {
    auto self = shared_from_this();
    
    // Set a timeout for the handshake
    auto timer = std::make_shared<asio::steady_timer>(io_context_);
    timer->expires_after(std::chrono::seconds(10));
    timer->async_wait([self, timer](const std::error_code& ec) {
        if (!ec) {
             if (self->logger_) self->logger_->error("[tls] stage=handshake status=failed detail=timeout");
             self->stop();
        }
    });

    stream_->async_handshake(asio::ssl::stream_base::client,
        [this, self, timer](std::error_code ec) {
            timer->cancel();
            if (!ec) {
                if (logger_) logger_->info("[tls] stage=handshake status=ok detail=client endpoint=" + remote_endpoint_);
                handshake_complete_ = true;
                if (!write_queue_.empty()) {
                    do_write();
                }
                do_receive();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) logger_->error("[tls] stage=handshake status=failed detail=client msg=" + ec.message());
                stop();
            }
        });
}

void TlsTransportAdapter::do_receive() {
    auto self = shared_from_this();

    // Always use BufferPool for receiving to support zero-copy
    auto block = clink::core::memory::BufferPool::instance()->acquire(8192);

    stream_->async_read_some(asio::buffer(block->write_ptr(), block->tailroom()),
        [this, self, block](std::error_code ec, std::size_t length) {
            if (!ec) {
                block->commit(length);

                if (zero_copy_callback_) {
                    zero_copy_callback_(block);
                } else if (receive_callback_) {
                    receive_callback_(block->begin(), length);
                }
                
                do_receive();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) {
                    logger_->info("[tls] stage=read status=closed msg=" + ec.message());
                }
                stop();
            }
        });
}

bool TlsTransportAdapter::verify_certificate(bool preverified, asio::ssl::verify_context& ctx) {
    std::string actual_digest;
    if (!tls_shared::verify_certificate_with_optional_pin(pinned_cert_hash_, preverified, ctx, &actual_digest)) {
        if (!pinned_cert_hash_.empty() && logger_) {
            logger_->error("[tls] certificate binding verification failed. expected: " + pinned_cert_hash_ + ", got: " + actual_digest);
        }
        return false;
    }

    return true;
}

// --- TlsTransportListener ---

TlsTransportListener::TlsTransportListener(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), logger_(std::move(logger)), 
      ssl_ctx_(std::make_shared<asio::ssl::context>(asio::ssl::context::tls_server)),
      acceptor_(io_context) {
    
    tls_shared::apply_server_context_options(*ssl_ctx_);
}

TlsTransportListener::~TlsTransportListener() {
    stop();
}

void TlsTransportListener::set_certificates(const std::string& ca_cert, const std::string& server_cert, const std::string& server_key) {
    ca_cert_path_ = ca_cert;
    server_cert_path_ = server_cert;
    server_key_path_ = server_key;

    if (!ca_cert_path_.empty() || !pinned_cert_hash_.empty()) {
        if (!ca_cert_path_.empty()) {
            ssl_ctx_->load_verify_file(ca_cert_path_);
        }
        ssl_ctx_->set_verify_callback([this](bool preverified, asio::ssl::verify_context& ctx) {
            if (logger_) logger_->info(std::string("[tls] stage=verify status=begin role=server preverified=") + (preverified ? "true" : "false"));
            if (!preverified) {
                const std::string subject = tls_shared::current_certificate_subject(ctx);
                if (!subject.empty()) {
                    if (logger_) logger_->warn(std::string("[tls] stage=verify status=failed role=server subject=") + subject);
                }
                if (logger_) logger_->warn(std::string("[tls] stage=verify status=failed role=server err=") + tls_shared::current_verify_error_message(ctx));
            }
            return this->verify_certificate(preverified, ctx);
        });
        ssl_ctx_->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    } else if (logger_) {
        logger_->warn("[tls] stage=verify status=disabled role=server reason=no_ca_or_pin");
    }

    if (!server_cert_path_.empty() && !server_key_path_.empty()) {
        tls_shared::load_certificate_chain_and_key(*ssl_ctx_, server_cert_path_, server_key_path_);
    }
}

bool TlsTransportListener::verify_certificate(bool preverified, asio::ssl::verify_context& ctx) {
    std::string actual_digest;
    if (!tls_shared::verify_certificate_with_optional_pin(pinned_cert_hash_, preverified, ctx, &actual_digest)) {
        if (!pinned_cert_hash_.empty() && logger_) {
            logger_->error("[tls] certificate binding verification failed. expected: " + pinned_cert_hash_ + ", got: " + actual_digest);
        }
        return false;
    }

    return true;
}

std::string TlsTransportListener::local_endpoint() const {
    if (!running_) return "";
    try {
        auto ep = acceptor_.local_endpoint();
        return tls_shared::format_endpoint(ep);
    } catch (...) {
        return "";
    }
}

std::error_code TlsTransportListener::listen(const std::string& endpoint) {
    if (running_) return {};

    listen_endpoint_ = endpoint;
    
    std::string ip;
    int port = 0;
    if (!tls_shared::parse_endpoint_host_port(endpoint, ip, port)) return std::make_error_code(std::errc::invalid_argument);

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
        logger_->info("[tls] stage=listen status=ok endpoint=" + endpoint);
    }

    do_accept();
    return {};
}

void TlsTransportListener::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (logger_) {
            logger_->info("[tls] stage=listen.stop status=begin endpoint=" + listen_endpoint_);
        }
        std::error_code ec;
        acceptor_.close(ec);
    }
}

void TlsTransportListener::on_connection(NewConnectionCallback callback) {
    connection_callback_ = std::move(callback);
}

void TlsTransportListener::do_accept() {
    std::shared_ptr<TlsTransportListener> self;
    try {
        self = shared_from_this();
    } catch (const std::bad_weak_ptr&) {
        if (logger_) logger_->warn("[tls] stage=accept self_reference=unavailable");
    }

    acceptor_.async_accept(io_context_,
        [this, self](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                if (logger_) {
                    std::string remote = tls_shared::remote_endpoint_or_unknown(socket);
                    logger_->info("[tls] stage=accept status=ok remote=" + remote);
                }

                socket.set_option(asio::ip::tcp::no_delay(true));
                auto stream = std::make_shared<asio::ssl::stream<asio::ip::tcp::socket>>(std::move(socket), *ssl_ctx_);

                if (logger_) logger_->info("[tls] stage=handshake status=begin role=server");

                auto timer = std::make_shared<asio::steady_timer>(io_context_);
                timer->expires_after(std::chrono::seconds(10));
                timer->async_wait([this, stream](const std::error_code& ec) {
                    if (!ec) {
                        if (logger_) logger_->warn("[tls] stage=handshake status=failed detail=timeout role=server");
                        std::error_code ignore;
                        stream->lowest_layer().close(ignore);
                    }
                });

                stream->async_handshake(asio::ssl::stream_base::server,
                    [this, self, stream, timer](std::error_code ec) {
                        timer->cancel();
                        if (!ec) {
                            if (logger_) logger_->info("[tls] stage=handshake status=ok role=server");
                            if (connection_callback_) {
                                auto adapter = std::make_shared<TlsTransportAdapter>(io_context_, logger_, std::move(*stream), ssl_ctx_);
                                adapter->start_accepted();
                                connection_callback_(std::move(adapter));
                            }
                        } else {
                            if (logger_) {
                                logger_->error("[tls] stage=handshake status=failed role=server msg=" + ec.message());
                            }
                        }
                    });

                do_accept();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) {
                    logger_->error("[tls] stage=accept status=failed msg=" + ec.message());
                }
            }
        });
}

} // namespace clink::core::network
