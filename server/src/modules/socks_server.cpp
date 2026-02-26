#include "server/include/clink/server/modules/socks_server.hpp"

namespace clink::server::modules {

SocksSession::SocksSession(asio::io_context& io_context, asio::ip::tcp::socket socket, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager)
    : io_context_(io_context),
      client_socket_(std::move(socket)),
      remote_socket_(io_context),
      logger_(std::move(logger)),
      session_manager_(std::move(session_manager)) {}

void SocksSession::start() {
    do_handshake();
}

void SocksSession::do_handshake() {
    // Read version (1 byte) + nmethods (1 byte) + methods (n bytes)
    // Minimal: 1 + 1 + n >= 3
    auto self(shared_from_this());
    client_socket_.async_read_some(asio::buffer(client_buffer_),
        [this, self](std::error_code ec, std::size_t length) {
            if (!ec && length >= 2 && client_buffer_[0] == 0x05) {
                // Ignore methods for now, assume No Auth
                // Respond: VER=5, METHOD=0 (No Auth)
                static const uint8_t response[] = {0x05, 0x00};
                asio::async_write(client_socket_, asio::buffer(response),
                    [this, self](std::error_code ec, std::size_t) {
                        if (!ec) {
                            do_request();
                        } else {
                            close();
                        }
                    });
            } else {
                close();
            }
        });
}

void SocksSession::do_request() {
    // Read Request: VER=5, CMD=1(Connect), RSV=0, ATYP=1(IPv4)/3(Domain)/4(IPv6), DST.ADDR, DST.PORT
    auto self(shared_from_this());
    client_socket_.async_read_some(asio::buffer(client_buffer_),
        [this, self](std::error_code ec, std::size_t length) {
            if (ec || length < 4 || client_buffer_[0] != 0x05 || client_buffer_[1] != 0x01) {
                // Only support CONNECT
                close();
                return;
            }

            uint8_t atyp = client_buffer_[3];
            std::string host;
            uint16_t port;
            size_t addr_len = 0;

            if (atyp == 0x01) { // IPv4
                if (length < 10) { close(); return; }
                asio::ip::address_v4::bytes_type bytes;
                std::copy_n(client_buffer_.begin() + 4, 4, bytes.begin());
                host = asio::ip::address_v4(bytes).to_string();
                addr_len = 4;
            } else if (atyp == 0x03) { // Domain
                uint8_t domain_len = client_buffer_[4];
                if (length < static_cast<size_t>(5 + domain_len + 2)) { close(); return; }
                host = std::string(reinterpret_cast<char*>(&client_buffer_[5]), domain_len);
                addr_len = 1 + domain_len;
            } else if (atyp == 0x04) { // IPv6
                if (length < 22) { close(); return; }
                asio::ip::address_v6::bytes_type bytes;
                std::copy_n(client_buffer_.begin() + 4, 16, bytes.begin());
                host = asio::ip::address_v6(bytes).to_string();
                addr_len = 16;
            } else {
                close();
                return;
            }

            port = (client_buffer_[4 + addr_len] << 8) | client_buffer_[4 + addr_len + 1];
            remote_host_ = host;
            remote_port_ = port;

            logger_->info("SOCKS Connect request to " + host + ":" + std::to_string(port));

            // Reply Success (0x00) immediately, assuming we can connect
            // Wait, we should connect first?
            // Usually connect first, then reply.
            do_connect(host, std::to_string(port));
        });
}

void SocksSession::do_connect(std::string host, std::string port) {
    auto self(shared_from_this());
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io_context_);
    resolver->async_resolve(host, port,
        [this, self, resolver](std::error_code ec, asio::ip::tcp::resolver::results_type results) {
            if (!ec) {
                // If SessionManager is available and VIP is set, bind to it.
                if (session_manager_) {
                    std::string vip = session_manager_->get_virtual_interface_address();
                    if (!vip.empty()) {
                        asio::error_code bind_ec;
                        remote_socket_.open(asio::ip::tcp::v4(), bind_ec);
                        if (!bind_ec) {
                            remote_socket_.bind(asio::ip::tcp::endpoint(asio::ip::make_address(vip), 0), bind_ec);
                            if (bind_ec) {
                                logger_->warn("Failed to bind to VIP " + vip + ": " + bind_ec.message());
                            }
                        }
                    }
                }

                asio::async_connect(remote_socket_, results,
                    [this, self](std::error_code ec, asio::ip::tcp::endpoint) {
                        if (!ec) {
                            // Reply Success
                            // VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR(0), BND.PORT(0)
                            static const uint8_t response[] = {
                                0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0
                            };
                            asio::async_write(client_socket_, asio::buffer(response),
                                [this, self](std::error_code ec, std::size_t) {
                                    if (!ec) {
                                        do_bridge();
                                    } else {
                                        close();
                                    }
                                });
                        } else {
                            // Reply Failure (0x04 Host Unreachable)
                            static const uint8_t response[] = {
                                0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0
                            };
                            asio::async_write(client_socket_, asio::buffer(response),
                                [this, self](std::error_code, std::size_t) { close(); });
                        }
                    });
            } else {
                close();
            }
        });
}

void SocksSession::do_bridge() {
    do_read_client();
    do_read_remote();
}

void SocksSession::do_read_client() {
    auto self(shared_from_this());
    client_socket_.async_read_some(asio::buffer(client_buffer_),
        [this, self](std::error_code ec, std::size_t length) {
            if (!ec) {
                asio::async_write(remote_socket_, asio::buffer(client_buffer_, length),
                    [this, self](std::error_code ec, std::size_t) {
                        if (!ec) {
                            do_read_client();
                        } else {
                            close();
                        }
                    });
            } else {
                close();
            }
        });
}

void SocksSession::do_read_remote() {
    auto self(shared_from_this());
    remote_socket_.async_read_some(asio::buffer(remote_buffer_),
        [this, self](std::error_code ec, std::size_t length) {
            if (!ec) {
                asio::async_write(client_socket_, asio::buffer(remote_buffer_, length),
                    [this, self](std::error_code ec, std::size_t) {
                        if (!ec) {
                            do_read_remote();
                        } else {
                            close();
                        }
                    });
            } else {
                close();
            }
        });
}

void SocksSession::close() {
    asio::error_code ignored_ec;
    client_socket_.close(ignored_ec);
    remote_socket_.close(ignored_ec);
}

// SocksServer Implementation

SocksServer::SocksServer(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager)
    : io_context_(io_context), acceptor_(io_context), logger_(std::move(logger)), session_manager_(std::move(session_manager)) {}

SocksServer::~SocksServer() {
    stop();
}

bool SocksServer::start(uint16_t port) {
    try {
        asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v4(), port);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        port_ = acceptor_.local_endpoint().port();
        
        logger_->info("SOCKS5 Server started on port " + std::to_string(port_));
        
        do_accept();
        return true;
    } catch (std::exception& e) {
        logger_->error("Failed to start SOCKS5 Server: " + std::string(e.what()));
        return false;
    }
}

void SocksServer::stop() {
    acceptor_.close();
}

uint16_t SocksServer::port() const {
    return port_;
}

void SocksServer::do_accept() {
    acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                std::make_shared<SocksSession>(io_context_, std::move(socket), logger_, session_manager_)->start();
            } else {
                logger_->warn("Socks accept failed: " + ec.message());
            }
            if (acceptor_.is_open()) {
                do_accept();
            }
        });
}

} // namespace clink::server::modules
