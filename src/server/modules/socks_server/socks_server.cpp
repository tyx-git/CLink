#include "src/server/modules/socks_server/socks_server.hpp"
#include "src/server/core/network/vip_bind.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

namespace clink::server::modules {

bool should_bind_to_virtual_interface_for_socks(const std::string& vip) {
    return clink::core::network::should_bind_to_virtual_interface(vip);
}

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
    // RFC1928 greeting: VER, NMETHODS, METHODS...
    auto self(shared_from_this());
    asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), 2),
        [this, self](std::error_code ec, std::size_t) {
            if (ec || client_buffer_[0] != 0x05) {
                close();
                return;
            }

            const uint8_t nmethods = client_buffer_[1];
            if (nmethods == 0) {
                close();
                return;
            }

            asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), nmethods),
                [this, self](std::error_code ec2, std::size_t) {
                    if (ec2) {
                        close();
                        return;
                    }

                    // No-auth only
                    static const uint8_t response[] = {0x05, 0x00};
                    asio::async_write(client_socket_, asio::buffer(response),
                        [this, self](std::error_code ec3, std::size_t) {
                            if (!ec3) {
                                do_request();
                            } else {
                                close();
                            }
                        });
                });
        });
}

void SocksSession::do_request() {
    // RFC1928 request header: VER, CMD, RSV, ATYP
    auto self(shared_from_this());
    asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), 4),
        [this, self](std::error_code ec, std::size_t) {
            if (ec || client_buffer_[0] != 0x05) {
                close();
                return;
            }

            if (client_buffer_[1] != 0x01) {
                static const uint8_t response[] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                asio::async_write(client_socket_, asio::buffer(response),
                    [this, self](std::error_code, std::size_t) { close(); });
                return;
            }

            const uint8_t atyp = client_buffer_[3];
            if (atyp == 0x01) { // IPv4 + port(2)
                asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), 6),
                    [this, self](std::error_code ec2, std::size_t) {
                        if (ec2) {
                            close();
                            return;
                        }

                        asio::ip::address_v4::bytes_type bytes{};
                        std::copy_n(client_buffer_.begin(), 4, bytes.begin());
                        const std::string host = asio::ip::address_v4(bytes).to_string();
                        const uint16_t port = static_cast<uint16_t>((client_buffer_[4] << 8) | client_buffer_[5]);
                        remote_host_ = host;
                        remote_port_ = port;
                        if (logger_) {
                            logger_->info("SOCKS Connect request to " + host + ":" + std::to_string(port));
                        }
                        do_connect(host, std::to_string(port));
                    });
                return;
            }

            if (atyp == 0x04) { // IPv6 + port(2)
                asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), 18),
                    [this, self](std::error_code ec2, std::size_t) {
                        if (ec2) {
                            close();
                            return;
                        }

                        asio::ip::address_v6::bytes_type bytes{};
                        std::copy_n(client_buffer_.begin(), 16, bytes.begin());
                        const std::string host = asio::ip::address_v6(bytes).to_string();
                        const uint16_t port = static_cast<uint16_t>((client_buffer_[16] << 8) | client_buffer_[17]);
                        remote_host_ = host;
                        remote_port_ = port;
                        if (logger_) {
                            logger_->info("SOCKS Connect request to " + host + ":" + std::to_string(port));
                        }
                        do_connect(host, std::to_string(port));
                    });
                return;
            }

            if (atyp == 0x03) { // DOMAIN
                asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), 1),
                    [this, self](std::error_code ec2, std::size_t) {
                        if (ec2) {
                            close();
                            return;
                        }

                        const uint8_t domain_len = client_buffer_[0];
                        if (domain_len == 0 || domain_len > 253) {
                            close();
                            return;
                        }

                        asio::async_read(client_socket_, asio::buffer(client_buffer_.data(), static_cast<size_t>(domain_len) + 2),
                            [this, self, domain_len](std::error_code ec3, std::size_t) {
                                if (ec3) {
                                    close();
                                    return;
                                }

                                const std::string host(reinterpret_cast<char*>(client_buffer_.data()), domain_len);
                                const uint16_t port = static_cast<uint16_t>((client_buffer_[domain_len] << 8) | client_buffer_[domain_len + 1]);
                                remote_host_ = host;
                                remote_port_ = port;
                                if (logger_) {
                                    logger_->info("SOCKS Connect request to " + host + ":" + std::to_string(port));
                                }
                                do_connect(host, std::to_string(port));
                            });
                    });
                return;
            }

            close();
        });
}

void SocksSession::do_connect(std::string host, std::string port) {
    auto self(shared_from_this());
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(io_context_);
    resolver->async_resolve(host, port,
        [this, self, resolver](std::error_code ec, asio::ip::tcp::resolver::results_type results) {
            if (ec || results.empty()) {
                static const uint8_t response[] = {0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                asio::async_write(client_socket_, asio::buffer(response),
                    [this, self](std::error_code, std::size_t) { close(); });
                return;
            }

            auto connect_results = results;

            if (session_manager_) {
                const std::string vip = session_manager_->get_virtual_interface_address();
                auto bind_addr = clink::core::network::parse_bind_address(vip, logger_, "[socks]");
                if (bind_addr) {
                    auto filtered = clink::core::network::filter_results_for_bind_address(results, *bind_addr);
                    if (filtered.empty()) {
                        if (logger_) {
                            logger_->warn("[socks] no remote endpoints match VIP address family vip=" + bind_addr->to_string());
                        }
                    } else if (clink::core::network::bind_socket_to_virtual_interface(remote_socket_, *bind_addr, logger_, "[socks]")) {
                        connect_results = std::move(filtered);
                    }
                }
            }

            asio::async_connect(remote_socket_, connect_results,
                [this, self](std::error_code ec2, asio::ip::tcp::endpoint) {
                    if (!ec2) {
                        static const uint8_t response[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                        asio::async_write(client_socket_, asio::buffer(response),
                            [this, self](std::error_code ec3, std::size_t) {
                                if (!ec3) {
                                    do_bridge();
                                } else {
                                    close();
                                }
                            });
                    } else {
                        static const uint8_t response[] = {0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
                        asio::async_write(client_socket_, asio::buffer(response),
                            [this, self](std::error_code, std::size_t) { close(); });
                    }
                });
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
    if (client_socket_.is_open()) {
        client_socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
        client_socket_.close(ignored_ec);
    }
    if (remote_socket_.is_open()) {
        remote_socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored_ec);
        remote_socket_.close(ignored_ec);
    }
}

// SocksServer Implementation

SocksServer::SocksServer(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager)
    : io_context_(io_context), logger_(std::move(logger)), session_manager_(std::move(session_manager)) {}

SocksServer::~SocksServer() {
    stop();
}

bool SocksServer::start(uint16_t port, const std::string& backend) {
    try {
        if (logger_) {
            logger_->info("[socks] stage=start.begin requested_port backend", port, backend);
        }

        if ((acceptor_ && acceptor_->is_open())
#ifdef _WIN32
            || winsock_running_.load()
#endif
        ) {
            if (logger_) {
                logger_->warn("[socks] stage=start.skip already_running bound_port", port_);
            }
            return true;
        }

        auto cleanup_on_failure = [this]() {
            close_acceptor();
            port_ = 0;
        };

#if defined(_WIN32)
        WSADATA wsa_data{};
        const int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);
        if (logger_) {
            logger_->info("[socks] stage=winsock_probe.rc={}", wsa_rc);
        }
        if (wsa_rc == 0) {
            SOCKET probe = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (probe == INVALID_SOCKET) {
                if (logger_) {
                    logger_->warn("[socks] stage=socket_probe.failed wsa={}", WSAGetLastError());
                }
            } else {
                if (logger_) {
                    logger_->info("[socks] stage=socket_probe.ok");
                }
                closesocket(probe);
            }
            WSACleanup();
        }
#endif

        asio::ip::tcp::endpoint endpoint(asio::ip::tcp::v6(), port);

        std::string backend_mode = backend;
        std::transform(backend_mode.begin(), backend_mode.end(), backend_mode.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

#ifdef _WIN32
        const bool force_winsock = (backend_mode == "winsock");
        const bool force_asio = (backend_mode == "asio");
        const bool auto_backend = (backend_mode.empty() || backend_mode == "auto");
        if (force_winsock) {
            return start_winsock_backend(port);
        }

        // On Windows, Asio constructor path has known toolchain-specific instability in some environments.
        // Prefer WinSock first in auto mode to maximize availability, then fall back to Asio only if needed.
        if (auto_backend) {
            if (start_winsock_backend(port)) {
                return true;
            }
            if (logger_) {
                logger_->warn("[socks] stage=fallback.asio.begin reason=winsock_start_failed");
            }
        }

        (void)force_asio;
#else
        const bool auto_backend = (backend_mode.empty() || backend_mode == "auto");
        if (backend_mode == "winsock") {
            if (logger_) {
                logger_->warn("[socks] stage=backend.override.unsupported backend=winsock platform=non_windows fallback=asio");
            }
        } else if (!auto_backend && backend_mode != "asio") {
            if (logger_) {
                logger_->warn("[socks] stage=backend.unknown value platform=non_windows fallback=asio", backend_mode);
            }
        }
#endif

        if (logger_) {
            logger_->info("[socks] stage=acceptor.alloc.begin");
        }
        if (!acceptor_) {
            acceptor_ = std::make_unique<asio::ip::tcp::acceptor>(io_context_);
        }
        if (logger_) {
            logger_->info("[socks] stage=acceptor.alloc.ok ptr={}", static_cast<const void*>(acceptor_.get()));
        }

        asio::error_code ec;

        if (logger_) {
            logger_->info("[socks] stage=acceptor.open.begin");
        }
        acceptor_->open(endpoint.protocol(), ec);
        if (ec) {
            if (logger_) {
                logger_->error("[socks] stage=acceptor.open.failed error", ec.message());
            }
            cleanup_on_failure();
#ifdef _WIN32
            if (auto_backend) {
                if (logger_) {
                    logger_->warn("[socks] stage=fallback.winsock.begin reason=acceptor_open_failed");
                }
                return start_winsock_backend(port);
            }
#endif
            return false;
        }
        if (logger_) {
            logger_->info("[socks] stage=acceptor.open.ok");
        }

        if (endpoint.address().is_v6()) {
            asio::ip::v6_only v6_only(false);
            acceptor_->set_option(v6_only, ec);
            if (ec) {
                if (logger_) {
                    logger_->warn("[socks] stage=acceptor.dual_stack.failed error={}", ec.message());
                }
                ec.clear();
            } else if (logger_) {
                logger_->info("[socks] stage=acceptor.dual_stack.ok");
            }
        }

        if (logger_) {
            logger_->info("[socks] stage=acceptor.set_reuse.begin");
        }
        acceptor_->set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
        if (ec) {
            if (logger_) {
                logger_->warn("[socks] stage=acceptor.set_reuse.failed error={}", ec.message());
            }
            ec.clear();
        } else if (logger_) {
            logger_->info("[socks] stage=acceptor.set_reuse.ok");
        }

        if (logger_) {
            logger_->info("[socks] stage=acceptor.bind.begin endpoint=[::]:{} dual_stack=true", port);
        }
        acceptor_->bind(endpoint, ec);
        if (ec) {
            if (logger_) {
                logger_->error("[socks] stage=acceptor.bind.failed error", ec.message());
            }
            cleanup_on_failure();
#ifdef _WIN32
            if (auto_backend) {
                if (logger_) {
                    logger_->warn("[socks] stage=fallback.winsock.begin reason=acceptor_bind_failed");
                }
                return start_winsock_backend(port);
            }
#endif
            return false;
        }
        if (logger_) {
            logger_->info("[socks] stage=acceptor.bind.ok");
        }

        if (logger_) {
            logger_->info("[socks] stage=acceptor.listen.begin");
        }
        acceptor_->listen(asio::socket_base::max_listen_connections, ec);
        if (ec) {
            if (logger_) {
                logger_->error("[socks] stage=acceptor.listen.failed error", ec.message());
            }
            cleanup_on_failure();
#ifdef _WIN32
            if (auto_backend) {
                if (logger_) {
                    logger_->warn("[socks] stage=fallback.winsock.begin reason=acceptor_listen_failed");
                }
                return start_winsock_backend(port);
            }
#endif
            return false;
        }
        if (logger_) {
            logger_->info("[socks] stage=acceptor.listen.ok");
        }

        port_ = acceptor_->local_endpoint(ec).port();
        if (ec) {
            if (logger_) {
                logger_->error("[socks] stage=acceptor.local_endpoint.failed error={}", ec.message());
            }
            cleanup_on_failure();
            return false;
        }

        if (logger_) {
            logger_->info("[socks] stage=start.ok bound_port backend", port_, "asio");
        }
        backend_ = Backend::Asio;
        do_accept();
        return true;
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->error("[socks] stage=start.exception error={}", e.what());
        }
        close_acceptor();
        port_ = 0;
        return false;
    } catch (...) {
        if (logger_) {
            logger_->error("[socks] stage=start.exception error=unknown");
        }
        close_acceptor();
        port_ = 0;
        return false;
    }
}

void SocksServer::stop() {
    close_acceptor();
#ifdef _WIN32
    stop_winsock_backend();
#endif
    backend_ = Backend::None;
    port_ = 0;
}

void SocksServer::close_acceptor() {
    if (!acceptor_) {
        return;
    }

    asio::error_code ec;
    acceptor_->cancel(ec);
    acceptor_->close(ec);
    acceptor_.reset();
}

uint16_t SocksServer::port() const {
    return port_;
}

#ifdef _WIN32
bool SocksServer::start_winsock_backend(uint16_t port) {
    WSADATA wsa_data{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        if (logger_) {
            logger_->error("[socks] stage=fallback.winsock.wsa_startup.failed");
        }
        return false;
    }

    SOCKET listen_sock = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock == INVALID_SOCKET) {
        if (logger_) {
            logger_->error("[socks] stage=fallback.winsock.socket.failed", WSAGetLastError());
        }
        WSACleanup();
        return false;
    }

    BOOL opt = TRUE;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    DWORD v6_only = 0;
    setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6_only), sizeof(v6_only));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (::bind(listen_sock, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (logger_) {
            logger_->error("[socks] stage=fallback.winsock.bind.failed", WSAGetLastError());
        }
        closesocket(listen_sock);
        WSACleanup();
        return false;
    }

    if (::listen(listen_sock, SOMAXCONN) != 0) {
        if (logger_) {
            logger_->error("[socks] stage=fallback.winsock.listen.failed", WSAGetLastError());
        }
        closesocket(listen_sock);
        WSACleanup();
        return false;
    }

    sockaddr_in6 local{};
    int local_len = sizeof(local);
    if (getsockname(listen_sock, reinterpret_cast<sockaddr*>(&local), &local_len) == 0) {
        port_ = ntohs(local.sin6_port);
    } else {
        port_ = port;
    }

    winsock_listen_socket_ = static_cast<uintptr_t>(listen_sock);
    winsock_work_guard_.emplace(asio::make_work_guard(io_context_));
    winsock_accepting_ = std::make_shared<std::atomic<bool>>(true);
    winsock_running_.store(true);
    backend_ = Backend::WinSock;

    winsock_accept_thread_ = std::thread([this]() { winsock_accept_loop(); });

    if (logger_) {
        logger_->warn("[socks] stage=start.ok bound_port backend", port_, "winsock");
    }
    return true;
}

void SocksServer::stop_winsock_backend() {
    if (!winsock_running_.exchange(false)) {
        if (winsock_accepting_) {
            winsock_accepting_->store(false);
        }
        return;
    }

    if (winsock_accepting_) {
        winsock_accepting_->store(false);
    }

    const SOCKET s = static_cast<SOCKET>(winsock_listen_socket_);
    if (s != 0 && s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
    winsock_listen_socket_ = 0;
    winsock_work_guard_.reset();

    if (winsock_accept_thread_.joinable()) {
        winsock_accept_thread_.join();
    }

    WSACleanup();
}

void SocksServer::winsock_accept_loop() {
    const SOCKET s = static_cast<SOCKET>(winsock_listen_socket_);
    while (winsock_running_.load()) {
        sockaddr_storage peer_addr{};
        int peer_len = sizeof(peer_addr);
        SOCKET client = ::accept(s, reinterpret_cast<sockaddr*>(&peer_addr), &peer_len);
        if (client == INVALID_SOCKET) {
            const int wsa_err = WSAGetLastError();
            if (!winsock_running_.load()) {
                break;
            }
            if (logger_) {
                logger_->warn("[socks] stage=fallback.winsock.accept.failed", wsa_err);
            }
            continue;
        }

        if (logger_) {
            char host[NI_MAXHOST] = {0};
            char serv[NI_MAXSERV] = {0};
            if (getnameinfo(reinterpret_cast<sockaddr*>(&peer_addr), peer_len,
                            host, sizeof(host), serv, sizeof(serv),
                            NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                logger_->debug("[socks] stage=fallback.winsock.accept.ok remote", std::string(host) + ":" + std::string(serv));
            } else {
                logger_->debug("[socks] stage=fallback.winsock.accept.ok remote=unknown");
            }
        }

        auto accepting = winsock_accepting_;
        auto logger = logger_;
        auto session_manager = session_manager_;
        auto& io_context = io_context_;
        asio::post(io_context_, [client, accepting, logger, session_manager, &io_context]() {
            if (!accepting || !accepting->load()) {
                closesocket(client);
                return;
            }

            asio::error_code ec;
            asio::ip::tcp::socket socket(io_context);
            socket.assign(asio::ip::tcp::v6(), client, ec);
            if (ec) {
                closesocket(client);
                if (logger) {
                    logger->warn("[socks] stage=fallback.winsock.assign.failed", ec.message());
                }
                return;
            }
            std::make_shared<SocksSession>(io_context, std::move(socket), logger, session_manager)->start();
        });
    }
}
#endif

void SocksServer::do_accept() {
    if (!acceptor_ || !acceptor_->is_open()) {
        return;
    }

    auto self = shared_from_this();
    if (logger_) {
        logger_->debug("[socks] stage=accept.wait");
    }

    acceptor_->async_accept(
        [self](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                if (self->logger_) {
                    asio::error_code rep_ec;
                    const auto rep = socket.remote_endpoint(rep_ec);
                    if (!rep_ec) {
                        self->logger_->debug("[socks] stage=accept.ok remote={}", rep.address().to_string());
                    } else {
                        self->logger_->debug("[socks] stage=accept.ok remote=unknown({})", rep_ec.message());
                    }
                }
                std::make_shared<SocksSession>(self->io_context_, std::move(socket), self->logger_, self->session_manager_)->start();
            } else if (self->logger_) {
                self->logger_->warn("[socks] stage=accept.failed error={}", ec.message());
            }

            if (self->acceptor_ && self->acceptor_->is_open()) {
                self->do_accept();
            }
        });
}

} // namespace clink::server::modules
