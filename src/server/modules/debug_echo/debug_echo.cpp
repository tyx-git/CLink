// Debug Echo Module implementation (v1.3.0)
// Simple TCP echo server for tunnel data path validation.
// Clients send data through the tunnel to the echo port on the server.
#include "src/server/modules/debug_echo/debug_echo.hpp"

namespace clink::debug {

DebugEchoServer::DebugEchoServer(asio::io_context& io, uint16_t port)
    : io_(io), acceptor_(io), port_(port) {}

DebugEchoServer::~DebugEchoServer() { stop(); }

void DebugEchoServer::start() {
    if (running_.exchange(true)) return;
    asio::ip::tcp::endpoint ep(asio::ip::tcp::v4(), port_);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();
    port_ = acceptor_.local_endpoint().port();
    std::cout << "[debug_echo] Echo server v1.3.0 on port " << port_ << std::endl;
    do_accept();
}

void DebugEchoServer::stop() {
    if (!running_.exchange(false)) return;
    std::error_code ec;
    acceptor_.close(ec);
    std::cout << "[debug_echo] Stopped" << std::endl;
}

void DebugEchoServer::do_accept() {
    if (!running_.load()) return;
    auto sock = std::make_shared<asio::ip::tcp::socket>(io_);
    acceptor_.async_accept(*sock, [this, sock](std::error_code ec) {
        if (!ec && running_.load()) {
            std::cout << "[debug_echo] Connection from "
                      << sock->remote_endpoint().address().to_string()
                      << ":" << sock->remote_endpoint().port() << std::endl;
            handle_session(std::move(sock));
        }
        do_accept();
    });
}

void DebugEchoServer::handle_session(std::shared_ptr<asio::ip::tcp::socket> sock) {
    auto buf = std::make_shared<std::vector<uint8_t>>(4096);
    auto self = shared_from_this();
    sock->async_read_some(asio::buffer(*buf), [self, sock, buf](std::error_code ec, size_t len) {
        if (ec) {
            if (ec != asio::error::eof && ec != asio::error::operation_aborted) {
                std::cerr << "[debug_echo] Read error: " << ec.message() << std::endl;
            }
            std::error_code ignored;
            sock->close(ignored);
            return;
        }
        std::string received(reinterpret_cast<const char*>(buf->data()), len);
        std::cout << "[debug_echo] Got " << len << " bytes: " << received << std::endl;
        // Echo with v1.3.0 debug prefix
        std::string response = "ECHO_v1.3.0[" + std::to_string(len) + "]: " + received;
        auto resp_buf = std::make_shared<std::string>(std::move(response));
        asio::async_write(*sock, asio::buffer(*resp_buf),
            [sock, resp_buf](std::error_code wec, size_t) {
                if (wec) std::cerr << "[debug_echo] Write error: " << wec.message() << std::endl;
                std::error_code ignored;
                sock->close(ignored);
            });
    });
}

} // namespace clink::debug
