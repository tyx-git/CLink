#include <catch2/catch_test_macros.hpp>
#include "clink/server/modules/socks_server.hpp"
#include "clink/core/logging/logger.hpp"
#include <asio.hpp>
#include <thread>
#include <future>
#include <iostream>

using namespace clink::server::modules;
using namespace clink::core::logging;

TEST_CASE("SocksServer Handshake and Connect", "[socks]") {
    asio::io_context io_context;
    auto logger = std::make_shared<Logger>("TestLogger");
    // logger->set_level(LogLevel::Debug); 

    SocksServer server(io_context, logger);
    // Run SOCKS server in background
    std::promise<uint16_t> port_promise;
    std::jthread server_thread([&]() {
        if (server.start(0)) {
            port_promise.set_value(server.port());
            std::cout << "Server thread starting io_context.run()" << std::endl;
            io_context.run();
            std::cout << "Server thread io_context.run() finished" << std::endl;
        } else {
            port_promise.set_exception(std::make_exception_ptr(std::runtime_error("Failed to start server")));
        }
    });

    uint16_t socks_port = port_promise.get_future().get();
    REQUIRE(socks_port > 0);

    // Client: Connect to SOCKS server
    asio::io_context client_io;
    asio::ip::tcp::socket client_socket(client_io);
    try {
        client_socket.connect(asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), socks_port));
        std::cout << "Client connected to " << socks_port << std::endl;
    } catch (const std::exception& e) {
        FAIL("Client connect failed: " << e.what());
    }

    // 1. Handshake
    // VER=5, NMETHODS=1, METHODS=[0]
    uint8_t handshake[] = {0x05, 0x01, 0x00};
    asio::write(client_socket, asio::buffer(handshake));

    uint8_t response[2];
    asio::error_code ec;
    size_t len = asio::read(client_socket, asio::buffer(response), ec);
    if (ec) {
        FAIL("Handshake read failed: " << ec.message());
    }
    REQUIRE(len == 2);
    REQUIRE(response[0] == 0x05);
    REQUIRE(response[1] == 0x00); // No Auth

    // Start a dummy echo server to connect TO
    asio::io_context echo_io;
    asio::ip::tcp::acceptor echo_acceptor(echo_io, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
    uint16_t echo_port = echo_acceptor.local_endpoint().port();
    
    std::promise<void> echo_ready;
    std::jthread echo_thread([&]() {
        echo_ready.set_value();
        asio::ip::tcp::socket socket(echo_io);
        echo_acceptor.accept(socket);
        
        char data[1024];
        asio::error_code ec;
        size_t len = socket.read_some(asio::buffer(data), ec);
        if (!ec) {
            asio::write(socket, asio::buffer(data, len));
        }
    });

    echo_ready.get_future().wait();

    // 2. Request CONNECT to Echo Server
    // VER=5, CMD=1, RSV=0, ATYP=1, DST.ADDR, DST.PORT
    std::vector<uint8_t> request = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1};
    request.push_back(static_cast<uint8_t>((echo_port >> 8) & 0xFF));
    request.push_back(static_cast<uint8_t>(echo_port & 0xFF));
    
    asio::write(client_socket, asio::buffer(request));

    uint8_t reply[10];
    len = asio::read(client_socket, asio::buffer(reply), ec);
    if (ec) {
        FAIL("Request read failed: " << ec.message());
    }
    REQUIRE(len == 10);
    REQUIRE(reply[0] == 0x05);
    REQUIRE(reply[1] == 0x00); // Success

    // 3. Send Data
    std::string msg = "Hello SOCKS";
    asio::write(client_socket, asio::buffer(msg));

    char buffer[1024];
    len = client_socket.read_some(asio::buffer(buffer));
    std::string received(buffer, len);
    REQUIRE(received == msg);

    // Cleanup
    server.stop();
    io_context.stop();
    if (server_thread.joinable()) server_thread.join();
    // if (echo_thread.joinable()) echo_thread.join();
}
