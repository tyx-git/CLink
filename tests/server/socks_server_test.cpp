#include <catch2/catch_test_macros.hpp>
#include "src/server/modules/socks_server/socks_server.hpp"
#include "src/server/core/network/vip_bind.hpp"
#include "src/share/core/logging/logger.hpp"
#include <asio.hpp>
#include <thread>
#include <future>
#include <iostream>
#include <cstdlib>
#include <chrono>
#include <vector>

using namespace clink::server::modules;
using namespace clink::core::logging;

class ScopedEnvVar {
public:
    ScopedEnvVar(const char* name, const char* value) : name_(name) {
#if defined(_WIN32)
        // Use _putenv (MSVCRT) rather than SetEnvironmentVariableA (Win32 API)
        // so that std::getenv (which reads the CRT block) picks up the change.
        const char* existing = std::getenv(name);
        if (existing) {
            old_value_ = existing;
        }
        std::string assign = name_ + "=" + value;
        // _putenv expects a pointer it can store; we must keep the buffer alive.
        // Allocate a copy that will be freed in the destructor.
        env_buf_ = assign;
        _putenv(env_buf_->c_str());
#else
        if (const char* existing = std::getenv(name)) {
            old_value_ = existing;
        }
        setenv(name, value, 1);
#endif
    }

    ~ScopedEnvVar() {
#if defined(_WIN32)
        // Restore previous value using _putenv.
        // The new env_buf_ replaces the old assignment in the CRT block.
        std::string restore;
        if (old_value_) {
            restore = name_ + "=" + *old_value_;
        } else {
            restore = name_ + "=";
        }
        env_buf_ = restore;
        _putenv(env_buf_->c_str());
#else
        if (old_value_) {
            setenv(name_.c_str(), old_value_->c_str(), 1);
        } else {
            unsetenv(name_.c_str());
        }
#endif
    }

private:
    std::string name_;
    std::optional<std::string> old_value_;
    std::optional<std::string> env_buf_;  // keeps the _putenv buffer alive
};

TEST_CASE("SocksSession skips VIP bind when VIF is disabled", "[socks]") {
    ScopedEnvVar disable_vif("CLINK_DISABLE_VIF", "1");

    CHECK_FALSE(should_bind_to_virtual_interface_for_socks("10.8.0.1"));
}

TEST_CASE("SocksSession allows VIP bind when VIF is enabled", "[socks]") {
    ScopedEnvVar enable_vif("CLINK_DISABLE_VIF", "0");

    CHECK(should_bind_to_virtual_interface_for_socks("10.8.0.1"));
    CHECK_FALSE(should_bind_to_virtual_interface_for_socks(""));
}

TEST_CASE("SocksSession filters remote endpoints to VIP address family", "[socks]") {
    std::vector<asio::ip::tcp::endpoint> endpoints{
        asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 80),
        asio::ip::tcp::endpoint(asio::ip::address_v6::loopback(), 80),
    };
    const auto mixed = asio::ip::tcp::resolver::results_type::create(
        endpoints.begin(), endpoints.end(), "localhost", "80");

    const auto filtered = clink::core::network::filter_results_for_bind_address(
        mixed, asio::ip::address_v4::loopback());

    REQUIRE_FALSE(filtered.empty());
    for (const auto& entry : filtered) {
        CHECK(entry.endpoint().address().is_v4());
    }
}

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
