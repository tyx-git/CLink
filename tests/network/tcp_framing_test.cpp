#include <catch2/catch_test_macros.hpp>
#include "src/server/core/network/tcp_adapter.hpp"
#include <asio.hpp>
#include <thread>
#include <future>
#include <vector>
#include <cstring>
#include <iostream>
#include <chrono>
#include <stdexcept>

using namespace clink::core::network;

TEST_CASE("TcpTransportAdapter Framing", "[network][tcp]") {
        asio::io_context io_context;
        auto logger = std::make_shared<clink::core::logging::Logger>("test");
    
    asio::ip::tcp::acceptor acceptor(
        io_context,
        asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0));
    const auto port = acceptor.local_endpoint().port();

    std::promise<std::shared_ptr<TcpTransportAdapter>> server_adapter_promise;
    auto server_adapter_future = server_adapter_promise.get_future();

    std::jthread io_thread([&](std::stop_token st) {
        std::stop_callback cb(st, [&]() {
            io_context.stop();
        });

        asio::ip::tcp::socket server_socket(io_context);
        asio::error_code accept_ec;
        acceptor.accept(server_socket, accept_ec);
        if (accept_ec) {
            server_adapter_promise.set_exception(
                std::make_exception_ptr(std::runtime_error(accept_ec.message())));
            return;
        }

        auto adapter = std::make_shared<TcpTransportAdapter>(io_context, logger, std::move(server_socket));
        adapter->start();
        server_adapter_promise.set_value(adapter);
        io_context.run();
    });

    // Create a raw socket client to send fragmented data
    asio::io_context client_ioc;
    asio::ip::tcp::socket client_socket(client_ioc);
    asio::ip::tcp::endpoint server_ep(asio::ip::make_address("127.0.0.1"), port);

    asio::error_code connect_ec;
    client_socket.connect(server_ep, connect_ec);
    REQUIRE_FALSE(connect_ec);

    // Wait for server to accept
    auto server_adapter = server_adapter_future.get();
    REQUIRE(server_adapter != nullptr);
    
    // Setup server receive
    std::vector<uint8_t> received_data;
    std::promise<void> receive_promise;
    auto receive_future = receive_promise.get_future();
    
    server_adapter->on_receive([&](const uint8_t* data, size_t size) {
        received_data.insert(received_data.end(), data, data + size);
        if (received_data.size() >= 5) { // "Hello"
            receive_promise.set_value();
        }
    });
    
    // Construct a packet
    PacketHeader header;
    std::memset(&header, 0, sizeof(header));
    std::string payload = "Hello";
    header.payload_size = static_cast<uint16_t>(payload.size());
    // header.magic = 0xCLINK; // No magic in core::network::PacketHeader
    
    std::vector<uint8_t> buffer(sizeof(header) + payload.size());
    std::memcpy(buffer.data(), &header, sizeof(header));
    std::memcpy(buffer.data() + sizeof(header), payload.data(), payload.size());
    
    // Send byte by byte to simulate extreme fragmentation
    for (size_t i = 0; i < buffer.size(); ++i) {
        asio::write(client_socket, asio::buffer(&buffer[i], 1));
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    // Wait for receive
    auto status = receive_future.wait_for(std::chrono::seconds(5));
    REQUIRE(status == std::future_status::ready);
    
    // Verify data
            std::string received_str(received_data.begin(), received_data.end());

            // TcpTransportAdapter passes the full packet (header + payload) to the callback.
            // We need to verify the header and the payload.
            
            size_t expected_size = sizeof(PacketHeader) + 5;
            REQUIRE(received_str.size() == expected_size);
            
            // Verify header
            const PacketHeader* recv_header = reinterpret_cast<const PacketHeader*>(received_str.data());
            REQUIRE(recv_header->payload_size == 5);
            
            // Verify payload
            std::string recv_payload = received_str.substr(sizeof(PacketHeader));
            REQUIRE(recv_payload == "Hello");
            
            // Cleanup handled by RAII
        }

TEST_CASE("TcpTransportListener wildcard bind accepts IPv4 and IPv6 clients", "[network][tcp][listener][ipv6]") {
    asio::io_context probe_io;
    asio::ip::tcp::acceptor probe(
        probe_io,
        asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    const auto port = probe.local_endpoint().port();
    probe.close();

    asio::io_context io;
    auto logger = std::make_shared<clink::core::logging::Logger>("tcp-listener-dual-stack-test");
    auto listener = std::make_shared<clink::core::network::TcpTransportListener>(io, logger);

    std::promise<void> accepted_promise;
    auto accepted_future = accepted_promise.get_future();
    listener->on_connection([&](clink::core::network::TransportAdapterPtr adapter) {
        if (adapter) {
            accepted_promise.set_value();
        }
    });

    const auto listen_ec = listener->listen("0.0.0.0:" + std::to_string(port));
    REQUIRE_FALSE(listen_ec);

    std::jthread io_thread([&]() {
        io.run();
    });

    asio::io_context client_io;
    asio::ip::tcp::socket ipv6_client(client_io);
    asio::error_code connect_ec;
    ipv6_client.connect(
        asio::ip::tcp::endpoint(asio::ip::address_v6::loopback(), port),
        connect_ec);
    if (connect_ec == asio::error::address_family_not_supported ||
        connect_ec == asio::error::network_unreachable) {
        WARN("IPv6 loopback is unavailable on this platform: " << connect_ec.message());
        listener->stop();
        io.stop();
        return;
    }
    REQUIRE_FALSE(connect_ec);
    CHECK(accepted_future.wait_for(std::chrono::seconds(2)) == std::future_status::ready);

    ipv6_client.close();
    listener->stop();
    io.stop();
}

TEST_CASE("TcpTransportListener can be stopped with a pending accept", "[network][tcp][listener]") {
    asio::io_context io;
    auto logger = std::make_shared<clink::core::logging::Logger>("tcp-listener-lifecycle-test");
    auto listener = std::make_shared<clink::core::network::TcpTransportListener>(io, logger);

    const auto ec = listener->listen("127.0.0.1:0");
    REQUIRE_FALSE(ec);

    listener->on_connection([](clink::core::network::TransportAdapterPtr) {
        FAIL("no connection should be accepted after listener stop");
    });

    listener->stop();
    listener.reset();

    CHECK_NOTHROW(io.run_for(std::chrono::milliseconds(50)));
}
