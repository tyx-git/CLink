#include <catch2/catch_test_macros.hpp>
#include "clink/core/network/tcp_adapter.hpp"
#include <asio.hpp>
#include <thread>
#include <future>
#include <vector>
#include <cstring>
#include <iostream>

using namespace clink::core::network;

TEST_CASE("TcpTransportAdapter Framing", "[network][tcp]") {
        asio::io_context io_context;
        auto logger = std::make_shared<clink::core::logging::Logger>("test");
    
    // Start a listener
    TcpTransportListener listener(io_context, logger);
    std::string endpoint = "127.0.0.1:0"; // Random port
    
    std::promise<std::string> port_promise;
    auto port_future = port_promise.get_future();
    
    std::promise<std::shared_ptr<TcpTransportAdapter>> server_adapter_promise;
    auto server_adapter_future = server_adapter_promise.get_future();
    
    listener.on_connection([&](std::shared_ptr<TransportAdapter> adapter) {
        auto tcp_adapter = std::dynamic_pointer_cast<TcpTransportAdapter>(adapter);
        server_adapter_promise.set_value(tcp_adapter);
    });
    
    // We need to bind first to get the port
    // But TcpTransportListener::listen binds and accepts.
    // We can't get the port easily unless we parse the log or modify listener.
    // Let's modify the test to use a known port or try to find a free one.
    // Or just let listener pick one and we need to find out what it is.
    // TcpTransportListener doesn't expose the port.
    // Wait, TcpTransportListener::listen takes an endpoint string.
    // If we pass "127.0.0.1:0", asio will pick a port.
    // But we don't know it.
    
    // Workaround: Use a random port between 50000 and 60000
    // Simple retry loop
    int port = 50000;
    std::error_code ec;
    while (port < 60000) {
        endpoint = "127.0.0.1:" + std::to_string(port);
        ec = listener.listen(endpoint);
        if (!ec) break;
        port++;
    }
    REQUIRE(!ec);
    
    // Start IO context in background
            std::jthread io_thread([&](std::stop_token st) {
                std::stop_callback cb(st, [&]() {
                    io_context.stop();
                });
                io_context.run();
            });
    
    // Create a raw socket client to send fragmented data
    asio::io_context client_ioc;
    asio::ip::tcp::socket client_socket(client_ioc);
    asio::ip::tcp::endpoint server_ep(asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(port));
    
    client_socket.connect(server_ep);
    
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
