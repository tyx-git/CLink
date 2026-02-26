#include <catch2/catch_test_macros.hpp>
#include "clink/core/network/tls_adapter.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <future>

using namespace clink::core::network;

// Helper to run shell commands
// int run_cmd(const std::string& cmd) {
//    return std::system(cmd.c_str());
// }

// Generate test certificates
// void generate_certs() {
// ...
// }

struct TlsTestContext {
    asio::io_context io_context;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard;
    std::thread io_thread;

    TlsTestContext() : work_guard(asio::make_work_guard(io_context)) {}

    void start_io() {
         io_thread = std::thread([this]() {
             asio::executor_work_guard<asio::io_context::executor_type> work_guard = asio::make_work_guard(io_context);
             std::cout << "IO Context starting..." << std::endl;
             io_context.run();
             std::cout << "IO Context stopped." << std::endl;
         });
    }

    ~TlsTestContext() {
        io_context.stop();
        if (io_thread.joinable()) {
            io_thread.join();
        }
    }
};

TEST_CASE("TLS Adapter Connection and Data Transfer", "[.tls][network]") {
    // Ensure certificates exist in config/certs/
    if (!std::filesystem::exists("config/certs/ca.crt")) {
        WARN("Certificates not found in config/certs/, skipping TLS tests");
        return;
    }

    TlsTestContext ctx;
    auto logger = std::make_shared<clink::core::logging::Logger>("TestLogger");

    // Server Listener
    auto listener = std::make_shared<TlsTransportListener>(ctx.io_context, logger);
    listener->set_certificates("config/certs/ca.crt", "config/certs/server.crt", "config/certs/server.key");

    std::promise<std::shared_ptr<TlsTransportAdapter>> server_adapter_promise;
    auto server_adapter_future = server_adapter_promise.get_future();
    std::vector<uint8_t> received_data1;
    std::promise<void> receive_promise1;
    auto receive_future1 = receive_promise1.get_future();

    // Add logger
    auto logger_ptr = logger;

    listener->on_connection([&, logger_ptr](std::shared_ptr<TransportAdapter> adapter) {
        logger_ptr->info("Server accepted connection");
        auto tls_adapter = std::dynamic_pointer_cast<TlsTransportAdapter>(adapter);
        if (tls_adapter) {
            server_adapter_promise.set_value(tls_adapter);
            
            tls_adapter->on_receive([&, logger_ptr](const uint8_t* data, size_t size) {
                logger_ptr->info("Server received data: " + std::string(reinterpret_cast<const char*>(data), size));
                received_data1.assign(data, data + size);
                receive_promise1.set_value();
            });
        }
    });

    REQUIRE(listener->listen("127.0.0.1:0").value() == 0);
    
    // Get bound port
    std::string bound_endpoint = listener->local_endpoint();
    REQUIRE(!bound_endpoint.empty());
    
    // std::cout << "Listening on " << bound_endpoint << std::endl;

    ctx.start_io();

    // Client Adapter
    auto client = std::make_shared<TlsTransportAdapter>(ctx.io_context, logger);
    // client->set_certificates("config/certs/ca.crt", "config/certs/client.crt", "config/certs/client.key"); // Use client certs for mTLS
    
    // Connect
    auto ec = client->start(bound_endpoint);
    REQUIRE(ec.value() == 0);

    // Wait for connection
    auto server_adapter = server_adapter_future.get();
    REQUIRE(server_adapter != nullptr);

    // Send data Client -> Server
    std::string msg1 = "Hello Server";
    client->send(reinterpret_cast<const uint8_t*>(msg1.data()), msg1.size());

    REQUIRE(receive_future1.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    receive_future1.get();
    
    std::string received_str1(received_data1.begin(), received_data1.end());
    CHECK(received_str1 == msg1);

    // Send data Server -> Client
    std::string msg2 = "Hello Client";
    std::promise<std::string> receive_promise2;
    auto receive_future2 = receive_promise2.get_future();

    client->on_receive([&](const uint8_t* data, size_t size) {
        receive_promise2.set_value(std::string(reinterpret_cast<const char*>(data), size));
    });

    server_adapter->send(reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size());

    REQUIRE(receive_future2.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
    CHECK(receive_future2.get() == msg2);

    client->stop();
    server_adapter->stop();
    listener->stop();
}
