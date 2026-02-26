#include <catch2/catch_test_macros.hpp>
#include <asio.hpp>
#include <thread>
#include <future>
#include <iostream>
#include "clink/server/modules/process_manager.hpp"
#include "clink/server/modules/ipc_proxy_session.hpp"
#include "process_ipc_server.hpp"

using namespace clink::server::modules;
using namespace clink::hook;

// Mock IPC Connection to verify data flow
class MockIPCConnection : public IPCConnection {
public:
    MockIPCConnection(asio::io_context&, ProcessIPCServer&) {}
    
    std::vector<char> last_received_data;
    uint64_t last_socket_id = 0;
    clink::hook::ipc::PacketType last_type;
    bool data_received = false;
    
    // Override write_packet to capture output instead of writing to pipe
    void write_packet(clink::hook::ipc::PacketType type, uint64_t socket_id, const std::vector<char>& data) override {
        last_type = type;
        last_socket_id = socket_id;
        last_received_data = data;
        data_received = true;
    }

    void close() override {}
};

TEST_CASE("IpcProxySession Data Flow", "[server][ipc]") {
    asio::io_context io_context;
    auto logger = std::make_shared<clink::core::logging::Logger>("TestIPC");
    
    // Create a real TCP server to act as target
    // We need to start the server first to get the port
    
    std::promise<uint16_t> port_promise;
    auto port_future = port_promise.get_future();

    std::thread server_thread([port_promise = std::move(port_promise)]() mutable {
        asio::io_context server_io;
        try {
            asio::ip::tcp::acceptor acc(server_io, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 0));
            port_promise.set_value(acc.local_endpoint().port());
            
            auto socket = std::make_shared<asio::ip::tcp::socket>(server_io);
            acc.accept(*socket);
            
            // Echo server
            char data[1024];
            asio::error_code ec;
            size_t len = socket->read_some(asio::buffer(data), ec);
            if (!ec) {
                asio::write(*socket, asio::buffer(data, len));
            }
        } catch (...) {
            try {
                port_promise.set_exception(std::current_exception());
            } catch (...) {}
        }
    });
    server_thread.detach(); 
    
    uint16_t port = port_future.get();

    // Setup Mock IPC
    ProcessIPCServer ipc_server(io_context);
    auto conn = std::make_shared<MockIPCConnection>(io_context, ipc_server);
    uint64_t socket_id = 12345;
    
    // Enable debug logging to console
    logger->set_level(clink::core::logging::Level::debug);
    
    auto session = std::make_shared<IpcProxySession>(io_context, conn, socket_id, logger);
    
    SECTION("Connect and Proxy Data") {
        std::cout << "Starting session..." << std::endl;
        // Start session (connects to target)
        session->start("127.0.0.1", port);
        
        // Run IO context to establish connection
        int retries = 0;
        while (retries++ < 20) {
            io_context.run_for(std::chrono::milliseconds(50));
            io_context.restart(); // Restart in case it stopped
        }
        
        std::cout << "Sending data..." << std::endl;
        // Simulate sending data from IPC
        std::string test_msg = "Hello Proxy";
        std::vector<char> data(test_msg.begin(), test_msg.end());
        session->send_data(data);
        
        // Run loop to process write to socket, read from socket, and write back to IPC
        retries = 0;
        while (!conn->data_received && retries++ < 40) {
            io_context.run_for(std::chrono::milliseconds(50));
            io_context.restart();
        }
        
        std::cout << "Verification... Data received: " << conn->data_received << std::endl;
        
        // Verify IPC received echo
        REQUIRE(conn->data_received);
        REQUIRE(conn->last_type == clink::hook::ipc::PacketType::DataRecv);
        REQUIRE(conn->last_socket_id == socket_id);
        
        std::string received_msg(conn->last_received_data.begin(), conn->last_received_data.end());
        REQUIRE(received_msg == test_msg);
    }
}
