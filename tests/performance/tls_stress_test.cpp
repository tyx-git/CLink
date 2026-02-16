#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <memory>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include "clink/core/network/tls_adapter.hpp"
#include "clink/core/network/packet.hpp"
#include "clink/core/logging/logger.hpp"
#include <asio.hpp>

#ifdef _WIN32
#include <winsock2.h>
#endif

using namespace clink::core;
namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    int session_count = 10;
    int duration_sec = 10;
    size_t packet_size = 1024;
    
    if (argc > 1) session_count = std::stoi(argv[1]);
    if (argc > 2) duration_sec = std::stoi(argv[2]);

    std::cout << "[perf] Preparing performance test..." << std::endl;
    std::cout << "[perf] Sessions: " << session_count << ", Duration: " << duration_sec << "s" << std::endl;

    // Ensure certs exist
    if (!fs::exists("config/certs/ca.crt")) {
        std::cerr << "[perf] Error: Certificates not found in config/certs/" << std::endl;
        return 1;
    }

    // 0. Init
    int num_io_threads = 1; // Force single thread for stability
    asio::io_context ioc(num_io_threads);
    auto work_guard = asio::make_work_guard(ioc);
    
    // Run IO context in multiple threads
    std::vector<std::thread> io_threads;
    for (int i = 0; i < num_io_threads; ++i) {
        io_threads.emplace_back([&ioc]() {
            ioc.run();
        });
    }

    auto logger = std::make_shared<logging::Logger>("perf");
    logger->set_level(logging::Level::info); // Enable info logs for debugging

    // 1. Setup Server
    auto server = std::make_shared<network::TlsTransportListener>(ioc, logger);
    server->set_certificates("config/certs/ca.crt", "config/certs/server.crt", "config/certs/server.key");
    
    std::atomic<size_t> total_bytes_received{0};
    std::atomic<size_t> total_packets_received{0};

    server->on_connection([&](std::shared_ptr<network::TransportAdapter> conn) {
        auto tls_conn = std::dynamic_pointer_cast<network::TlsTransportAdapter>(conn);
        if (tls_conn) {
            tls_conn->start_accepted();
            tls_conn->on_receive([&](const uint8_t* data, size_t size) {
                total_bytes_received += size;
                total_packets_received++;
            });
        }
    });

    if (auto ec = server->listen("127.0.0.1:0")) {
        std::cerr << "[perf] Server listen failed: " << ec.message() << std::endl;
        return 1;
    }
    
    std::string server_endpoint = server->local_endpoint();
    std::cout << "[perf] Server listening on " << server_endpoint << std::endl;

    // 2. Setup Clients
    std::vector<std::shared_ptr<network::TlsTransportAdapter>> clients;
    std::atomic<int> connected_clients{0};
    
    for (int i = 0; i < session_count; ++i) {
        auto client = std::make_shared<network::TlsTransportAdapter>(ioc, logger);
        client->set_certificates("config/certs/ca.crt", "config/certs/client.crt", "config/certs/client.key");
        
        // Disable verify for self-signed loopback test convenience if needed, 
        // but we have proper certs so let's try to use them.
        // If hostname verification fails for 127.0.0.1, we might need to disable it or generate cert for IP.
        // Assuming certs are valid for localhost or we might see errors.
        
        clients.push_back(client);
    }

    std::cout << "[perf] Connecting clients..." << std::endl;
    for (auto& client : clients) {
        auto ec = client->start(server_endpoint);
        if (!ec) {
            connected_clients++;
        } else {
            std::cerr << "[perf] Client connect failed: " << ec.message() << std::endl;
        }
        // Small delay to avoid thundering herd on accept
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    std::cout << "[perf] Connected clients: " << connected_clients << "/" << session_count << std::endl;

    // 3. Start Traffic
    std::cout << "[perf] Starting traffic generation..." << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    std::atomic<bool> running{true};
    
    std::vector<uint8_t> payload(packet_size, 'X');
    
    std::vector<std::thread> traffic_threads;
    for (auto& client : clients) {
        traffic_threads.emplace_back([&client, &payload, &running]() {
            while (running) {
                if (client->is_connected()) {
                    client->send(payload.data(), payload.size());
                    // Limit rate per client slightly to avoid buffer explosion if send is too fast for IO
                    std::this_thread::sleep_for(std::chrono::microseconds(100)); 
                } else {
                    break;
                }
            }
        });
    }

    // 4. Measure
    for (int i = 0; i < duration_sec; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        size_t bytes = total_bytes_received.load();
        double mbs = static_cast<double>(bytes) / (1024 * 1024);
        std::cout << "[perf] T+" << (i+1) << "s: Total Received: " << std::fixed << std::setprecision(2) << mbs << " MB" << std::endl;
    }

    running = false;
    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Join traffic threads
    for (auto& t : traffic_threads) {
        if (t.joinable()) t.join();
    }

    // Stop everything
    for (auto& client : clients) client->stop();
    server->stop();
    work_guard.reset();
    ioc.stop();
    
    for (auto& t : io_threads) {
        if (t.joinable()) t.join();
    }

    // 5. Report
    double total_mb = static_cast<double>(total_bytes_received) / (1024 * 1024);
    double time_s = duration / 1000.0;
    double throughput = total_mb / time_s;

    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "Performance Test Results" << std::endl;
    std::cout << "------------------------------------------------" << std::endl;
    std::cout << "Sessions:    " << session_count << std::endl;
    std::cout << "Duration:    " << time_s << " s" << std::endl;
    std::cout << "Total Data:  " << total_mb << " MB" << std::endl;
    std::cout << "Throughput:  " << throughput << " MB/s" << std::endl;
    std::cout << "Packets/sec: " << (total_packets_received / time_s) << std::endl;
    std::cout << "------------------------------------------------" << std::endl;

    // Write report to file
    fs::create_directories("docs");
    std::ofstream report("docs/performance_report.md");
    report << "# Network Performance Test Report\n\n";
    report << "- **Date**: " << std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) << "\n";
    report << "- **Sessions**: " << session_count << "\n";
    report << "- **Packet Size**: " << packet_size << " bytes\n";
    report << "- **Duration**: " << time_s << " s\n";
    report << "- **Total Data Transfer**: " << total_mb << " MB\n";
    report << "- **Average Throughput**: " << throughput << " MB/s\n";
    report << "- **Packets Per Second**: " << (total_packets_received / time_s) << "\n";
    report.close();

    return 0;
}
