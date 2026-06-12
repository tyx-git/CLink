#include <catch2/catch_test_macros.hpp>

#include "src/server/core/application/application.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <asio.hpp>
#include <string>
#include <thread>

namespace {

std::filesystem::path write_temp_config(const std::string& filename, const std::string& content) {
    const auto path = std::filesystem::temp_directory_path() / filename;
    std::ofstream out(path, std::ios::trunc);
    REQUIRE(out.is_open());
    out << content;
    out.close();
    return path;
}

} // namespace

TEST_CASE("server connect_session uses transport.server_endpoint fallback", "[application][connect]") {
    namespace control_plane = clink::protocol::control_plane;
    using json = nlohmann::json;

    const auto config_path = write_temp_config(
        "clink-connect-transport-endpoint-test.toml",
        "[transport]\n"
        "server_endpoint = \"tcp://127.0.0.1:1\"\n"
        "[network]\n"
        "listen_endpoint = \"tcp://0.0.0.0:0\"\n"
        "[network.virtual_interface]\n"
        "enabled = false\n"
        "[process_manager]\n"
        "enabled = false\n");

    clink::core::ApplicationOptions options;
    options.identity = "clink-connect-test";
    options.role = "test";
    options.config_path = config_path;
    options.heartbeat_interval = std::chrono::milliseconds(10);

    clink::core::Application app{options};
    app.initialize();

    const auto result = json::parse(app.connect_session());

    CHECK(result.at(control_plane::kFieldReason).get<std::string>() != control_plane::kReasonMissingEndpoint);

    app.shutdown(std::chrono::milliseconds(100));
    std::filesystem::remove(config_path);
}

TEST_CASE("application shutdown returns promptly after io thread exits", "[application][shutdown]") {
    const auto config_path = write_temp_config(
        "clink-shutdown-timeout-regression.toml",
        "[network]\n"
        "listen_endpoint = \"\"\n"
        "[network.virtual_interface]\n"
        "enabled = false\n"
        "[process_manager]\n"
        "enabled = false\n");

    clink::core::ApplicationOptions options;
    options.identity = "clink-shutdown-timeout-test";
    options.role = "test";
    options.config_path = config_path;
    options.heartbeat_interval = std::chrono::milliseconds(1);

    clink::core::Application app{options};
    app.initialize();

    std::thread runner([&app]() {
        app.run();
    });

    const auto start_wait = std::chrono::steady_clock::now();
    while (!app.running() && std::chrono::steady_clock::now() - start_wait < std::chrono::seconds(2)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    REQUIRE(app.running());

    app.request_stop();
    runner.join();

    const auto shutdown_start = std::chrono::steady_clock::now();
    app.shutdown(std::chrono::seconds(5));
    const auto elapsed = std::chrono::steady_clock::now() - shutdown_start;

    CHECK(elapsed < std::chrono::seconds(1));

    std::filesystem::remove(config_path);
}

TEST_CASE("application disconnect clears pending connect status details", "[application][connect]") {
    namespace control_plane = clink::protocol::control_plane;
    using json = nlohmann::json;

    asio::io_context server_io;
    asio::ip::tcp::acceptor acceptor(
        server_io,
        asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    const auto port = acceptor.local_endpoint().port();

    std::thread server_thread([&]() {
        asio::ip::tcp::socket socket(server_io);
        asio::error_code ec;
        acceptor.accept(socket, ec);
        if (!ec) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    });

    const auto config_path = write_temp_config(
        "clink-disconnect-clears-connect-status.toml",
        "[network]\n"
        "listen_endpoint = \"\"\n"
        "[network.virtual_interface]\n"
        "enabled = false\n"
        "[process_manager]\n"
        "enabled = false\n");

    clink::core::ApplicationOptions options;
    options.identity = "clink-disconnect-status-test";
    options.role = "test";
    options.config_path = config_path;
    options.heartbeat_interval = std::chrono::milliseconds(1);

    clink::core::Application app{options};
    app.initialize();

    const auto connect_result = json::parse(
        app.connect_session("tcp://127.0.0.1:" + std::to_string(port)));
    REQUIRE(connect_result.at(control_plane::kFieldStatus).get<std::string>() == control_plane::kStatusPending);

    app.disconnect_session();

    const auto status = json::parse(app.get_session_status());
    CHECK(status.at(control_plane::kFieldStatus).get<std::string>() == control_plane::kStatusDisconnected);
    CHECK(status.at(control_plane::kFieldConnectPhase).get<std::string>() == control_plane::kStatusIdle);
    CHECK(status.at(control_plane::kFieldConnectReason).get<std::string>() == control_plane::kValueNone);
    CHECK_FALSE(status.contains(control_plane::kFieldConnectMessage));

    app.shutdown(std::chrono::milliseconds(100));
    std::filesystem::remove(config_path);
    acceptor.close();
    if (server_thread.joinable()) {
        server_thread.join();
    }
}
