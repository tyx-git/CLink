#include <catch2/catch_test_macros.hpp>

#include "src/server/core/application/application.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
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
