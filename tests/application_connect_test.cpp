#include <catch2/catch_test_macros.hpp>

#include "src/server/core/application/application.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>

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
