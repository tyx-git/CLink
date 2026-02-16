#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <sstream>

#include "clink/core/logging/config.hpp"
#include "clink/core/config/configuration.hpp"

TEST_CASE("LogConfig from TOML", "[logging][config]") {
    using namespace clink::core;
    using namespace clink::core::logging;

    SECTION("Empty config returns defaults") {
        config::Configuration empty_config;
        auto log_config = LogConfig::from_toml(empty_config);

        REQUIRE(log_config.level == Level::info);
        REQUIRE(log_config.format == LogFormat::Simple);
        REQUIRE(log_config.async == true);
        REQUIRE(log_config.sinks.size() >= 1); // Default console sink
    }

    SECTION("Parse log level from config") {
        config::Configuration config;
        config.set("logging.level", "debug");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.level == Level::debug);

        config.set("logging.level", "error");
        log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.level == Level::error);

        config.set("logging.level", "invalid");
        log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.level == Level::info); // default
    }

    SECTION("Parse format from config") {
        config::Configuration config;
        config.set("logging.format", "json");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.format == LogFormat::Json);

        config.set("logging.format", "custom");
        log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.format == LogFormat::Custom);

        config.set("logging.format", "simple");
        log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.format == LogFormat::Simple);
    }

    SECTION("Parse async settings") {
        config::Configuration config;
        config.set("logging.async", "false");
        config.set("logging.queue_size", "4096");
        config.set("logging.flush_interval", "5");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.async == false);
        REQUIRE(log_config.queue_size == 4096);
        REQUIRE(log_config.flush_interval == std::chrono::seconds(5));
    }

    SECTION("Parse pattern") {
        config::Configuration config;
        config.set("logging.pattern", "[%H:%M:%S] %v");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.pattern == "[%H:%M:%S] %v");
    }
}

TEST_CASE("SinkConfig parsing", "[logging][config]") {
    using namespace clink::core;
    using namespace clink::core::logging;

    SECTION("Parse console sink") {
        config::Configuration config;
        config.set("logging.sinks[0].type", "console");
        config.set("logging.sinks[0].enabled", "true");
        config.set("logging.sinks[0].level", "debug");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.sinks.size() == 1);

        const auto& sink = log_config.sinks[0];
        REQUIRE(sink.type == SinkType::Console);
        REQUIRE(sink.enabled == true);
        REQUIRE(sink.level == Level::debug);
    }

    SECTION("Parse file sink") {
        config::Configuration config;
        config.set("logging.sinks[0].type", "file");
        config.set("logging.sinks[0].path", "test.log");
        config.set("logging.sinks[0].max_size", "10485760"); // 10MB in bytes
        config.set("logging.sinks[0].max_files", "3");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.sinks.size() == 1);

        const auto& sink = log_config.sinks[0];
        REQUIRE(sink.type == SinkType::File);
        REQUIRE(sink.path == "test.log");
        REQUIRE(sink.max_size == 10485760);
        REQUIRE(sink.max_files == 3);
    }

    SECTION("Parse size string with units") {
        config::Configuration config;
        config.set("logging.sinks[0].type", "file");
        config.set("logging.sinks[0].max_size", "10MB");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.sinks.size() == 1);
        REQUIRE(log_config.sinks[0].max_size == 10 * 1024 * 1024);
    }

    SECTION("Parse multiple sinks") {
        config::Configuration config;
        config.set("logging.sinks[0].type", "console");
        config.set("logging.sinks[0].level", "info");

        config.set("logging.sinks[1].type", "file");
        config.set("logging.sinks[1].path", "app.log");
        config.set("logging.sinks[1].level", "debug");

        auto log_config = LogConfig::from_toml(config);
        REQUIRE(log_config.sinks.size() == 2);

        REQUIRE(log_config.sinks[0].type == SinkType::Console);
        REQUIRE(log_config.sinks[0].level == Level::info);

        REQUIRE(log_config.sinks[1].type == SinkType::File);
        REQUIRE(log_config.sinks[1].path == "app.log");
        REQUIRE(log_config.sinks[1].level == Level::debug);
    }

    SECTION("Disabled sink is skipped") {
        config::Configuration config;
        config.set("logging.sinks[0].type", "console");
        config.set("logging.sinks[0].enabled", "false");

        auto log_config = LogConfig::from_toml(config);
        // Sink is still parsed but marked as disabled
        REQUIRE(log_config.sinks.size() == 1);
        REQUIRE(log_config.sinks[0].enabled == false);
    }
}

TEST_CASE("Configuration integration", "[logging][config]") {
    using namespace clink::core;

    SECTION("Load from sample config file") {
        // This test requires the sample config file to exist
        auto sample_path = std::filesystem::path("config/clink.sample.toml");
        if (std::filesystem::exists(sample_path)) {
            auto config = config::Configuration::load_from_file(sample_path);

            // Check that logging section exists
            REQUIRE(config.contains("logging.level") == true);
            REQUIRE(config.contains("logging.format") == true);
            REQUIRE(config.contains("logging.sinks[0].type") == true);

            // Parse logging config
            auto log_config = logging::LogConfig::from_toml(config);
            REQUIRE(log_config.validate() == true);
        }
    }
}