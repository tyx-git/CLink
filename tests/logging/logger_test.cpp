#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <sstream>
#include <fstream>
#include <filesystem>

#include "clink/core/logging/logger.hpp"
#include "clink/core/logging/config.hpp"
#include "clink/core/config/configuration.hpp"

TEST_CASE("Logger API Compatibility", "[logging]") {
    auto logger = std::make_shared<clink::core::logging::Logger>("test-logger");

    SECTION("Level setting and getting") {
        REQUIRE(logger->level() == clink::core::logging::Level::info);

        logger->set_level(clink::core::logging::Level::debug);
        REQUIRE(logger->level() == clink::core::logging::Level::debug);

        logger->set_level(clink::core::logging::Level::warn);
        REQUIRE(logger->level() == clink::core::logging::Level::warn);
    }

    SECTION("Logger name") {
        REQUIRE(logger->name() == "test-logger");
    }

    SECTION("Level string conversion") {
        using Level = clink::core::logging::Level;

        REQUIRE(clink::core::logging::level_to_string(Level::trace) == std::string("TRACE"));
        REQUIRE(clink::core::logging::level_to_string(Level::debug) == std::string("DEBUG"));
        REQUIRE(clink::core::logging::level_to_string(Level::info) == std::string("INFO"));
        REQUIRE(clink::core::logging::level_to_string(Level::warn) == std::string("WARN"));
        REQUIRE(clink::core::logging::level_to_string(Level::error) == std::string("ERROR"));
        REQUIRE(clink::core::logging::level_to_string(Level::critical) == std::string("CRITICAL"));

        REQUIRE(clink::core::logging::level_from_string("trace") == Level::trace);
        REQUIRE(clink::core::logging::level_from_string("debug") == Level::debug);
        REQUIRE(clink::core::logging::level_from_string("info") == Level::info);
        REQUIRE(clink::core::logging::level_from_string("warn") == Level::warn);
        REQUIRE(clink::core::logging::level_from_string("error") == Level::error);
        REQUIRE(clink::core::logging::level_from_string("critical") == Level::critical);
        REQUIRE(clink::core::logging::level_from_string("unknown") == Level::info); // default
    }

    SECTION("Log methods exist") {
        // Test that all log methods compile and run
        logger->set_level(clink::core::logging::Level::trace);

        logger->trace("trace message");
        logger->debug("debug message");
        logger->info("info message");
        logger->warn("warn message");
        logger->error("error message");

        // Test with multiple arguments
        logger->info("message with", "multiple", "arguments", 123, 45.6);
    }
}

TEST_CASE("LogConfig parsing", "[logging]") {
    using namespace clink::core::logging;

    SECTION("Default config") {
        auto config = LogConfig::default_config();
        REQUIRE(config.level == Level::info);
        REQUIRE(config.format == LogFormat::Simple);
        REQUIRE(config.async == true);
        REQUIRE(config.queue_size == 8192);
        REQUIRE(config.flush_interval == std::chrono::seconds(3));
        REQUIRE(config.sinks.size() >= 1); // At least console sink
    }

    SECTION("Config validation") {
        auto config = LogConfig::default_config();
        REQUIRE(config.validate() == true);

        // Invalid level (out of range - but enum prevents this)
        // Invalid queue size for async
        config.async = true;
        config.queue_size = 0;
        REQUIRE(config.validate() == false);

        // Fix queue size
        config.queue_size = 1024;
        REQUIRE(config.validate() == true);
    }
}

TEST_CASE("Logger factory functions", "[logging]") {
    SECTION("Create logger with default config") {
        auto logger = clink::core::logging::create_logger("factory-test");
        REQUIRE(logger != nullptr);
        REQUIRE(logger->name() == "factory-test");
        REQUIRE(logger->level() == clink::core::logging::Level::info);
    }

    SECTION("Create logger with custom config") {
        auto config = clink::core::logging::LogConfig::default_config();
        config.level = clink::core::logging::Level::debug;

        auto logger = clink::core::logging::create_logger("custom-test", config);
        REQUIRE(logger != nullptr);
        REQUIRE(logger->name() == "custom-test");
        REQUIRE(logger->level() == clink::core::logging::Level::debug);
    }
}

TEST_CASE("Logging initialization", "[logging]") {
    SECTION("Initialize with default config") {
        auto config = clink::core::logging::LogConfig::default_config();

        // Should not throw
        REQUIRE_NOTHROW(clink::core::logging::initialize_logging(config));

        // Second initialization should be no-op
        REQUIRE_NOTHROW(clink::core::logging::initialize_logging(config));
    }
}

// Note: File sink tests are omitted because they require file I/O
// and cleanup. In a real test suite, we would use temporary directories.