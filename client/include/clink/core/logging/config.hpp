#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace clink::core {
namespace config {
class Configuration;
}
}

namespace clink::core::logging {

// Log levels
enum class Level {
    trace = 0,
    debug,
    info,
    warn,
    error,
    critical
};

// Log format types
enum class LogFormat {
    Simple,  // Simple text format
    Json,    // JSON format
    Custom   // Custom pattern
};

// Sink types
enum class SinkType {
    Console,
    File,
    RotatingFile,
    DailyFile
};

// Sink configuration
struct SinkConfig {
    SinkType type{SinkType::Console};
    bool enabled{true};
    Level level{Level::info};

    // File-specific options
    std::filesystem::path path;
    std::size_t max_size{10 * 1024 * 1024};  // 10MB
    std::size_t max_files{5};
    std::string rotation_time{"daily"};      // "daily", "hourly", or size-based

    // Pattern for custom format
    std::string pattern;
};

// Main logging configuration
struct LogConfig {
    // Global settings
    Level level{Level::info};
    LogFormat format{LogFormat::Simple};
    std::string pattern{"%Y-%m-%d %H:%M:%S.%e [%n] [%l] %v"};

    // Async logging settings
    bool async{true};
    std::size_t queue_size{8192};
    std::chrono::seconds flush_interval{3};

    // Sinks
    std::vector<SinkConfig> sinks;

    // Factory methods
    static LogConfig default_config();
    static LogConfig from_toml(const config::Configuration& config);

    // Validation
    bool validate() const;

private:
    void add_default_sinks();
};

}  // namespace clink::core::logging