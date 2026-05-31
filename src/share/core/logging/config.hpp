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

enum class Level {
    trace = 0,
    debug,
    info,
    warn,
    error,
    critical
};

enum class LogFormat {
    Simple,
    Json,
    Custom
};

enum class SinkType {
    Console,
    File,
    RotatingFile,
    DailyFile
};

struct SinkConfig {
    SinkType type{SinkType::Console};
    bool enabled{true};
    Level level{Level::info};
    std::filesystem::path path;
    std::size_t max_size{10 * 1024 * 1024};
    std::size_t max_files{5};
    std::string rotation_time{"daily"};
    std::string pattern;
};

struct LogConfig {
    Level level{Level::info};
    LogFormat format{LogFormat::Simple};
    std::string pattern{"%Y-%m-%d %H:%M:%S.%e [%n] [%l] %v"};
    bool async{true};
    std::size_t queue_size{8192};
    std::chrono::seconds flush_interval{3};
    std::vector<SinkConfig> sinks;

    static LogConfig default_config();
    static LogConfig from_toml(const config::Configuration& config);
    bool validate() const;

private:
    void add_default_sinks();
};

}  // namespace clink::core::logging
