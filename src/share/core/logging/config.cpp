#include "src/share/core/logging/config.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <stdexcept>

#include "src/share/core/config/configuration.hpp"

namespace clink::core::logging {

namespace {

Level level_from_string_impl(const std::string& str) {
    std::string lower;
    lower.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(lower),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower == "trace") return Level::trace;
    if (lower == "debug") return Level::debug;
    if (lower == "info") return Level::info;
    if (lower == "warn") return Level::warn;
    if (lower == "error") return Level::error;
    if (lower == "critical") return Level::critical;

    return Level::info;
}

LogFormat format_from_string(const std::string& str) {
    std::string lower;
    lower.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(lower),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower == "json") return LogFormat::Json;
    if (lower == "custom") return LogFormat::Custom;
    return LogFormat::Simple;
}

SinkType sink_type_from_string(const std::string& str) {
    std::string lower;
    lower.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(lower),
                   [](unsigned char c) { return std::tolower(c); });

    if (lower == "file") return SinkType::File;
    if (lower == "rotating_file" || lower == "rotating") return SinkType::RotatingFile;
    if (lower == "daily_file" || lower == "daily") return SinkType::DailyFile;
    return SinkType::Console;
}

std::size_t parse_size_string(const std::string& str) {
    if (str.empty()) return 0;

    std::string num_str;
    std::string unit_str;

    auto it = str.begin();
    while (it != str.end() && std::isdigit(*it)) {
        num_str.push_back(*it);
        ++it;
    }
    while (it != str.end() && !std::isdigit(*it)) {
        unit_str.push_back(*it);
        ++it;
    }

    std::size_t multiplier = 1;
    std::string unit_lower;
    unit_lower.reserve(unit_str.size());
    std::transform(unit_str.begin(), unit_str.end(), std::back_inserter(unit_lower),
                   [](unsigned char c) { return std::tolower(c); });

    if (unit_lower.find("kb") != std::string::npos) multiplier = 1024;
    else if (unit_lower.find("mb") != std::string::npos) multiplier = 1024 * 1024;
    else if (unit_lower.find("gb") != std::string::npos) multiplier = 1024 * 1024 * 1024;

    try {
        std::size_t value = std::stoull(num_str);
        return value * multiplier;
    } catch (...) {
        return 0;
    }
}

}  // namespace

LogConfig LogConfig::default_config() {
    LogConfig config;
    config.add_default_sinks();
    return config;
}

LogConfig LogConfig::from_toml(const config::Configuration& config) {
    LogConfig log_config;

    if (config.contains("logging.level")) {
        log_config.level = level_from_string_impl(config.get_string("logging.level"));
    }
    if (config.contains("logging.format")) {
        log_config.format = format_from_string(config.get_string("logging.format"));
    }
    if (config.contains("logging.pattern")) {
        log_config.pattern = config.get_string("logging.pattern");
    }
    if (config.contains("logging.async")) {
        log_config.async = config.get_bool("logging.async", true);
    }
    if (config.contains("logging.queue_size")) {
        log_config.queue_size = static_cast<std::size_t>(config.get_int("logging.queue_size", 8192));
    }
    if (config.contains("logging.flush_interval")) {
        log_config.flush_interval = std::chrono::seconds(config.get_int("logging.flush_interval", 3));
    }

    for (int i = 0; i < 10; ++i) {
        std::string prefix = "logging.sinks[" + std::to_string(i) + "]";
        if (!config.contains(prefix + ".type")) {
            break;
        }

        SinkConfig sink;
        sink.type = sink_type_from_string(config.get_string(prefix + ".type"));
        if (config.contains(prefix + ".enabled")) {
            sink.enabled = config.get_bool(prefix + ".enabled", true);
        }
        if (config.contains(prefix + ".level")) {
            sink.level = level_from_string_impl(config.get_string(prefix + ".level"));
        }
        if (config.contains(prefix + ".path")) {
            sink.path = config.get_string(prefix + ".path");
        }
        if (config.contains(prefix + ".max_size")) {
            std::string max_size_str = config.get_string(prefix + ".max_size");
            if (std::all_of(max_size_str.begin(), max_size_str.end(), ::isdigit)) {
                sink.max_size = std::stoull(max_size_str);
            } else {
                sink.max_size = parse_size_string(max_size_str);
            }
        }
        if (config.contains(prefix + ".max_files")) {
            sink.max_files = static_cast<std::size_t>(config.get_int(prefix + ".max_files", 5));
        }
        if (config.contains(prefix + ".rotation_time")) {
            sink.rotation_time = config.get_string(prefix + ".rotation_time");
        }
        if (config.contains(prefix + ".pattern")) {
            sink.pattern = config.get_string(prefix + ".pattern");
        }
        log_config.sinks.push_back(sink);
    }

    if (log_config.sinks.empty()) {
        log_config.add_default_sinks();
    }

    return log_config;
}

bool LogConfig::validate() const {
    if (level < Level::trace || level > Level::critical) {
        return false;
    }
    if (async && queue_size == 0) {
        return false;
    }

    for (const auto& sink : sinks) {
        if (!sink.enabled) {
            continue;
        }
        if (sink.level < Level::trace || sink.level > Level::critical) {
            return false;
        }
        if (sink.type != SinkType::Console && sink.path.empty()) {
            return false;
        }
        if (sink.type == SinkType::RotatingFile && sink.max_size == 0) {
            return false;
        }
        if ((sink.type == SinkType::RotatingFile || sink.type == SinkType::DailyFile) && sink.max_files == 0) {
            return false;
        }
    }

    return true;
}

void LogConfig::add_default_sinks() {
    SinkConfig console_sink;
    console_sink.type = SinkType::Console;
    console_sink.enabled = true;
    console_sink.level = level;
    sinks.push_back(console_sink);
}

}  // namespace clink::core::logging
