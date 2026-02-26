#include "client/include/clink/core/logging/logger.hpp"
#include <algorithm>
#include <memory>
#include <stdexcept>
// For Python script builds (mingw.py), we need to define SPDLOG_HEADER_ONLY
// before including spdlog headers. CMake builds will have proper library linking.
// If SPDLOG_COMPILED_LIB is not defined (library mode), use header-only mode.
#ifndef SPDLOG_COMPILED_LIB
#ifndef SPDLOG_HEADER_ONLY
#define SPDLOG_HEADER_ONLY
#endif
#endif
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/async.h>
#include <spdlog/async_logger.h>
#include <spdlog/pattern_formatter.h>
#include <spdlog/fmt/fmt.h>
#include "client/include/clink/core/config/configuration.hpp"

namespace clink::core::logging {
namespace {
// Convert clink::core::logging::Level to spdlog::level::level_enum
spdlog::level::level_enum to_spdlog_level(Level level) {
    switch (level) {
        case Level::trace:    return spdlog::level::trace;
        case Level::debug:    return spdlog::level::debug;
        case Level::info:     return spdlog::level::info;
        case Level::warn:     return spdlog::level::warn;
        case Level::error:    return spdlog::level::err;
        case Level::critical: return spdlog::level::critical;
        default:              return spdlog::level::info;
    }
}
// Convert spdlog::level::level_enum to clink::core::logging::Level
Level from_spdlog_level(spdlog::level::level_enum level) {
    switch (level) {
        case spdlog::level::trace:    return Level::trace;
        case spdlog::level::debug:    return Level::debug;
        case spdlog::level::info:     return Level::info;
        case spdlog::level::warn:     return Level::warn;
        case spdlog::level::err:      return Level::error;
        case spdlog::level::critical: return Level::critical;
        default:                      return Level::info;
    }
}
// Create spdlog sink from SinkConfig
std::shared_ptr<spdlog::sinks::sink> create_spdlog_sink(const SinkConfig& config) {
    if (!config.enabled) {
        return nullptr;
    }
    std::shared_ptr<spdlog::sinks::sink> sink;
    switch (config.type) {
        case SinkType::Console: {
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            sink = console_sink;
            break;
        }
        case SinkType::File: {
            auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                config.path.string(), false  // append instead of truncate
            );
            sink = file_sink;
            break;
        }
        case SinkType::RotatingFile: {
            auto rotating_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                config.path.string(),
                config.max_size,
                config.max_files
            );
            sink = rotating_sink;
            break;
        }
        case SinkType::DailyFile: {
            // Parse rotation time (default to midnight)
            int rotation_hour = 0;
            int rotation_minute = 0;
            if (config.rotation_time == "hourly") {
                // Will rotate every hour
                rotation_hour = -1;
            } else {
                // Try to parse time like "14:30"
                auto colon_pos = config.rotation_time.find(':');
                if (colon_pos != std::string::npos) {
                    try {
                        rotation_hour = std::stoi(config.rotation_time.substr(0, colon_pos));
                        rotation_minute = std::stoi(config.rotation_time.substr(colon_pos + 1));
                    } catch (...) {
                        // Use default midnight
                    }
                }
            }
            auto daily_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>(
                config.path.string(),
                rotation_hour,
                rotation_minute
            );
            sink = daily_sink;
            break;
        }
        default:
            throw std::runtime_error("Unknown sink type");
    }
    if (sink) {
        sink->set_level(to_spdlog_level(config.level));
        // Set pattern if provided
        if (!config.pattern.empty()) {
            sink->set_pattern(config.pattern);
        }
    }
    return sink;
}
// Global spdlog registry (for default logger)
bool g_logging_initialized = false;
bool g_thread_pool_initialized = false;
std::shared_ptr<spdlog::logger> g_default_logger = nullptr;
}  // namespace
// Logger class implementation (delegating to spdlog)
class Logger::Impl {
public:
    Impl(const std::string& name, const LogConfig* config = nullptr)
        : name_(name) {
        std::vector<std::shared_ptr<spdlog::sinks::sink>> sinks;
        if (config) {
            // Create sinks from config
            for (const auto& sink_config : config->sinks) {
                auto sink = create_spdlog_sink(sink_config);
                if (sink) {
                    sinks.push_back(sink);
                }
            }
            // Create logger with sinks
            if (config->async) {
                // Create async logger
                if (!g_thread_pool_initialized) {
                    spdlog::init_thread_pool(config->queue_size, 1);
                    g_thread_pool_initialized = true;
                }
                spdlog_logger_ = std::make_shared<spdlog::async_logger>(
                    name,
                    sinks.begin(),
                    sinks.end(),
                    spdlog::thread_pool(),
                    spdlog::async_overflow_policy::block
                );
                // Set flush on level
                spdlog_logger_->flush_on(spdlog::level::info);
                // Set flush interval
                spdlog::flush_every(std::chrono::seconds(config->flush_interval));
            } else {
                // Create sync logger
                spdlog_logger_ = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
                spdlog_logger_->flush_on(spdlog::level::info);
            }
            // Set format
            switch (config->format) {
                case LogFormat::Json:
                    spdlog_logger_->set_formatter(std::make_unique<spdlog::pattern_formatter>("%v"));
                    // Note: For JSON format, we'd need a custom formatter
                    // For now, use simple format
                    spdlog_logger_->set_pattern(config->pattern);
                    break;
                case LogFormat::Custom:
                    spdlog_logger_->set_pattern(config->pattern);
                    break;
                case LogFormat::Simple:
                default:
                    spdlog_logger_->set_pattern(config->pattern);
                    break;
            }
        } else {
            // Create default logger (console only)
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            console_sink->set_pattern("%Y-%m-%d %H:%M:%S.%e [%n] [%l] %v");
            sinks.push_back(console_sink);
            spdlog_logger_ = std::make_shared<spdlog::logger>(name, sinks.begin(), sinks.end());
        }
        spdlog_logger_->set_level(to_spdlog_level(config ? config->level : Level::info));
    }
    void set_level(Level level) {
        spdlog_logger_->set_level(to_spdlog_level(level));
    }
    Level level() const {
        return from_spdlog_level(spdlog_logger_->level());
    }
    const std::string& name() const {
        return name_;
    }
    void log(Level level, const std::string& message) {
        spdlog_logger_->log(to_spdlog_level(level), message);
    }
    void flush() {
        spdlog_logger_->flush();
    }
    std::shared_ptr<spdlog::logger> spdlog_logger() const {
        return spdlog_logger_;
    }
private:
    std::string name_;
    std::shared_ptr<spdlog::logger> spdlog_logger_;
};
// Logger public interface implementation
Logger::Logger(std::string name)
    : impl_(std::make_unique<Impl>(name)) {
}
Logger::Logger(std::string name, const LogConfig* config)
    : impl_(std::make_unique<Impl>(name, config)) {
}
Logger::~Logger() = default;
void Logger::set_level(Level level) noexcept {
    impl_->set_level(level);
}
Level Logger::level() const noexcept {
    return impl_->level();
}
const std::string& Logger::name() const noexcept {
    return impl_->name();
}
void Logger::log(Level level, const std::string& message) {
    impl_->log(level, message);
}
void Logger::flush() {
    impl_->flush();
}
// Static methods (kept for compatibility)
const char* Logger::level_to_string(Level level) noexcept {
    switch (level) {
        case Level::trace:    return "TRACE";
        case Level::debug:    return "DEBUG";
        case Level::info:     return "INFO";
        case Level::warn:     return "WARN";
        case Level::error:    return "ERROR";
        case Level::critical: return "CRITICAL";
        default:              return "UNKNOWN";
    }
}
std::string Logger::current_timestamp() {
    // This is now handled by spdlog's formatter
    // Keep for compatibility
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&time));
    return buffer;
}
// Factory functions
std::shared_ptr<Logger> create_logger(const std::string& name) {
    return std::make_shared<Logger>(name);
}
std::shared_ptr<Logger> create_logger(const std::string& name, const LogConfig& config) {
    return std::make_shared<Logger>(name, &config);
}
// Initialize logging system
void initialize_logging(const LogConfig& config) {
    if (g_logging_initialized) {
        return;
    }
    // Validate config
    if (!config.validate()) {
        throw std::runtime_error("Invalid logging configuration");
    }
    // Set global spdlog level
    spdlog::set_level(to_spdlog_level(config.level));
    // Set default logger pattern
    if (!config.pattern.empty()) {
        spdlog::set_pattern(config.pattern);
    }
    // Create default logger
    std::vector<std::shared_ptr<spdlog::sinks::sink>> sinks;
    for (const auto& sink_config : config.sinks) {
        auto sink = create_spdlog_sink(sink_config);
        if (sink) {
            sinks.push_back(sink);
        }
    }
    if (!sinks.empty()) {
        if (config.async) {
            // Initialize async logging (only once)
            if (!g_thread_pool_initialized) {
                spdlog::init_thread_pool(config.queue_size, 1);
                g_thread_pool_initialized = true;
            }
            g_default_logger = std::make_shared<spdlog::async_logger>(
                "cvpn",
                sinks.begin(),
                sinks.end(),
                spdlog::thread_pool(),
                spdlog::async_overflow_policy::block
            );
            spdlog::set_default_logger(g_default_logger);
            spdlog::flush_every(std::chrono::seconds(config.flush_interval));
        } else {
            g_default_logger = std::make_shared<spdlog::logger>("cvpn", sinks.begin(), sinks.end());
            spdlog::set_default_logger(g_default_logger);
        }
        g_default_logger->set_level(to_spdlog_level(config.level));
    }
    g_logging_initialized = true;
}
void initialize_logging(const config::Configuration& config) {
    auto log_config = LogConfig::from_toml(config);
    initialize_logging(log_config);
}
void shutdown_logging() {
    spdlog::shutdown();
    g_logging_initialized = false;
    g_thread_pool_initialized = false;
    g_default_logger = nullptr;
}
// Utility functions
Level level_from_string(const std::string& str) {
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
    return Level::info;  // default
}
std::string level_to_string(Level level) {
    return Logger::level_to_string(level);
}
}  // namespace clink::core::logging