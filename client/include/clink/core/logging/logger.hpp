#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include "client/include/clink/core/logging/config.hpp"

namespace clink::core {

namespace config {
class Configuration;
}

namespace logging {

// Forward declarations
struct LogConfig;

class Logger {
public:
    explicit Logger(std::string name);
    explicit Logger(std::string name, const LogConfig* config);
    ~Logger();

    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = default;
    Logger& operator=(Logger&&) = default;

    void set_level(Level level) noexcept;
    [[nodiscard]] Level level() const noexcept;
    [[nodiscard]] const std::string& name() const noexcept;

    void log(Level level, const std::string& message);
    void flush();

    [[nodiscard]] static const char* level_to_string(Level level) noexcept;
    [[nodiscard]] static std::string current_timestamp();

    template <typename... Args>
    void log(Level level, std::string_view message, Args&&... args) {
        if (level < this->level()) {
            return;
        }
        
        if constexpr (sizeof...(Args) == 0) {
            log(level, std::string{message});
        } else {
            // For now, use a simple implementation that appends arguments
            // In a real implementation, we would use fmt::format or std::format
            std::ostringstream oss;
            oss << message;
            ((oss << " " << std::forward<Args>(args)), ...);
            log(level, oss.str());
        }
    }

    template <typename... Args>
    void trace(std::string_view message, Args&&... args) {
        log(Level::trace, message, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void debug(std::string_view message, Args&&... args) {
        log(Level::debug, message, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void info(std::string_view message, Args&&... args) {
        log(Level::info, message, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void warn(std::string_view message, Args&&... args) {
        log(Level::warn, message, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void error(std::string_view message, Args&&... args) {
        log(Level::error, message, std::forward<Args>(args)...);
    }

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Factory functions
std::shared_ptr<Logger> create_logger(const std::string& name);
std::shared_ptr<Logger> create_logger(const std::string& name, const LogConfig& config);

// Initialize logging system
void initialize_logging(const LogConfig& config);
void initialize_logging(const config::Configuration& config);

// Shutdown logging system (flushes all logs)
void shutdown_logging();

// Utility functions
Level level_from_string(const std::string& str);
std::string level_to_string(Level level);

}  // namespace logging
}  // namespace clink::core
