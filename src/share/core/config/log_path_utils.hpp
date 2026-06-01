#pragma once

#include <string>
#include "src/share/core/config/configuration.hpp"

namespace clink::core::config {

// Resolve the first enabled log file path from logging.sinks[] config.
// Falls back to the provided default if no file sink is configured.
inline std::string resolve_log_file_path(const Configuration& configuration,
                                         const std::string& default_path = "") {
    for (int i = 0; i < 10; ++i) {
        const std::string prefix = "logging.sinks[" + std::to_string(i) + "]";
        const std::string type = configuration.get_string(prefix + ".type", "");
        const bool enabled = configuration.get_bool(prefix + ".enabled", true);
        if (!enabled) {
            continue;
        }
        if (type == "file" || type == "rotating" || type == "rotating_file" || type == "daily" || type == "daily_file") {
            const std::string path = configuration.get_string(prefix + ".path", "");
            if (!path.empty()) {
                return path;
            }
        }
    }

    if (!default_path.empty()) {
        return default_path;
    }

#ifdef _WIN32
    return "logs/clink-win.log";
#else
    return "logs/clink-linux.log";
#endif
}

} // namespace clink::core::config
