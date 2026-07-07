#pragma once

#include <string>
#include "src/share/core/config/configuration.hpp"

// 解析日志文件路径：遍历 [[logging.sinks]] 配置，返回第一个启用中的文件类 sink 的路径
// 如果都未配置，fallback 到 default_path，再 fallback 到平台默认路径
namespace clink::core::config {

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
