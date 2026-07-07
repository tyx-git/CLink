#pragma once

#include "src/share/core/config/configuration.hpp"

#include <algorithm>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

// 配置签名工具：从指定前缀的配置键生成签名，用于检测配置是否变化
// 热重载时比对签名：签名不变则跳过重建，签名变则重新加载
// 某些域的变更（如 ipc.address）标记 restart_required 而非热加载
namespace clink::core::config {

inline std::string build_prefixed_signature(const Configuration& configuration,
                                            std::initializer_list<std::string_view> prefixes) {
    auto keys = configuration.get_keys();
    std::sort(keys.begin(), keys.end());

    std::string signature;
    for (const auto& key : keys) {
        bool match = false;
        for (const auto prefix : prefixes) {
            if (key.rfind(prefix, 0) == 0) {
                match = true;
                break;
            }
        }
        if (!match) {
            continue;
        }

        if (!signature.empty()) {
            signature += '|';
        }
        signature += key;
        signature += '=';
        signature += configuration.get_string(key, "");
    }

    return signature;
}

/// Shorthand for building a logging-domain configuration signature.
inline std::string build_logging_signature(const Configuration& configuration) {
    return build_prefixed_signature(configuration, {"logging."});
}

}  // namespace clink::core::config
