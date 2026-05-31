#pragma once

#include "src/share/core/config/configuration.hpp"

#include <algorithm>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

namespace clink::core::config {

/// Build a canonical signature string from all configuration keys that match
/// any of the given prefixes.  Keys are sorted for deterministic output.
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
