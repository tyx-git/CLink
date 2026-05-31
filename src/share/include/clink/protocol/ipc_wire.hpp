#pragma once

#include <string>

#include "src/share/include/clink/protocol/control_plane.hpp"

namespace clink::protocol::ipc {

struct WireParts {
    std::string command;
    std::string payload;
};

inline std::string json_escape(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (char c : input) {
        const unsigned char byte = static_cast<unsigned char>(c);
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (byte < 0x20) {
                    static constexpr char kHex[] = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(kHex[(byte >> 4U) & 0x0FU]);
                    out.push_back(kHex[byte & 0x0FU]);
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    return out;
}

inline std::string build_error_payload(const std::string& command,
                                       const std::string& message,
                                       const std::string& reason = std::string{}) {
    const std::string final_reason = reason.empty() ? message : reason;
    return std::string("{\"") + control_plane::kEnvelopeOk + "\":false,\"" +
           control_plane::kEnvelopeCommand + "\":\"" + json_escape(command) +
           "\",\"" + control_plane::kEnvelopeError + "\":\"" + json_escape(message) +
           "\",\"" + control_plane::kEnvelopeData +
           "\":{\"" + control_plane::kFieldAccepted + "\":false,\"" +
           control_plane::kFieldStatus + "\":\"" + control_plane::kStatusFailed +
           "\",\"" + control_plane::kFieldReason + "\":\"" + json_escape(final_reason) +
           "\",\"" + control_plane::kFieldMessage + "\":\"" + json_escape(message) + "\"}}";
}

inline std::string build_wire_message(const std::string& command, const std::string& payload) {
    return command + "|" + payload;
}

inline WireParts parse_wire_message(const std::string& raw) {
    const auto sep = raw.find('|');
    return {sep == std::string::npos ? raw : raw.substr(0, sep),
            sep == std::string::npos ? std::string{} : raw.substr(sep + 1)};
}

inline std::string extract_wire_payload(const std::string& raw) {
    const auto sep = raw.find('|');
    return sep == std::string::npos ? raw : raw.substr(sep + 1);
}

}  // namespace clink::protocol::ipc
