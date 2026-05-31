#pragma once

#include <string>

#include "src/share/include/clink/protocol/control_plane.hpp"
#include "src/share/include/clink/protocol/ipc_wire.hpp"

namespace clink::core::ipc::detail {

inline std::string build_error_payload(const std::string& command,
                                      const std::string& message,
                                      const std::string& reason = std::string{}) {
    return clink::protocol::ipc::build_error_payload(command, message, reason);
}

inline Message make_error_response(const Message& request,
                                   const std::string& message,
                                   const std::string& reason = std::string{}) {
    return {MessageType::Response,
            request.command,
            build_error_payload(request.command, message, reason)};
}

inline std::string build_wire_message(const std::string& command, const std::string& payload) {
    return clink::protocol::ipc::build_wire_message(command, payload);
}

inline Message parse_wire_request(const std::string& raw) {
    const auto parts = clink::protocol::ipc::parse_wire_message(raw);
    return {MessageType::Request, parts.command, parts.payload};
}

inline std::string extract_wire_payload(const std::string& raw) {
    return clink::protocol::ipc::extract_wire_payload(raw);
}

}  // namespace clink::core::ipc::detail
