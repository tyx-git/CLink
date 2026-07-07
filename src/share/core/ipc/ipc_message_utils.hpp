#pragma once

#include <string>

#include "src/share/include/clink/protocol/control_plane.hpp"
#include "src/share/include/clink/protocol/ipc_wire.hpp"

// IPC 消息工具：封装 IPC 线协议的构建和解析
// 提供服务端侧便捷的 make_error_response 等辅助函数
namespace clink::core::ipc::detail {

// 构建错误 JSON 载荷（委托到 clink::protocol::ipc::build_error_payload）
inline std::string build_error_payload(const std::string& command,
                                      const std::string& message,
                                      const std::string& reason = std::string{}) {
    return clink::protocol::ipc::build_error_payload(command, message, reason);
}

// 从请求消息构造错误响应 Message
inline Message make_error_response(const Message& request,
                                   const std::string& message,
                                   const std::string& reason = std::string{}) {
    return {MessageType::Response,
            request.command,
            build_error_payload(request.command, message, reason)};
}

// 组装 "command|payload" 线格式字符串
inline std::string build_wire_message(const std::string& command, const std::string& payload) {
    return clink::protocol::ipc::build_wire_message(command, payload);
}

// 从原始字符串解析出 IPC 请求消息
inline Message parse_wire_request(const std::string& raw) {
    const auto parts = clink::protocol::ipc::parse_wire_message(raw);
    return {MessageType::Request, parts.command, parts.payload};
}

// 提取载荷部分（跳过 command| 前缀）
inline std::string extract_wire_payload(const std::string& raw) {
    return clink::protocol::ipc::extract_wire_payload(raw);
}

}  // namespace clink::core::ipc::detail
