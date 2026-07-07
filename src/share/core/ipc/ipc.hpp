#pragma once

#include <string>
#include <memory>
#include <functional>
#include <vector>
#include "src/share/core/logging/logger.hpp"

namespace asio { class io_context; }

// IPC 抽象接口：IpcServer（服务端监听）+ IpcClient（客户端调用）
// 平台实现：Windows Named Pipe（ipc_win.cpp）/ Linux Unix Socket（ipc_linux.cpp）
namespace clink::core::ipc {

enum class MessageType {
    Request,      // 请求：cli → daemon
    Response,     // 响应：daemon → cli
    Notification  // 通知（暂未使用）
};

// IPC 消息结构：type 区分请求/响应，command 是命令名，payload 是 JSON 字符串
struct Message {
    MessageType type;
    std::string command;
    std::string payload;
};

// IPC 服务端：监听 Named Pipe / Unix Socket，接收并处理消息
class IpcServer {
public:
    virtual ~IpcServer() = default;
    virtual void start(const std::string& address) = 0;        // 开始在 address 监听
    virtual void stop() = 0;                                    // 停止监听
    virtual void set_handler(std::function<Message(const Message&)> handler) = 0; // 注册消息处理器
};

// IPC 客户端：连接服务端并发送请求-响应消息
class IpcClient {
public:
    virtual ~IpcClient() = default;
    virtual void connect(const std::string& address) = 0;        // 连接到服务端
    virtual void disconnect() = 0;                                 // 断开连接
    virtual Message send_request(const Message& request) = 0;     // 发送请求并等待响应（同步阻塞）
};

std::unique_ptr<IpcServer> create_server(std::shared_ptr<logging::Logger> logger);
std::unique_ptr<IpcServer> create_server();
std::unique_ptr<IpcServer> create_server(asio::io_context& io, std::shared_ptr<logging::Logger> logger);
std::unique_ptr<IpcClient> create_client(std::shared_ptr<logging::Logger> logger);

} // namespace clink::core::ipc
