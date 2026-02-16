#pragma once

#include <string>
#include <memory>
#include <functional>
#include <vector>

namespace clink::core::ipc {

enum class MessageType {
    Request,
    Response,
    Notification
};

struct Message {
    MessageType type;
    std::string command;
    std::string payload;
};

class IpcServer {
public:
    virtual ~IpcServer() = default;
    virtual void start(const std::string& address) = 0;
    virtual void stop() = 0;
    virtual void set_handler(std::function<Message(const Message&)> handler) = 0;
};

class IpcClient {
public:
    virtual ~IpcClient() = default;
    virtual void connect(const std::string& address) = 0;
    virtual void disconnect() = 0;
    virtual Message send_request(const Message& request) = 0;
};

std::unique_ptr<IpcServer> create_server();
std::unique_ptr<IpcClient> create_client();

} // namespace clink::core::ipc
