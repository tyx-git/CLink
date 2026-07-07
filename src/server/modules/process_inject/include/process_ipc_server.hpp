#pragma once

#if defined(_WIN32)
  #if defined(clink_inject_EXPORTS) || defined(clink_process_server_EXPORTS)
    #define CLINK_EXPORT __declspec(dllexport)
  #else
    #define CLINK_EXPORT __declspec(dllimport)
  #endif
#else
  #define CLINK_EXPORT
#endif

#include <memory>
#include <vector>
#include <functional>
#include <string>
#include <asio.hpp>

#include "ipc_protocol.hpp"

// 进程注入 IPC 服务端：管理 Hook DLL ↔ PM 之间的 Named Pipe 连接
// IPCConnection：代表一条 Pipe 连接，可写包和关闭
// ProcessIPCServer：Asio 异步 Named Pipe acceptor，接收 Hook DLL 的连接
namespace clink::hook {

using namespace clink::hook::ipc;

class NamedPipeAcceptor;

class CLINK_EXPORT IPCConnection {
public:
    virtual ~IPCConnection() = default;
    virtual void write_packet(ipc::PacketType type, uint64_t socket_id, const std::vector<char>& data) = 0; // 发送数据到 Hook DLL
    virtual void close() = 0;                                       // 关闭连接
};

class CLINK_EXPORT ProcessIPCServer : public std::enable_shared_from_this<ProcessIPCServer> {
public:
    explicit ProcessIPCServer(asio::io_context& io_context);
    ~ProcessIPCServer();

    using PacketHandler = std::function<void(std::shared_ptr<IPCConnection>, const ipc::PacketHeader&, const std::vector<char>&)>; // 数据包处理器
    using DisconnectHandler = std::function<void(std::shared_ptr<IPCConnection>)>;  // 断开处理器
    using LogSink = std::function<void(bool is_error, const std::string& message)>; // 日志回调

    void set_packet_handler(PacketHandler handler);     // 注册包处理器（PM 设置回调）
    void set_disconnect_handler(DisconnectHandler handler); // 注册断开处理器
    void set_log_sink(LogSink sink);                    // 注册日志回调
    void set_socks_port(uint16_t port);                 // 设置 SOCKS 端口（注入 IPC 传递用）
    void start();                                       // 开始监听 Named Pipe
    void stop();                                        // 停止监听

    friend class NamedPipeAcceptor;

private:
    asio::io_context& io_context_;
    PacketHandler packet_handler_;
    DisconnectHandler disconnect_handler_;
    LogSink log_sink_;
    uint16_t socks_port_ = 0;

    std::shared_ptr<NamedPipeAcceptor> acceptor_;       // Asio 异步 Named Pipe acceptor
};

} // namespace clink::hook
