#pragma once

#if defined(_WIN32)
  #if defined(clink_process_server_EXPORTS)
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

namespace clink::hook {

// Re-use ipc namespace from ipc_protocol.hpp
using namespace clink::hook::ipc;

class NamedPipeAcceptor;

class CLINK_EXPORT IPCConnection {
public:
    virtual ~IPCConnection() = default;
    virtual void write_packet(ipc::PacketType type, uint64_t socket_id, const std::vector<char>& data) = 0;
    virtual void close() = 0;
};

class CLINK_EXPORT ProcessIPCServer : public std::enable_shared_from_this<ProcessIPCServer> {
public:
    explicit ProcessIPCServer(asio::io_context& io_context);
    ~ProcessIPCServer();

    using PacketHandler = std::function<void(std::shared_ptr<IPCConnection>, const ipc::PacketHeader&, const std::vector<char>&)>;
    using DisconnectHandler = std::function<void(std::shared_ptr<IPCConnection>)>;
    
    void set_packet_handler(PacketHandler handler);
    void set_disconnect_handler(DisconnectHandler handler);
    void set_socks_port(uint16_t port);
    void start();
    void stop();

    friend class NamedPipeAcceptor;

private:
    asio::io_context& io_context_;
    PacketHandler packet_handler_;
    DisconnectHandler disconnect_handler_;
    uint16_t socks_port_ = 0;
    
    std::shared_ptr<NamedPipeAcceptor> acceptor_;
};

} // namespace clink::hook
