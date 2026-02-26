#pragma once

#include <memory>
#include <asio.hpp>
#include "server/include/clink/core/logging/logger.hpp"
#include "server/include/clink/core/config/configuration.hpp"

#ifdef _WIN32
namespace clink::hook {
    class ProcessIPCServer;
}
#endif

namespace clink::core::network {
    class SessionManager;
}

namespace clink::server::modules {

class SocksServer;

class ProcessManager {
public:
    ProcessManager(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    ~ProcessManager();

    bool start(const clink::core::config::Configuration& config);
    void stop();

private:
    asio::io_context& io_context_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    
    std::shared_ptr<clink::server::modules::SocksServer> socks_server_;
    
#ifdef _WIN32
    std::shared_ptr<clink::hook::ProcessIPCServer> ipc_server_;
    std::shared_ptr<void> session_state_; // PIMPL for IpcProxySession map
#endif
    
    bool running_ = false;
};

} // namespace clink::server::modules
