#pragma once

#include <memory>
#include <mutex>
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
    enum class StartState {
        Failed,
        Ready,
        Degraded
    };

    ProcessManager(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    ~ProcessManager();

    bool start(const clink::core::config::Configuration& config);
    void stop();

    [[nodiscard]] StartState start_state() const noexcept { return start_state_; }
    [[nodiscard]] bool is_degraded() const noexcept { return start_state_ == StartState::Degraded; }
    [[nodiscard]] bool socks_available() const noexcept { return socks_available_; }
    [[nodiscard]] const std::string& start_reason() const noexcept { return start_reason_; }
    [[nodiscard]] const std::string& socks_backend() const noexcept { return socks_backend_; }

private:
    asio::io_context& io_context_;
    std::shared_ptr<clink::core::logging::Logger> logger_;
    std::shared_ptr<clink::core::network::SessionManager> session_manager_;
    
    std::mutex lifecycle_mutex_;
    std::shared_ptr<clink::server::modules::SocksServer> socks_server_;
    
#ifdef _WIN32
    std::shared_ptr<clink::hook::ProcessIPCServer> ipc_server_;
    std::shared_ptr<void> session_state_; // PIMPL for IpcProxySession map
#endif
    
    bool running_ = false;
    bool socks_available_ = false;
    StartState start_state_ = StartState::Failed;
    std::string start_reason_ = "not_started";
    std::string socks_backend_ = "none";
};

} // namespace clink::server::modules
