#pragma once

#include <memory>
#include <mutex>
#include <asio.hpp>
#include "src/share/core/logging/logger.hpp"
#include "src/share/core/config/configuration.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

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

// 进程管理器：管理 SOCKS5 代理 + 进程注入链路的生命周期
// 负责：SOCKS 启动/停止、DLL 注入触发、注入连接会话管理、健康状态上报
class ProcessManager {
public:
    enum class StartState {
        Failed,   // 启动失败
        Ready,    // 完全就绪（SOCKS + 注入均可用）
        Degraded  // 降级运行（SOCKS 或注入不可用）
    };

    ProcessManager(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager = nullptr);
    ~ProcessManager();

    bool start(const clink::core::config::Configuration& config); // 启动：SocksServer + ProcessIPCServer + InjectLibrary
    void stop();                                                   // 停止所有子服务

    [[nodiscard]] StartState start_state() const noexcept { return start_state_; }
    [[nodiscard]] bool is_degraded() const noexcept { return start_state_ == StartState::Degraded; }
    [[nodiscard]] bool socks_available() const noexcept { return socks_available_; }    // SOCKS 是否可用
    [[nodiscard]] const std::string& start_reason() const noexcept { return start_reason_; }  // 启动结果说明
    [[nodiscard]] const std::string& socks_backend() const noexcept { return socks_backend_; } // 当前 SOCKS 后端：asio/winsock

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
    std::string start_reason_ = clink::protocol::control_plane::kStateNotStarted;
    std::string socks_backend_ = clink::protocol::control_plane::kValueNone;
};

} // namespace clink::server::modules
