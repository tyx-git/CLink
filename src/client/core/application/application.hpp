#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <asio.hpp>
#include <thread>

#include "src/share/core/config/configuration.hpp"
#include "src/share/core/logging/logger.hpp"
#include "src/client/core/registry.hpp"
#include "src/share/core/ipc/ipc.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#ifndef CLINK_SOURCE_DIR
#define CLINK_SOURCE_DIR "."
#endif

// 客户端 Application：比服务端精简，没有 session_manager 和可靠性引擎
// 职责：连接本地 daemon 的 IPC、维护出站 TLS/TCP 连接、转发状态
namespace clink::core {

namespace network {
class TlsTransportAdapter;
}

inline std::filesystem::path default_config_path() {
    return std::filesystem::path{CLINK_SOURCE_DIR} / "config" / "clink.init.toml";
}

struct ApplicationOptions {
    std::string identity{"clink"};               // 身份标识
    std::string role{"client"};                  // 角色：客户端
    std::chrono::milliseconds heartbeat_interval{std::chrono::seconds(5)};
    std::filesystem::path config_path{default_config_path()};
    logging::Level log_level{logging::Level::info};
    bool auto_reload_config{false};
};

// 客户端 Application：只维持 IPC 连接和出站 TLS 连接，不管理会话表
class Application {
public:
    explicit Application(ApplicationOptions options = {});

    void initialize();        // 加载配置、初始化日志、启动 IPC
    void run();               // 启动模块 + io_context 事件循环
    void shutdown();          // 停止所有资源

    [[nodiscard]] const ApplicationOptions& options() const noexcept { return options_; }
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] const config::Configuration& configuration() const noexcept { return configuration_; }
    [[nodiscard]] std::shared_ptr<logging::Logger> logger() const noexcept { return logger_; }
    [[nodiscard]] ModuleRegistry& modules() noexcept { return *module_registry_; }
    [[nodiscard]] const ModuleRegistry& modules() const noexcept { return *module_registry_; }
    [[nodiscard]] asio::io_context& io_context() noexcept { return io_context_; }
    
    void start_ipc_server(const std::string& address);  // 启动 IPC 服务端
    ipc::IpcClient& ipc_client();                         // 获取 IPC 客户端

    enum class SessionState {
        Disconnected,
        Connecting,
        Connected,
        Disconnecting
    };

    void connect_session();     // 发起出站 TLS 连接（在独立线程中执行）
    void disconnect_session();  // 断开当前连接
    std::string get_session_status() const;  // 收集状态 JSON

private:
    void initialize_logging();
    void log_lifecycle(const std::string& stage) const;
    void load_configuration();
    void start_modules();
    void stop_modules();
    void update_connect_status(std::string phase, std::string reason, std::string message = {}); // 更新连接阶段状态

    asio::io_context io_context_;                                     // 异步事件循环
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> io_work_;
    std::thread io_thread_;                                            // io_context 线程
    std::thread session_thread_;                                       // 出站连接独立线程
    std::mutex session_command_mutex_;                                  // 连接命令互斥
    mutable std::mutex control_state_mutex_;
    std::mutex session_adapter_mutex_;                                  // adapter 访问互斥
    std::shared_ptr<network::TlsTransportAdapter> active_adapter_;      // 当前活跃的 TLS 连接

    ApplicationOptions options_{};
    config::Configuration configuration_{};
    bool modules_started_{false};
    std::shared_ptr<logging::Logger> logger_;
    std::shared_ptr<ModuleRegistry> module_registry_;
    std::unique_ptr<ipc::IpcServer> ipc_server_;
    std::unique_ptr<ipc::IpcClient> ipc_client_;
    
    // Process Manager
    std::shared_ptr<void> process_manager_;
    
    std::atomic<bool> initialized_{false};   // initialize() 防重入
    std::atomic<bool> running_{false};         // run() 防重入 + 主循环退出条件
    std::atomic<SessionState> session_state_{SessionState::Disconnected};
    std::string session_id_{clink::protocol::control_plane::kValueNone};
    std::string last_connect_phase_{clink::protocol::control_plane::kStatusIdle};
    std::string last_connect_reason_{clink::protocol::control_plane::kValueNone};
    std::string last_connect_message_{};
    std::string effective_ipc_address_{};
    std::string effective_transport_signature_{};
    std::string effective_logging_signature_{};
};

}  // namespace clink::core
