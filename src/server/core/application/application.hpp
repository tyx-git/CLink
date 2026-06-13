#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <asio.hpp>

#include "src/share/core/config/configuration.hpp"
#include "src/share/core/logging/logger.hpp"
#include "src/server/core/registry.hpp"
#include "src/share/core/ipc/ipc.hpp"
#include "src/server/core/network/session_manager.hpp"
#include "src/server/core/security/auth.hpp"
#include "src/server/core/policy/engine.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#ifndef CLINK_SOURCE_DIR
#define CLINK_SOURCE_DIR "."
#endif

namespace clink::core {

inline std::filesystem::path default_config_path() {
    return std::filesystem::path{CLINK_SOURCE_DIR} / "config" / "clink.init.toml";
}

struct ApplicationOptions {
    std::string identity{"clink"};
    std::string role{"service"};
    std::chrono::milliseconds heartbeat_interval{std::chrono::seconds(5)};
    std::filesystem::path config_path{default_config_path()};
    logging::Level log_level{logging::Level::info};
    bool auto_reload_config{false};
};

class Application {
public:
    explicit Application(ApplicationOptions options = {});

    void initialize();
    void run();
    void shutdown(std::chrono::milliseconds timeout = std::chrono::seconds(5));
    void request_stop() noexcept { running_.store(false); }

    [[nodiscard]] const ApplicationOptions& options() const noexcept { return options_; }
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] const config::Configuration& configuration() const noexcept { return configuration_; }
    [[nodiscard]] std::shared_ptr<logging::Logger> logger() const noexcept { return logger_; }
    [[nodiscard]] ModuleRegistry& modules() noexcept { return *module_registry_; }
    [[nodiscard]] const ModuleRegistry& modules() const noexcept { return *module_registry_; }
    [[nodiscard]] network::SessionManager* session_manager() noexcept { return session_manager_.get(); }
    [[nodiscard]] asio::io_context& io_context() noexcept { return io_context_; }
    
    // IPC methods
    void start_ipc_server(const std::string& address);
    ipc::IpcClient& ipc_client();

    enum class SessionState {
        Disconnected,
        Connecting,
        Connected,
        Disconnecting
    };

    // Session methods
    std::string connect_session(const std::string& endpoint_override = "");
    void disconnect_session();
    std::string get_session_status() const;

    // Configuration methods
    void reload_configuration();
    void set_auto_reload(bool enable);

private:
    void initialize_logging();
    void log_lifecycle(const std::string& stage) const;
    void load_configuration();
    bool apply_configuration();
    bool apply_process_manager_runtime_configuration();
    void start_modules();
    void stop_modules();
    void setup_config_watcher(); 
    void start_config_watcher_timer();
    void setup_ipc_handlers();
    void on_session_event(network::SessionEvent event, const std::string& session_id);

    asio::io_context io_context_;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> io_work_;
    std::thread io_thread_;
    mutable std::mutex io_thread_state_mutex_;
    std::condition_variable io_thread_stopped_cv_;
    bool io_thread_stopped_{false};
    asio::steady_timer config_watcher_timer_{io_context_};

    ApplicationOptions options_{};
    config::Configuration configuration_{};
    bool modules_started_{false};
    std::shared_ptr<logging::Logger> logger_;
    std::shared_ptr<ModuleRegistry> module_registry_;
    std::shared_ptr<network::SessionManager> session_manager_;
    std::shared_ptr<security::AuthService> auth_service_;
    std::shared_ptr<security::CredentialStore> credential_store_;
    std::shared_ptr<policy::PolicyEngine> policy_engine_;
    std::unique_ptr<ipc::IpcServer> ipc_server_;
    std::unique_ptr<ipc::IpcClient> ipc_client_;
    
    // Process Manager (Handles IPC and SOCKS)
    std::shared_ptr<void> process_manager_; // Using void* to avoid header dependency
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_called_{false};
    std::atomic<bool> control_runtime_ready_{false};
    std::atomic<SessionState> session_state_{SessionState::Disconnected};
    std::atomic<int> active_session_count_{0};
    mutable std::mutex control_state_mutex_;
    std::string session_id_{clink::protocol::control_plane::kValueNone};
    std::string last_connect_phase_{clink::protocol::control_plane::kStatusIdle};
    std::string last_connect_reason_{clink::protocol::control_plane::kValueNone};
    std::string last_connect_message_{};
    std::string applied_listener_signature_{};
    std::string effective_ipc_address_{};
    std::string effective_process_manager_signature_{};
    std::string effective_logging_signature_{};

    // Watcher related
    std::atomic<bool> auto_reload_{false};
    std::filesystem::file_time_type last_config_time_;
};

}  // namespace clink::core
