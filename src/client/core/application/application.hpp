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

namespace clink::core {

namespace network {
class TlsTransportAdapter;
}

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
    void shutdown();

    [[nodiscard]] const ApplicationOptions& options() const noexcept { return options_; }
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] const config::Configuration& configuration() const noexcept { return configuration_; }
    [[nodiscard]] std::shared_ptr<logging::Logger> logger() const noexcept { return logger_; }
    [[nodiscard]] ModuleRegistry& modules() noexcept { return *module_registry_; }
    [[nodiscard]] const ModuleRegistry& modules() const noexcept { return *module_registry_; }
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
    void connect_session();
    void disconnect_session();
    std::string get_session_status() const;

private:
    void initialize_logging();
    void log_lifecycle(const std::string& stage) const;
    void load_configuration();
    void start_modules();
    void stop_modules();
    void update_connect_status(std::string phase, std::string reason, std::string message = {});

    asio::io_context io_context_;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> io_work_;
    std::thread io_thread_;
    std::thread session_thread_;
    std::mutex session_command_mutex_;
    mutable std::mutex control_state_mutex_;
    std::mutex session_adapter_mutex_;
    std::shared_ptr<network::TlsTransportAdapter> active_adapter_;

    ApplicationOptions options_{};
    config::Configuration configuration_{};
    bool modules_started_{false};
    std::shared_ptr<logging::Logger> logger_;
    std::shared_ptr<ModuleRegistry> module_registry_;
    std::unique_ptr<ipc::IpcServer> ipc_server_;
    std::unique_ptr<ipc::IpcClient> ipc_client_;
    
    // Process Manager
    std::shared_ptr<void> process_manager_;
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
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
