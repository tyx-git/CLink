#include "server/include/clink/core/application.hpp"
#include "server/include/clink/core/logging/config.hpp"
#include "server/include/clink/core/network/session_manager_impl.hpp"
#include "server/include/clink/core/network/tcp_adapter.hpp"
#include "server/include/clink/core/network/tls_adapter.hpp"
#include "server/include/clink/core/network/acl.hpp"
#include "server/include/clink/core/security/psk_provider.hpp"
#include "server/include/clink/core/security/windows_store.hpp"
#include "server/include/clink/core/security/dpapi_helper.hpp"
#include "server/include/clink/core/policy/engine.hpp"
#include "server/include/clink/core/observability/telemetry.hpp"
#include "server/include/clink/server/modules/heartbeat.hpp"
#include "server/include/clink/server/modules/metrics.hpp"
#include "server/include/clink/server/modules/process_manager.hpp"
#include <cstdint>

#include <thread>
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <codecvt>
#include <locale>

#ifdef _WIN32
#include <winsock2.h>
#endif

namespace clink::core {

namespace {
#ifdef _WIN32
std::string to_utf8_safe(std::string input) {
    if (input.empty()) {
        return input;
    }

    // Fast path: already valid UTF-8
    if (nlohmann::json::accept("\"" + input + "\"")) {
        return input;
    }

    const int wide_len = MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, nullptr, 0);
    if (wide_len <= 0) {
        return "windows_error_non_utf8";
    }

    std::wstring wide(static_cast<size_t>(wide_len), L'\0');
    MultiByteToWideChar(CP_ACP, 0, input.c_str(), -1, wide.data(), wide_len);

    const int utf8_len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8_len <= 0) {
        return "windows_error_non_utf8";
    }

    std::string out(static_cast<size_t>(utf8_len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, out.data(), utf8_len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}
#else
std::string to_utf8_safe(std::string input) {
    return input;
}
#endif
} // namespace

Application::Application(ApplicationOptions options)
    : io_work_(std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(io_context_.get_executor())),
      options_(std::move(options)),
      logger_(std::make_shared<logging::Logger>(options_.identity)),
      module_registry_(std::make_shared<ModuleRegistry>()) {
    // Set initial log level from options
    logger_->set_level(options_.log_level);
}

void Application::initialize() {
    bool expected = false;
    if (!initialized_.compare_exchange_strong(expected, true)) {
        return;
    }

    log_lifecycle("initializing subsystems");

#ifdef _WIN32
    logger_->info("[init] stage=winsock_startup.begin");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        logger_->error("[init] stage=winsock_startup.failed");
        logger_->error("Failed to initialize Winsock");
        return;
    }
    logger_->info("[init] stage=winsock_startup.ok");
#endif

    try {
        logger_->info("[init] stage=load_configuration.begin");
        load_configuration();
        logger_->info("[init] stage=load_configuration.ok");

        logger_->info("[init] stage=initialize_logging.begin");
        initialize_logging();
        logger_->info("[init] stage=initialize_logging.ok");

        logger_->info("[init] stage=security_policy_init.begin");
        credential_store_ = std::make_shared<security::WindowsCredentialStore>();
        auth_service_ = std::make_shared<security::PskAuthProvider>();
        policy_engine_ = std::make_shared<policy::PolicyEngine>();
        policy_engine_->load_from_config(configuration_);
        logger_->info("[init] stage=security_policy_init.ok");

        logger_->info("[init] stage=apply_configuration.begin");
        apply_configuration();
        logger_->info("[init] stage=apply_configuration.ok");

        if (!ipc_server_ && options_.role == "service") {
            logger_->info("[init] stage=ipc_server.start_default.begin");
            ipc_server_ = ipc::create_server(logger_);
#ifdef _WIN32
            ipc_server_->start("\\\\.\\pipe\\clink-ipc");
#else
            ipc_server_->start("/tmp/clink-ipc.sock");
#endif
            logger_->info("[init] stage=ipc_server.start_default.ok");
        }

        logger_->info("[init] stage=ipc_handlers.begin");
        setup_ipc_handlers();
        logger_->info("[init] stage=ipc_handlers.ok");

        if (options_.role == "service") {
            bool enable_process_manager = configuration_.get_bool("process_manager.enabled", true);
            if (const char* env_disable_pm = std::getenv("CLINK_DISABLE_PROCESS_MANAGER")) {
                if (std::string(env_disable_pm) == "1") {
                    enable_process_manager = false;
                }
            }

            logger_->info(std::string("[init] stage=process_manager.enabled=") + (enable_process_manager ? "true" : "false"));

            if (enable_process_manager) {
                try {
                    logger_->info("[init] stage=process_manager.create.begin");
                    auto pm = std::make_shared<clink::server::modules::ProcessManager>(io_context_, logger_, session_manager_);
                    logger_->info("[init] stage=process_manager.create.ok");

                    logger_->info("[init] stage=process_manager.start.begin");
                    const auto pm_start_t0 = std::chrono::steady_clock::now();
                    const bool pm_started = pm->start(configuration_);
                    const auto pm_start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - pm_start_t0).count();

                    logger_->info("[init] stage=process_manager.start.elapsed_ms", pm_start_ms);
                    if (pm_start_ms > 3000) {
                        logger_->warn("[init] stage=process_manager.start.slow elapsed_ms", pm_start_ms);
                    }

                    if (pm_started) {
                        process_manager_ = pm;
                        const auto pm_state = pm->start_state();
                        if (pm_state == clink::server::modules::ProcessManager::StartState::Ready) {
                            logger_->info("[init] stage=process_manager.start.ok mode=ready");
                        } else if (pm_state == clink::server::modules::ProcessManager::StartState::Degraded) {
                            logger_->warn("[init] stage=process_manager.start.ok mode=degraded socks_available=false");
                        } else {
                            logger_->warn("[init] stage=process_manager.start.ok mode=unknown");
                        }
                    } else {
                        logger_->warn("[init] stage=process_manager.start.failed_return_false");
                    }
                } catch (const std::exception& ex) {
                    logger_->error(std::string("[init] stage=process_manager.start.exception: ") + ex.what());
                } catch (...) {
                    logger_->error("[init] stage=process_manager.start.exception: unknown");
                }
            } else {
                logger_->warn("[init] stage=process_manager.skip.disabled");
            }
        }

        if (options_.auto_reload_config) {
            logger_->info("[init] stage=auto_reload.begin");
            set_auto_reload(true);
            logger_->info("[init] stage=auto_reload.ok");
        }
    } catch (const std::exception& e) {
        logger_->error(std::string("[init] failed with exception: ") + e.what());
        throw;
    }
}

void Application::apply_configuration() {
    bool vif_enabled = configuration_.get_bool("network.virtual_interface.enabled", true);
    if (const char* env_disable_vif = std::getenv("CLINK_DISABLE_VIF")) {
        if (std::string(env_disable_vif) == "1") {
            vif_enabled = false;
        }
    }

    if (!session_manager_) {
        logger_->info("[apply] stage=session_manager.create.begin");
        session_manager_ = network::create_session_manager(io_context_, logger_);
        if (!session_manager_) {
            logger_->error("[apply] stage=session_manager.create.failed");
            logger_->warn("[apply] session manager unavailable, continue in degraded mode");
        } else {
            logger_->info("[apply] stage=session_manager.create.ok");

            if (auto* impl = dynamic_cast<network::DefaultSessionManager*>(session_manager_.get())) {
                impl->set_virtual_interface_enabled(vif_enabled);

                const bool zero_copy_enabled = configuration_.get_bool("network.zerocopy.enabled", true);
                impl->set_zero_copy_enabled(zero_copy_enabled);
                logger_->info(std::string("[apply] stage=session_manager.zerocopy=") + (zero_copy_enabled ? "true" : "false"));

                impl->set_session_event_callback([this](network::SessionEvent event, const std::string& session_id) {
                    asio::post(io_context_, [this, event, session_id]() {
                        on_session_event(event, session_id);
                    });
                });
                logger_->info(std::string("[apply] stage=session_manager.vif.preinit=") + (vif_enabled ? "true" : "false"));
            }

            logger_->info("[apply] stage=session_manager.initialize.begin");
            auto init_ec = session_manager_->initialize();
            if (init_ec) {
                logger_->error("[apply] stage=session_manager.initialize.failed: " + init_ec.message());
                logger_->warn("[apply] session manager init reported error, continue in degraded mode");
            } else {
                logger_->info("[apply] stage=session_manager.initialize.ok");
            }
        }
    }

    if (session_manager_) {
        // 1. 应用 ACL 配置
        auto acl = std::make_shared<network::AccessControlList>(logger_);
        if (configuration_.contains("network.acl.whitelist")) {
            acl->load_from_string(configuration_.get_string("network.acl.whitelist"));
        }
        
        auto* impl = dynamic_cast<network::DefaultSessionManager*>(session_manager_.get());
        if (impl) {
            impl->set_acl(std::move(acl));
            impl->set_policy_engine(policy_engine_);

            impl->set_virtual_interface_enabled(vif_enabled);
            logger_->info(std::string("[apply] stage=session_manager.vif.enabled=") + (vif_enabled ? "true" : "false"));

            const bool zero_copy_enabled = configuration_.get_bool("network.zerocopy.enabled", true);
            impl->set_zero_copy_enabled(zero_copy_enabled);
            logger_->info(std::string("[apply] stage=session_manager.zerocopy=") + (zero_copy_enabled ? "true" : "false"));

            int idle_timeout_sec = configuration_.get_int("network.session_idle_timeout_sec", 0);
            if (idle_timeout_sec < 0) {
                idle_timeout_sec = 0;
            }
            impl->set_session_idle_timeout(std::chrono::seconds(idle_timeout_sec));
            logger_->info("[apply] stage=session_manager.idle_timeout_sec", idle_timeout_sec);

            const bool reliability_timer_enabled = configuration_.get_bool("network.reliability_timer_enabled", true);
            impl->set_reliability_timer_enabled(reliability_timer_enabled);
            logger_->info("[apply] stage=session_manager.reliability_timer_enabled", reliability_timer_enabled ? "true" : "false");
        }

        // 2. 应用全局带宽限制
        if (configuration_.contains("network.bandwidth_limit")) {
            int limit = configuration_.get_int("network.bandwidth_limit", 0);
            if (limit > 0) {
                session_manager_->set_default_rate_limit(static_cast<size_t>(limit), static_cast<size_t>(limit * 2));
            }
        }

        // 3. 启动监听
        std::string endpoint = configuration_.get_string("network.listen_endpoint", "0.0.0.0:443");
        if (!endpoint.empty()) {
            std::unique_ptr<network::TransportListener> listener;
            logger_->info("[apply] stage=listener.prepare endpoint=" + endpoint);

            if (endpoint.rfind("tls://", 0) == 0) {
                auto tls_listener = std::make_unique<network::TlsTransportListener>(io_context_, logger_);

                std::string ca_cert = configuration_.get_string("network.tls.ca_cert", "config/certs/ca.crt");
                std::string server_cert = configuration_.get_string("network.tls.server_cert", "config/certs/server.crt");
                std::string server_key = configuration_.get_string("network.tls.server_key", "config/certs/server.key");
                logger_->info("[apply] stage=listener.tls.certs ca=" + ca_cert + " cert=" + server_cert + " key=" + server_key);

                tls_listener->set_certificates(ca_cert, server_cert, server_key);

                if (configuration_.contains("network.tls.pinned_client_cert")) {
                    const auto pinned = configuration_.get_string("network.tls.pinned_client_cert");
                    logger_->info("[apply] stage=listener.tls.pinned_client_cert.set");
                    tls_listener->set_pinned_certificate_hash(pinned);
                }

                listener = std::move(tls_listener);
                endpoint = endpoint.substr(6); // 移除 tls://
                logger_->info("[apply] stage=listener.transport tls endpoint=" + endpoint);
            } else {
                listener = std::make_unique<network::TcpTransportListener>(io_context_, logger_);
                if (endpoint.rfind("tcp://", 0) == 0) {
                    endpoint = endpoint.substr(6);
                }
                logger_->info("[apply] stage=listener.transport tcp endpoint=" + endpoint);
            }

            logger_->info("[apply] stage=listener.start.begin endpoint=" + endpoint);
            session_manager_->start_listen(std::move(listener), endpoint);
            logger_->info("[apply] stage=listener.start.ok endpoint=" + endpoint);
        } else {
            logger_->warn("[apply] stage=listener.skip.empty_endpoint");
        }
    }

    // 4. 更新模块配置
    if (module_registry_) {
        module_registry_->configure_all(configuration_);
    }

    // 5. 应用策略配置 (Policy Engine)
    if (policy_engine_) {
        policy_engine_->load_from_config(configuration_);
        logger_->info("[app] policy engine loaded with global and hierarchical rules");
    }

    // 6. 应用认证配置
    if (auth_service_) {
        auto* psk_provider = dynamic_cast<security::PskAuthProvider*>(auth_service_.get());
        if (psk_provider) {
            bool config_changed = false;
            // 从配置中加载加密的 PSK 列表
            // 配置格式示例: auth.psk_list = ["user1:Base64EncryptedSecret", "user2:..."]
            if (configuration_.contains("auth.psk_list")) {
                auto list = configuration_.get_list("auth.psk_list");
                std::vector<std::string> updated_list;

                for (const auto& entry : list) {
                    auto pos = entry.find(':');
                    if (pos != std::string::npos) {
                        std::string user_id = entry.substr(0, pos);
                        std::string secret_part = entry.substr(pos + 1);
                        
                        try {
                            // 尝试判定是否已经是加密的 Base64 (简单启发式：长度较长且包含特殊字符)
                            // 更好的办法是：尝试解密，失败则认为是明文
                            std::string psk;
                            bool is_encrypted = false;
                            
                            try {
                                std::string encrypted = security::DpapiHelper::from_base64(secret_part);
                                psk = security::DpapiHelper::decrypt(encrypted);
                                is_encrypted = true;
                            } catch (...) {
                                // 解密失败，认为是明文
                                psk = secret_part;
                                is_encrypted = false;
                            }

                            if (!is_encrypted) {
                                // 强制加密明文
                                std::string new_encrypted = security::DpapiHelper::encrypt(psk);
                                std::string new_base64 = security::DpapiHelper::to_base64(new_encrypted);
                                updated_list.push_back(user_id + ":" + new_base64);
                                config_changed = true;
                                logger_->info("[app] auto-encrypted psk for user: " + user_id);
                            } else {
                                updated_list.push_back(entry);
                            }
                            
                            psk_provider->add_user(user_id, psk);
                        } catch (const std::exception& e) {
                            logger_->error(std::string("[app] failed to process psk for ") + user_id + ": " + e.what());
                        }
                    }
                }

                if (config_changed) {
                    // 构建回写的字符串列表格式 [ "a:b", "c:d" ]
                    std::string toml_list = "[";
                    for (size_t i = 0; i < updated_list.size(); ++i) {
                        toml_list += "\"" + updated_list[i] + "\"";
                        if (i < updated_list.size() - 1) toml_list += ", ";
                    }
                    toml_list += "]";
                    
                    configuration_.set("auth.psk_list", toml_list);
                    configuration_.save();
                    logger_->info("[app] configuration updated with encrypted credentials");
                }
            }
        }
    }

    // 7. 初始化并注册模块 (如果尚未注册)
    if (module_registry_->empty()) {
        module_registry_->emplace_module<modules::HeartbeatModule>(logger_);
        module_registry_->emplace_module<modules::MetricsModule>(logger_, session_manager_);
        module_registry_->configure_all(configuration_);
    }
}

void Application::reload_configuration() {
    load_configuration();
    
    // 重新初始化日志 (如果配置变了)
    initialize_logging();
    
    logger_->info("[app] configuration reloaded successfully");
    apply_configuration();
}

void Application::set_auto_reload(bool enable) {
    if (auto_reload_ == enable) return;
    auto_reload_ = enable;
    
    if (enable) {
        if (std::filesystem::exists(options_.config_path)) {
            last_config_time_ = std::filesystem::last_write_time(options_.config_path);
        }
        setup_config_watcher();
    } else {
        config_watcher_timer_.cancel();
    }
}

void Application::setup_config_watcher() {
    start_config_watcher_timer();
}

void Application::start_config_watcher_timer() {
    if (!auto_reload_.load()) return;

    config_watcher_timer_.expires_after(std::chrono::seconds(2));
    config_watcher_timer_.async_wait([this](std::error_code ec) {
        if (ec) return;

        try {
            if (std::filesystem::exists(options_.config_path)) {
                auto current_time = std::filesystem::last_write_time(options_.config_path);
                if (current_time != last_config_time_) {
                    last_config_time_ = current_time;
                    reload_configuration();
                }
            }
        } catch (const std::exception& e) {
            if (logger_) logger_->error(std::string("[watcher] error checking config file: ") + e.what());
        }

        start_config_watcher_timer();
    });
}

void Application::setup_ipc_handlers() {
    if (ipc_server_) {
        ipc_server_->set_handler([this](const ipc::Message& req) -> ipc::Message {
            auto json_escape = [](const std::string& input) -> std::string {
                std::string out;
                out.reserve(input.size() + 16);
                for (char c : input) {
                    switch (c) {
                        case '\\': out += "\\\\"; break;
                        case '"': out += "\\\""; break;
                        case '\n': out += "\\n"; break;
                        case '\r': out += "\\r"; break;
                        case '\t': out += "\\t"; break;
                        default: out.push_back(c); break;
                    }
                }
                return out;
            };

            auto ok_payload = [&](const std::string& command, const std::string& data_json) -> std::string {
                return "{\"ok\":true,\"command\":\"" + command + "\",\"data\":" + data_json + "}";
            };

            auto error_payload = [&](const std::string& command, const std::string& message) -> std::string {
                return "{\"ok\":false,\"command\":\"" + command + "\",\"error\":\"" + json_escape(message) + "\"}";
            };

            try {
                if (req.command == "reload") {
                    reload_configuration();
                    return {ipc::MessageType::Response, "reload", ok_payload("reload", "{\"status\":\"ok\"}")};
                }
                if (req.command == "status") {
                    return {ipc::MessageType::Response, "status", ok_payload("status", get_session_status())};
                }
                if (req.command == "connect") {
                    const auto connect_result = connect_session(req.payload);
                    return {ipc::MessageType::Response, "connect", ok_payload("connect", connect_result)};
                }
                if (req.command == "disconnect") {
                    disconnect_session();
                    return {ipc::MessageType::Response, "disconnect", ok_payload("disconnect", "{\"status\":\"disconnecting\"}")};
                }
                if (req.command == "logs") {
                    std::string log_path = "logs/clink-daemon.log";
                    std::ifstream log_file(log_path, std::ios::binary);
                    if (!log_file.is_open()) {
                        return {ipc::MessageType::Response, "logs", error_payload("logs", "failed to open log file")};
                    }

                    log_file.seekg(0, std::ios::end);
                    std::streamoff end_pos = log_file.tellg();
                    std::streamoff start_pos = (end_pos > 2000) ? (end_pos - 2000) : 0;

                    log_file.seekg(start_pos);
                    std::string content((std::istreambuf_iterator<char>(log_file)), std::istreambuf_iterator<char>());

                    if (start_pos > 0) {
                        auto first_newline = content.find('\n');
                        if (first_newline != std::string::npos) {
                            content = content.substr(first_newline + 1);
                        }
                    }

                    return {
                        ipc::MessageType::Response,
                        "logs",
                        ok_payload("logs", "{\"content\":\"" + json_escape(content) + "\"}")
                    };
                }
                return {ipc::MessageType::Response, req.command, error_payload(req.command, "unknown command")};
            } catch (const std::exception& ex) {
                logger_->error(std::string("[ipc] handler exception command=") + req.command + " error=" + ex.what());
                return {ipc::MessageType::Response, req.command,
                        error_payload(req.command, std::string("handler_exception: ") + ex.what())};
            } catch (...) {
                logger_->error(std::string("[ipc] handler unknown exception command=") + req.command);
                return {ipc::MessageType::Response, req.command,
                        error_payload(req.command, "handler_exception: unknown")};
            }
        });
    }
}

void Application::run() {
    if (!initialized_) {
        initialize();
    }

    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;
    }

    log_lifecycle("entering event loop");

    // Start Asio I/O thread
    io_thread_ = std::thread([this]() {
        logger_->info("[app] asio io_context started");
        io_context_.run();
        logger_->info("[app] asio io_context stopped");
    });

    start_modules();

    // Main event loop
    while (running_.load()) {
        std::this_thread::sleep_for(options_.heartbeat_interval);
        // We can add periodic background tasks here if needed
    }

    log_lifecycle("event loop exited");
    // Modules are stopped by shutdown() to avoid duplicate stop during signal-driven shutdown.
}

void Application::shutdown(std::chrono::milliseconds /*timeout*/) {
    bool expected_shutdown = false;
    if (!shutdown_called_.compare_exchange_strong(expected_shutdown, true)) {
        return; // already shut down (or shutting down)
    }

    if (!initialized_) {
        return;
    }

    running_.store(false);
    log_lifecycle("shutting down subsystems");

    // Stop modules first, then I/O thread/resources
    stop_modules();

    // Stop Asio
    io_work_.reset();
    io_context_.stop();
    if (io_thread_.joinable()) {
        io_thread_.join();
    }

    if (session_manager_) {
        session_manager_->shutdown();
    }

#ifdef _WIN32
    WSACleanup();
#endif

    log_lifecycle("shutdown complete");
}

void Application::log_lifecycle(const std::string& stage) const {
    logger_->info("[" + options_.role + "|" + options_.identity + "] " + stage);
}

void Application::load_configuration() {
    if (options_.config_path.empty()) {
        return;
    }

    try {
        configuration_ = config::Configuration::load_from_file(options_.config_path);
        logger_->info("Loaded configuration from " + options_.config_path.string());
    } catch (const std::exception& e) {
        logger_->error(std::string("Failed to load configuration: ") + e.what());
    }
}

void Application::initialize_logging() {
    // Check if we have logging configuration
    if (configuration_.contains("logging.level") || configuration_.contains("logging.sinks")) {
        // Initialize logging system from configuration
        logging::initialize_logging(configuration_);

        // Recreate logger with new configuration
        auto log_config = logging::LogConfig::from_toml(configuration_);
        logger_ = logging::create_logger(options_.identity, log_config);

        // Update log level from configuration
        if (configuration_.contains("logging.level")) {
            logger_->set_level(log_config.level);
        }
    } else {
        // No logging configuration, just update level from options
        logger_->set_level(options_.log_level);
    }
}

void Application::start_modules() {
    if (modules_started_) {
        return;
    }
    log_lifecycle("starting modules");
    module_registry_->start_all();
    modules_started_ = true;
}

void Application::stop_modules() {
    if (!modules_started_) {
        return;
    }
    log_lifecycle("stopping modules");
    module_registry_->stop_all();
    modules_started_ = false;
}

void Application::start_ipc_server(const std::string& address) {
    if (!ipc_server_) {
        ipc_server_ = ipc::create_server(logger_);
    }
    
    setup_ipc_handlers();
    ipc_server_->start(address);
}

ipc::IpcClient& Application::ipc_client() {
    if (!ipc_client_) {
        ipc_client_ = ipc::create_client(logger_);
    }
    return *ipc_client_;
}

std::string Application::get_session_status() const {
    const auto state = session_state_.load();
    std::string state_str;
    switch (state) {
        case SessionState::Disconnected:  state_str = "disconnected"; break;
        case SessionState::Connecting:    state_str = "connecting"; break;
        case SessionState::Connected:     state_str = "connected"; break;
        case SessionState::Disconnecting: state_str = "disconnecting"; break;
    }

    std::string result = "{";
    result += "\"status\": \"" + state_str + "\", ";
    result += "\"session_id\": \"" + session_id_ + "\", ";
    result += "\"connect_phase\": \"" + last_connect_phase_ + "\", ";
    result += "\"connect_reason\": \"" + last_connect_reason_ + "\"";
    if (!last_connect_message_.empty()) {
        result += ", \"connect_message\": \"" + last_connect_message_ + "\"";
    }

    {
        bool pm_enabled = false;
        bool pm_socks_available = false;
        std::string pm_state = "not_started";
        std::string pm_reason = "not_started";

        if (process_manager_) {
            pm_enabled = true;
            auto pm = std::static_pointer_cast<clink::server::modules::ProcessManager>(process_manager_);
            if (pm) {
                pm_socks_available = pm->socks_available();
                pm_reason = pm->start_reason();
                const auto s = pm->start_state();
                if (s == clink::server::modules::ProcessManager::StartState::Ready) {
                    pm_state = "ready";
                } else if (s == clink::server::modules::ProcessManager::StartState::Degraded) {
                    pm_state = "degraded";
                } else {
                    pm_state = "failed";
                }
            } else {
                pm_state = "invalid_ref";
            }
        }

        std::string health = "green";
        if (!pm_enabled || pm_state == "failed") {
            health = "red";
        } else if (pm_state == "degraded") {
            health = "yellow";
        }

        result += ", \"health\": \"" + health + "\"";
        result += ", \"process_manager\": {";
        std::string pm_socks_backend = "none";
        if (process_manager_) {
            auto pm = std::static_pointer_cast<clink::server::modules::ProcessManager>(process_manager_);
            if (pm) {
                pm_socks_backend = pm->socks_backend();
            }
        }

        result += "\"enabled\": " + std::string(pm_enabled ? "true" : "false") + ", ";
        result += "\"state\": \"" + pm_state + "\", ";
        result += "\"reason\": \"" + pm_reason + "\", ";
        result += "\"socks_backend\": \"" + pm_socks_backend + "\", ";
        result += "\"socks_available\": " + std::string(pm_socks_available ? "true" : "false");
        result += "}";
    }

    result += ", ";

    if (session_manager_) {
        auto sessions = session_manager_->get_active_sessions();
        if (logger_) {
            logger_->info("[status.stage] app_state=" + std::to_string(static_cast<int>(state)) +
                          " app_state_text=" + state_str +
                          " active_sessions=" + std::to_string(sessions.size()) +
                          " session_id='" + session_id_ + "'");
        }
        result += "\"active_sessions\": " + std::to_string(sessions.size());
        
        if (!sessions.empty()) {
            result += ", \"sessions\": [";
            for (size_t i = 0; i < sessions.size(); ++i) {
                const auto& s = sessions[i];
                result += "{";
                result += "\"id\": \"" + s.session_id + "\", ";
                result += "\"user_id\": \"" + s.user_id + "\", ";
                result += "\"remote_endpoint\": \"" + s.remote_endpoint + "\", ";
                result += "\"bytes_sent\": " + std::to_string(s.bytes_sent) + ", ";
                result += "\"bytes_received\": " + std::to_string(s.bytes_received) + ", ";
                result += "\"rtt_ms\": " + std::to_string(s.rtt.count()) + ", ";
                result += "\"rto_ms\": " + std::to_string(s.rto.count()) + ", ";
                result += "\"retrans_count\": " + std::to_string(s.retransmission_count) + ", ";
                result += "\"corrupted_packets\": " + std::to_string(s.corrupted_packets) + ", ";
                result += "\"latency_distribution\": {";
                result += "\"<10ms\": " + std::to_string(s.latency_bucket_10ms) + ", ";
                result += "\"10-50ms\": " + std::to_string(s.latency_bucket_50ms) + ", ";
                result += "\"50-100ms\": " + std::to_string(s.latency_bucket_100ms) + ", ";
                result += "\"100-200ms\": " + std::to_string(s.latency_bucket_200ms) + ", ";
                result += "\"200-500ms\": " + std::to_string(s.latency_bucket_500ms) + ", ";
                result += "\"500ms-1s\": " + std::to_string(s.latency_bucket_1s) + ", ";
                result += "\">1s\": " + std::to_string(s.latency_bucket_inf);
                result += "}";
                result += "}";
                if (i < sessions.size() - 1) result += ", ";
            }
            result += "]";
        }
    } else {
        result += "\"active_sessions\": 0";
    }
    
    result += "}";
    return result;
}

void Application::on_session_event(network::SessionEvent event, const std::string& event_session_id) {
    switch (event) {
        case network::SessionEvent::Connected: {
            const int prev_count = active_session_count_.fetch_add(1);
            if (prev_count == 0) {
                const auto prev_state = session_state_.load();
                session_state_ = SessionState::Connected;
                session_id_ = event_session_id;
                logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev_state)) + "->" +
                              std::to_string(static_cast<int>(SessionState::Connected)) +
                              " reason=engine_start_ok session_id=" + event_session_id);
            } else {
                logger_->info("[connect.state] connected_event additional_session session_id=" + event_session_id +
                              " active_count=" + std::to_string(prev_count + 1));
            }
            break;
        }
        case network::SessionEvent::Disconnected: {
            int current = active_session_count_.load();
            while (current > 0 && !active_session_count_.compare_exchange_weak(current, current - 1)) {
            }
            const int new_count = active_session_count_.load();
            logger_->info("[connect.state] disconnected_event session_id=" + event_session_id +
                          " active_count=" + std::to_string(new_count));
            if (new_count == 0) {
                const auto prev_state = session_state_.load();
                session_state_ = SessionState::Disconnected;
                session_id_ = "none";
                logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev_state)) + "->" +
                              std::to_string(static_cast<int>(SessionState::Disconnected)) +
                              " reason=session_closed");
            }
            break;
        }
    }
}

std::string Application::connect_session(const std::string& endpoint_override) {
    using json = nlohmann::json;
    logger_->info("[connect.stage] enter payload_bytes=" + std::to_string(endpoint_override.size()));
    if (!endpoint_override.empty()) {
        logger_->info("[connect.stage] payload.raw=" + endpoint_override);
    }

    auto parse_override = [](const std::string& raw) {
        struct Override {
            std::string endpoint;
            std::string transport;
            int timeout_ms = 0;
            bool no_self_check = false;
        } out;

        if (raw.empty()) return out;

        auto j = json::parse(raw, nullptr, false);
        if (j.is_discarded() || !j.is_object()) {
            // Backward compatible: raw may be a plain endpoint string
            out.endpoint = raw;
            return out;
        }

        if (j.contains("endpoint") && j.at("endpoint").is_string()) {
            out.endpoint = j.at("endpoint").get<std::string>();
        }
        if (j.contains("transport") && j.at("transport").is_string()) {
            out.transport = j.at("transport").get<std::string>();
        }
        if (j.contains("timeout_ms") && j.at("timeout_ms").is_number_integer()) {
            out.timeout_ms = j.at("timeout_ms").get<int>();
        }
        if (j.contains("no_self_check") && j.at("no_self_check").is_boolean()) {
            out.no_self_check = j.at("no_self_check").get<bool>();
        }
        return out;
    };

    auto tracer = observability::Telemetry::get_tracer("clink-app");
    observability::ScopedSpan span(tracer->start_span("connect_session"));

    auto make_result = [this](bool accepted, std::string status, std::string reason,
                               std::string message = "", std::string endpoint = "", std::string session_id = "") {
        message = to_utf8_safe(std::move(message));
        last_connect_phase_ = status;
        last_connect_reason_ = reason;
        last_connect_message_ = message;

        json data;
        data["accepted"] = accepted;
        data["status"] = std::move(status);
        data["reason"] = std::move(reason);
        if (!message.empty()) data["message"] = std::move(message);
        if (!endpoint.empty()) data["endpoint"] = std::move(endpoint);
        if (!session_id.empty()) data["session_id"] = std::move(session_id);
        return data.dump();
    };

    if (session_state_.load() != SessionState::Disconnected) {
        logger_->warn("Cannot connect: session is already active or in transition");
        span->add_event("connection_aborted_active_session");
        logger_->info("connect.final status=rejected reason=session_not_disconnected");
        return make_result(false, "rejected", "session_not_disconnected");
    }

    if (!session_manager_) {
        logger_->error("[app] cannot connect: session manager unavailable");
        span->set_attribute("error", "no_session_manager");
        logger_->info("connect.final status=rejected reason=no_session_manager");
        return make_result(false, "rejected", "no_session_manager");
    }

    logger_->info("[connect.stage] parse_override.begin");
    const auto ov = parse_override(endpoint_override);
    logger_->info("[connect.stage] parse_override.ok endpoint_present=" + std::string(ov.endpoint.empty() ? "false" : "true") +
                  " transport_override=" + (ov.transport.empty() ? std::string("none") : ov.transport) +
                  " timeout_ms=" + std::to_string(ov.timeout_ms) +
                  " no_self_check=" + std::string(ov.no_self_check ? "true" : "false"));

    std::string endpoint = ov.endpoint;
    if (endpoint.empty()) {
        endpoint = configuration_.get_string("client.remote_endpoint");
    }
    if (endpoint.empty()) {
        logger_->error("[app] cannot connect: endpoint not set (payload/config both empty)");
        span->set_attribute("error", "missing_endpoint");
        logger_->info("connect.final status=rejected reason=missing_endpoint");
        return make_result(false, "rejected", "missing_endpoint");
    }

    auto normalize_endpoint = [](std::string ep) {
        std::string transport = "tcp";
        if (ep.rfind("tls://", 0) == 0) {
            transport = "tls";
            ep = ep.substr(6);
        } else if (ep.rfind("tcp://", 0) == 0) {
            ep = ep.substr(6);
        }
        return std::pair<std::string, std::string>{transport, ep};
    };

    if (!ov.transport.empty() && (ov.transport == "tcp" || ov.transport == "tls")) {
        auto [existing_transport, hostport] = normalize_endpoint(endpoint);
        (void)existing_transport;
        endpoint = ov.transport + "://" + hostport;
    }

    auto [target_transport, target_hostport] = normalize_endpoint(endpoint);
    logger_->info("[connect.stage] normalized_target transport=" + target_transport + " hostport=" + target_hostport);
    auto target_colon = target_hostport.rfind(':');
    std::string target_host = (target_colon == std::string::npos) ? "" : target_hostport.substr(0, target_colon);
    std::string target_port = (target_colon == std::string::npos) ? "" : target_hostport.substr(target_colon + 1);

    if (options_.role == "service") {

        std::string listen_ep = configuration_.get_string("network.listen_endpoint", "");
        auto [listen_transport, listen_hostport] = normalize_endpoint(listen_ep);

        bool allow_self_connect_debug = configuration_.get_bool("network.allow_self_connect_for_debug", false);
        const bool allow_self_connect = configuration_.get_bool("network.allow_self_connect", false);
        if (const char* env_allow = std::getenv("CLINK_ALLOW_SELF_CONNECT_DEBUG")) {
            if (std::string(env_allow) == "1") {
                allow_self_connect_debug = true;
            }
        }

        if (const char* env_force_off = std::getenv("CLINK_FORCE_DISABLE_SELF_CONNECT_DEBUG")) {
            if (std::string(env_force_off) == "1") {
                allow_self_connect_debug = false;
                logger_->warn("[connect.stage] self-connect debug forcibly disabled by CLINK_FORCE_DISABLE_SELF_CONNECT_DEBUG=1");
            }
        }
        logger_->info("[connect.stage] normalized_listener transport=" + listen_transport + " hostport=" + listen_hostport);
        auto listen_colon = listen_hostport.rfind(':');
        std::string listen_host = (listen_colon == std::string::npos) ? "" : listen_hostport.substr(0, listen_colon);
        std::string listen_port = (listen_colon == std::string::npos) ? "" : listen_hostport.substr(listen_colon + 1);

        if (!listen_transport.empty() && !target_transport.empty() && listen_transport != target_transport) {
            bool allow_mismatch = false;
            if (const char* env_allow = std::getenv("CLINK_ALLOW_TRANSPORT_MISMATCH")) {
                if (std::string(env_allow) == "1") {
                    allow_mismatch = true;
                }
            }

            if (!allow_mismatch) {
                logger_->warn("[app] connect rejected: transport mismatch (target=" + target_transport + ", listener=" + listen_transport + ")");
                span->set_attribute("error", "transport_mismatch");
                const std::string msg = "target transport does not match listener transport (listener=" + listen_transport + ")";
                logger_->info("connect.final status=rejected reason=transport_mismatch endpoint=" + endpoint);
                return make_result(false, "rejected", "transport_mismatch", msg, endpoint);
            }

            logger_->warn("[app] transport mismatch allowed by env override (CLINK_ALLOW_TRANSPORT_MISMATCH=1)");
        }

        auto is_local_host = [](const std::string& h) {
            return h == "127.0.0.1" || h == "localhost" || h == "0.0.0.0" || h == "::1" || h == "::";
        };

        const bool self_connect = !target_port.empty() && target_port == listen_port &&
                                  target_transport == listen_transport &&
                                  is_local_host(target_host) && is_local_host(listen_host);

        bool allow_self_connect_effective = allow_self_connect;
        if (allow_self_connect_debug || ov.no_self_check) {
            allow_self_connect_effective = true;
        }

        if (self_connect && !allow_self_connect_effective) {
            logger_->error("[app] connect aborted: endpoint resolves to local listener (self-connect disabled by default): " + endpoint);
            span->set_attribute("error", "self_connect_blocked");
            logger_->info("connect.final status=rejected reason=self_connect_blocked endpoint=" + endpoint);
            return make_result(false, "rejected", "self_connect_blocked", "Connecting to local listener is disabled by default", endpoint);
        }

        if (self_connect && allow_self_connect_effective) {
            logger_->warn("[app] self-connect override enabled, proceeding: " + endpoint);
        }
    }

    span->set_attribute("endpoint", endpoint);

    {
        const auto prev = session_state_.load();
        session_state_ = SessionState::Connecting;
        logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev)) + "->" +
                      std::to_string(static_cast<int>(SessionState::Connecting)) +
                      " reason=transport_start.begin endpoint=" + endpoint);
    }
    logger_->info("[connect.stage] state=connecting endpoint=" + endpoint);
    logger_->info("Starting session connection to " + endpoint);

    network::TransportAdapterPtr adapter;
    if (endpoint.rfind("tls://", 0) == 0) {
        logger_->info("[connect.stage] adapter.select tls");
        span->set_attribute("transport", "tls");
        auto tls_adapter = std::make_shared<network::TlsTransportAdapter>(io_context_, logger_);

        std::string ca_cert = configuration_.get_string("network.tls.ca_cert", "config/certs/ca.crt");
        std::string client_cert = configuration_.get_string("network.tls.client_cert", "config/certs/client.crt");
        std::string client_key = configuration_.get_string("network.tls.client_key", "config/certs/client.key");

        tls_adapter->set_certificates(ca_cert, client_cert, client_key);
        adapter = tls_adapter;
        endpoint = endpoint.substr(6);
    } else {
        logger_->info("[connect.stage] adapter.select tcp");
        span->set_attribute("transport", "tcp");
        adapter = std::make_shared<network::TcpTransportAdapter>(io_context_, logger_);
        if (endpoint.rfind("tcp://", 0) == 0) {
            endpoint = endpoint.substr(6);
        }
    }

    span->add_event("transport_starting");
    logger_->info("[connect.stage] transport.start.begin endpoint=" + endpoint);
    auto err = adapter->start(endpoint);
    if (err) {
        const std::string err_message = to_utf8_safe(err.message());
        logger_->error("[app] failed to start transport to " + endpoint + ": " + err_message);
        span->set_attribute("error", err_message);
        session_state_ = SessionState::Disconnected;
        logger_->info("connect.final status=failed reason=transport_start_failed endpoint=" + endpoint);
        return make_result(false, "failed", "transport_start_failed", err_message, endpoint);
    }
    span->add_event("transport_connected");
    logger_->info("[connect.stage] transport.start.ok endpoint=" + endpoint);

    try {
        logger_->info("[connect.stage] session.create.begin endpoint=" + endpoint);
        session_manager_->create_session(adapter);
        logger_->info("[connect.stage] session.create.ok endpoint=" + endpoint);
    if (session_manager_) {
        const auto sessions_after_create = session_manager_->get_active_sessions();
        logger_->info("[connect.stage] session.create.snapshot active_sessions=" + std::to_string(sessions_after_create.size()));
        for (const auto& s : sessions_after_create) {
            logger_->info("[connect.stage] session.create.snapshot.item id=" + s.session_id +
                          " status=" + std::to_string(static_cast<int>(s.status)) +
                          " remote='" + s.remote_endpoint + "'");
        }
    }
    } catch (const std::exception& ex) {
        logger_->error(std::string("[app] create_session failed: ") + ex.what());
        span->set_attribute("error", ex.what());
        session_state_ = SessionState::Disconnected;
        logger_->info("connect.final status=failed reason=create_session_exception endpoint=" + endpoint);
        return make_result(false, "failed", "create_session_exception", ex.what(), endpoint);
    } catch (...) {
        logger_->error("[app] create_session failed: unknown exception");
        span->set_attribute("error", "create_session_exception_unknown");
        session_state_ = SessionState::Disconnected;
        logger_->info("connect.final status=failed reason=create_session_exception_unknown endpoint=" + endpoint);
        return make_result(false, "failed", "create_session_exception_unknown", "unknown exception", endpoint);
    }

    session_id_ = "sess_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count() % 10000);
    span->set_attribute("session_id", session_id_);
    session_state_ = SessionState::Connecting;
    logger_->info("[connect.stage] state=pending session_id=" + session_id_);
    logger_->info("Session accepted (pending): " + session_id_);
    logger_->info("connect.final status=pending session_id=" + session_id_ + " endpoint=" + endpoint);
    span->add_event("session_pending");
    return make_result(true, "pending", "none", "engine starting asynchronously", endpoint, session_id_);
}

void Application::disconnect_session() {
    if (session_state_.load() != SessionState::Connected && session_state_.load() != SessionState::Connecting) {
        logger_->warn("Cannot disconnect: no active session or connection in progress");
        return;
    }

    const auto prev_state = session_state_.load();
    session_state_ = SessionState::Disconnecting;
    logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev_state)) + "->" +
                  std::to_string(static_cast<int>(SessionState::Disconnecting)) +
                  " reason=disconnect_command.begin");
    logger_->info("Starting session disconnection process...");

    std::vector<std::string> ids;
    if (session_manager_) {
        auto sessions = session_manager_->get_active_sessions();
        ids.reserve(sessions.size());
        for (const auto& s : sessions) {
            ids.push_back(s.session_id);
        }
    }

    if (session_manager_) {
        for (const auto& id : ids) {
            session_manager_->terminate_session(id);
        }
    }

    active_session_count_.store(0);
    session_id_ = "none";
    const auto prev = session_state_.load();
    session_state_ = SessionState::Disconnected;
    logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev)) + "->" +
                  std::to_string(static_cast<int>(SessionState::Disconnected)) +
                  " reason=disconnect_command");
    logger_->info("Session disconnected");
}

}  // namespace clink::core
