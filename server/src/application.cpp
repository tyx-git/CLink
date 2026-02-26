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

#include <thread>
#include <fstream>

#ifdef _WIN32
#include <winsock2.h>
#endif

namespace clink::core {

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
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        logger_->error("Failed to initialize Winsock");
        return;
    }
#endif

    load_configuration();
    
    // Initialize logging system with configuration early
    initialize_logging();
    
    // Initialize Security & Policy
    credential_store_ = std::make_shared<security::WindowsCredentialStore>();
    auth_service_ = std::make_shared<security::PskAuthProvider>();
    policy_engine_ = std::make_shared<policy::PolicyEngine>();
    policy_engine_->load_from_config(configuration_);

    // 初始化 SessionManager 等 (apply_configuration 会负责创建)
    apply_configuration();

    // Start IPC server if needed (usually handled by main or specialized call)
    // 注意：ipc_server_ 必须在 setup_ipc_handlers 之前创建
    if (!ipc_server_ && options_.role == "service") {
        ipc_server_ = ipc::create_server(logger_);
        ipc_server_->start("\\\\.\\pipe\\clink-ipc");
    }
    setup_ipc_handlers();

    // Initialize Process Manager (Handles Process Injection & SOCKS)
    if (options_.role == "service") {
        auto pm = std::make_shared<clink::server::modules::ProcessManager>(io_context_, logger_, session_manager_);
        if (pm->start(configuration_)) {
            process_manager_ = pm;
        }
    }

    if (options_.auto_reload_config) {
        set_auto_reload(true);
    }
}

void Application::apply_configuration() {
    if (!session_manager_) {
        session_manager_ = network::create_session_manager(io_context_, logger_);
        if (session_manager_) {
            session_manager_->initialize();
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
            
            if (endpoint.rfind("tls://", 0) == 0) {
                auto tls_listener = std::make_unique<network::TlsTransportListener>(io_context_, logger_);
                
                // 加载 TLS 证书配置
                std::string ca_cert = configuration_.get_string("network.tls.ca_cert", "config/certs/ca.crt");
                std::string server_cert = configuration_.get_string("network.tls.server_cert", "config/certs/server.crt");
                std::string server_key = configuration_.get_string("network.tls.server_key", "config/certs/server.key");
                
                tls_listener->set_certificates(ca_cert, server_cert, server_key);

                // 加载证书绑定 (Certificate Binding) 配置 - 用于限制允许连接的客户端证书
                if (configuration_.contains("network.tls.pinned_client_cert")) {
                    tls_listener->set_pinned_certificate_hash(configuration_.get_string("network.tls.pinned_client_cert"));
                }

                listener = std::move(tls_listener);
                endpoint = endpoint.substr(6); // 移除 tls://
            } else {
                listener = std::make_unique<network::TcpTransportListener>(io_context_, logger_);
                if (endpoint.rfind("tcp://", 0) == 0) {
                    endpoint = endpoint.substr(6);
                }
            }
            
            session_manager_->start_listen(std::move(listener), endpoint);
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

            if (req.command == "reload") {
                reload_configuration();
                return {ipc::MessageType::Response, "reload", ok_payload("reload", "{\"status\":\"ok\"}")};
            }
            if (req.command == "status") {
                return {ipc::MessageType::Response, "status", ok_payload("status", get_session_status())};
            }
            if (req.command == "connect") {
                connect_session();
                return {ipc::MessageType::Response, "connect", ok_payload("connect", "{\"status\":\"connecting\"}")};
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
    stop_modules();
}

void Application::shutdown(std::chrono::milliseconds /*timeout*/) {
    if (!initialized_) {
        return;
    }

    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        log_lifecycle("shutting down subsystems");

        // Stop Asio
        io_work_.reset();
        io_context_.stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }

        stop_modules();
    
    if (session_manager_) {
        session_manager_->shutdown();
    }

#ifdef _WIN32
    WSACleanup();
#endif

    log_lifecycle("shutdown complete");
    }
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
    std::string state_str;
    switch (session_state_.load()) {
        case SessionState::Disconnected:  state_str = "disconnected"; break;
        case SessionState::Connecting:    state_str = "connecting"; break;
        case SessionState::Connected:     state_str = "connected"; break;
        case SessionState::Disconnecting: state_str = "disconnecting"; break;
    }

    std::string result = "{";
    result += "\"status\": \"" + state_str + "\", ";
    result += "\"session_id\": \"" + session_id_ + "\", ";
    
    if (session_manager_) {
        auto sessions = session_manager_->get_active_sessions();
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

void Application::connect_session() {
    auto tracer = observability::Telemetry::get_tracer("clink-app");
    observability::ScopedSpan span(tracer->start_span("connect_session"));

    if (session_state_.load() != SessionState::Disconnected) {
        logger_->warn("Cannot connect: session is already active or in transition");
        span->add_event("connection_aborted_active_session");
        return;
    }

    if (session_manager_) {
        // 1. 获取目标地址
        std::string endpoint = configuration_.get_string("client.remote_endpoint");
        if (endpoint.empty()) {
            logger_->error("[app] cannot connect: client.remote_endpoint not set");
            span->set_attribute("error", "missing_endpoint");
            return;
        }
        span->set_attribute("endpoint", endpoint);

        session_state_ = SessionState::Connecting;
        logger_->info("Starting session connection to " + endpoint);

        // 2. 创建适配器
        std::unique_ptr<network::TransportAdapter> adapter;
        if (endpoint.rfind("tls://", 0) == 0) {
            span->set_attribute("transport", "tls");
            auto tls_adapter = std::make_unique<network::TlsTransportAdapter>(io_context_, logger_);
            
            // 加载 TLS 证书配置
            std::string ca_cert = configuration_.get_string("network.tls.ca_cert", "config/certs/ca.crt");
            std::string client_cert = configuration_.get_string("network.tls.client_cert", "config/certs/client.crt");
            std::string client_key = configuration_.get_string("network.tls.client_key", "config/certs/client.key");
            
            tls_adapter->set_certificates(ca_cert, client_cert, client_key);
            adapter = std::move(tls_adapter);
            endpoint = endpoint.substr(6);
        } else {
            span->set_attribute("transport", "tcp");
            adapter = std::make_unique<network::TcpTransportAdapter>(io_context_, logger_);
            if (endpoint.rfind("tcp://", 0) == 0) {
                endpoint = endpoint.substr(6);
            }
        }

        // 3. 发起连接
        span->add_event("transport_starting");
        auto err = adapter->start(endpoint);
        if (err) {
            logger_->error("[app] failed to start transport to " + endpoint + ": " + err.message());
            span->set_attribute("error", err.message());
            session_state_ = SessionState::Disconnected;
            return;
        }
        span->add_event("transport_connected");

        // 4. 创建会话
        session_manager_->create_session(std::move(adapter));
        session_id_ = "sess_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count() % 10000);
        span->set_attribute("session_id", session_id_);
        session_state_ = SessionState::Connected;
        logger_->info("Session connected: " + session_id_);
        span->add_event("session_active");
    }
}

void Application::disconnect_session() {
    if (session_state_.load() != SessionState::Connected && session_state_.load() != SessionState::Connecting) {
        logger_->warn("Cannot disconnect: no active session or connection in progress");
        return;
    }

    session_state_ = SessionState::Disconnecting;
    logger_->info("Starting session disconnection process...");

    // Simulate asynchronous disconnection
    std::thread([this]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        session_id_ = "none";
        session_state_ = SessionState::Disconnected;
        logger_->info("Session disconnected");
    }).detach();
}

}  // namespace clink::core
