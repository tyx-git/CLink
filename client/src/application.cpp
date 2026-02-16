#include "clink/core/application.hpp"
#include "clink/core/logging/config.hpp"
#include "clink/core/network/tls_adapter.hpp"

#include <thread>

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
    load_configuration();

    // Initialize logging system with configuration
    initialize_logging();

    module_registry_->configure_all(configuration_);
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
    
    // Start IO context in a separate thread
    io_thread_ = std::thread([this]() {
        io_context_.run();
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

void Application::shutdown() {
    if (!initialized_) {
        return;
    }

    running_ = false;
    
    // Stop IO context
    io_work_.reset();
    if (io_thread_.joinable()) {
        io_thread_.join();
    }
    
    stop_modules();
    log_lifecycle("shutting down");
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
        logger_->error("Failed to load configuration: " + std::string(e.what()));
        // Don't throw if it's the CLI, it might just want to use defaults or IPC
        if (options_.role != "cli") throw;
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
        ipc_server_ = ipc::create_server();
    }
    
    ipc_server_->set_handler([this](const ipc::Message& req) -> ipc::Message {
        if (req.command == "status") {
            return {ipc::MessageType::Response, "status", get_session_status()};
        } else if (req.command == "connect") {
            connect_session();
            return {ipc::MessageType::Response, "connect", "{\"status\": \"connecting\"}"};
        } else if (req.command == "disconnect") {
            disconnect_session();
            return {ipc::MessageType::Response, "disconnect", "{\"status\": \"disconnecting\"}"};
        }
        return {ipc::MessageType::Response, req.command, "{\"error\": \"unknown command\"}"};
    });
    
    ipc_server_->start(address);
    logger_->info("IPC server started at " + address);
}

ipc::IpcClient& Application::ipc_client() {
    if (!ipc_client_) {
        ipc_client_ = ipc::create_client();
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
    return "{\"status\": \"" + state_str + "\", \"session_id\": \"" + session_id_ + "\"}";
}

void Application::connect_session() {
    if (session_state_.load() != SessionState::Disconnected) {
        logger_->warn("Cannot connect: session is already active or in transition");
        return;
    }

    session_state_ = SessionState::Connecting;
    logger_->info("Starting session connection process...");

    // 启动连接线程
    std::thread([this]() {
#ifdef _WIN32
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

        try {
            std::string server_endpoint = "127.0.0.1:4433"; // 默认测试地址
            if (configuration_.contains("transport.server_endpoint")) {
                server_endpoint = configuration_.get_string("transport.server_endpoint");
            }

            logger_->info("Connecting to server via TLS: " + server_endpoint);
            
            auto adapter = std::make_shared<network::TlsTransportAdapter>(io_context_, logger_);
            
            // 加载 TLS 证书配置
            std::string ca_cert = configuration_.get_string("network.tls.ca_cert", "config/certs/ca.crt");
            std::string client_cert = configuration_.get_string("network.tls.client_cert", "config/certs/client.crt");
            std::string client_key = configuration_.get_string("network.tls.client_key", "config/certs/client.key");
            
            adapter->set_certificates(ca_cert, client_cert, client_key);

            // 加载证书绑定 (Certificate Binding) 配置
            if (configuration_.contains("network.tls.pinned_server_cert")) {
                adapter->set_pinned_certificate_hash(configuration_.get_string("network.tls.pinned_server_cert"));
            }
            
            auto ec = adapter->start(server_endpoint);
            
            if (ec) {
                logger_->error("Failed to connect to server: " + ec.message());
                session_state_ = SessionState::Disconnected;
                return;
            }

            // 保持连接并处理数据
            adapter->on_receive([this](const uint8_t* data, size_t size) {
                std::string msg(reinterpret_cast<const char*>(data), size);
                logger_->debug("Received data from server: " + msg);
            });

            session_id_ = "sess_tls_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count() % 10000);
            session_state_ = SessionState::Connected;
            logger_->info("Session connected via TLS: " + session_id_);

            // 循环检查连接状态
            while (session_state_.load() == SessionState::Connected && adapter->is_connected()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }

            if (session_state_.load() == SessionState::Connected) {
                logger_->warn("Connection lost unexpectedly");
            }
            
            adapter->stop();
        } catch (const std::exception& e) {
            logger_->error("Connection thread error: " + std::string(e.what()));
        }

        session_id_ = "none";
        session_state_ = SessionState::Disconnected;
        logger_->info("Session thread terminated");

#ifdef _WIN32
        WSACleanup();
#endif
    }).detach();
}

void Application::disconnect_session() {
    if (session_state_.load() != SessionState::Connected && session_state_.load() != SessionState::Connecting) {
        logger_->warn("Cannot disconnect: no active session or connection in progress");
        return;
    }

    logger_->info("Initiating manual disconnection...");
    session_state_ = SessionState::Disconnecting;
    // 连接线程检测到 Disconnecting 会自动退出并清理
}

}  // namespace clink::core
