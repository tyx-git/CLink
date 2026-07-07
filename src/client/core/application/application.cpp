// ===== 客户端 Application 实现 =====
// 比服务端精简：没有 SessionManager，不管理会话表
// 主要方法 connect_session() 创建独立线程发起 TLS/TCP 出站连接

#include "src/client/core/application/application.hpp"
#include "src/share/core/config/config_signature.hpp"
#include "src/share/core/logging/config.hpp"
#include "src/client/core/network/tls_adapter.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif

#include <nlohmann/json.hpp>
#include <algorithm>
#include <thread>

namespace clink::core {

namespace {
namespace control_plane = clink::protocol::control_plane;
using clink::core::config::build_prefixed_signature;
using clink::core::config::build_logging_signature;

std::string resolve_ipc_address(const config::Configuration& configuration) {
    return configuration.get_string("ipc.address", "");
}

std::string build_transport_signature(const config::Configuration& configuration) {
    return build_prefixed_signature(configuration, {"transport.", "network.tls."});
}

} // namespace

Application::Application(ApplicationOptions options)
    : io_work_(std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(io_context_.get_executor())),
      options_(std::move(options)),
      logger_(std::make_shared<logging::Logger>(options_.identity)),
      module_registry_(std::make_shared<ModuleRegistry>()) {
    logger_->set_level(options_.log_level);
}

void Application::initialize() {
    bool expected = false;
    if (!initialized_.compare_exchange_strong(expected, true)) {
        return;
    }

    log_lifecycle("initializing subsystems");
    load_configuration();
    initialize_logging();
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        effective_logging_signature_ = build_logging_signature(configuration_);
        effective_transport_signature_ = build_transport_signature(configuration_);
    }

    module_registry_->configure_all(configuration_);

    if (configuration_.contains("ipc.address")) {
        start_ipc_server(configuration_.get_string("ipc.address"));
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

    io_thread_ = std::thread([this]() {
        io_context_.run();
    });

    start_modules();

    while (running_.load()) {
        std::this_thread::sleep_for(options_.heartbeat_interval);
    }

    log_lifecycle("event loop exited");
    stop_modules();
}

void Application::shutdown() {
    if (!initialized_) {
        return;
    }

    running_ = false;

    if (ipc_server_) {
        ipc_server_->stop();
        ipc_server_.reset();
    }

    if (ipc_client_) {
        ipc_client_->disconnect();
        ipc_client_.reset();
    }

    {
        std::lock_guard<std::mutex> command_lock(session_command_mutex_);
        session_state_ = SessionState::Disconnecting;
    }

    std::shared_ptr<network::TlsTransportAdapter> adapter_to_stop;
    {
        std::lock_guard<std::mutex> lock(session_adapter_mutex_);
        adapter_to_stop = active_adapter_;
    }
    if (adapter_to_stop) {
        adapter_to_stop->stop();
    }

    if (session_thread_.joinable()) {
        session_thread_.join();
    }

    io_work_.reset();
    io_context_.stop();
    if (io_thread_.joinable()) {
        io_thread_.join();
    }

    stop_modules();
    log_lifecycle("shutting down");
}

void Application::log_lifecycle(const std::string& stage) const {
    logger_->info("[" + options_.role + "|" + options_.identity + "] " + stage);
}

void Application::update_connect_status(std::string phase, std::string reason, std::string message) {
    std::lock_guard<std::mutex> lock(control_state_mutex_);
    last_connect_phase_ = std::move(phase);
    last_connect_reason_ = std::move(reason);
    last_connect_message_ = std::move(message);
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
        if (options_.role != "cli") throw;
    }
}

void Application::initialize_logging() {
    if (configuration_.contains("logging.level") || configuration_.contains("logging.sinks")) {
        logging::initialize_logging(configuration_);
        auto log_config = logging::LogConfig::from_toml(configuration_);
        logger_ = logging::create_logger(options_.identity, log_config);
        if (configuration_.contains("logging.level")) {
            logger_->set_level(log_config.level);
        }
    } else {
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

    ipc_server_->set_handler([this](const ipc::Message& req) -> ipc::Message {
        using json = nlohmann::json;

        auto parse_data_payload = [](const std::string& raw) -> json {
            if (raw.empty()) {
                return json::object();
            }

            auto parsed = json::parse(raw, nullptr, false);
            if (!parsed.is_discarded()) {
                return parsed;
            }

            return json(raw);
        };

        auto ok_payload = [](const std::string& command, json data) -> std::string {
            json payload;
            payload[control_plane::kEnvelopeOk] = true;
            payload[control_plane::kEnvelopeCommand] = command;
            payload[control_plane::kEnvelopeData] = std::move(data);
            return payload.dump();
        };

        auto error_payload = [](const std::string& command, const std::string& message) -> std::string {
            json payload;
            payload[control_plane::kEnvelopeOk] = false;
            payload[control_plane::kEnvelopeCommand] = command;
            payload[control_plane::kEnvelopeError] = message;
            return payload.dump();
        };

        if (req.command == "status") {
            return {ipc::MessageType::Response, "status", ok_payload("status", parse_data_payload(get_session_status()))};
        } else if (req.command == "connect") {
            const auto previous_state = session_state_.load();
            const bool accepted = (previous_state == SessionState::Disconnected);
            connect_session();
            auto data = parse_data_payload(get_session_status());
            data[control_plane::kFieldAccepted] = accepted;
            if (!accepted) {
                data[control_plane::kFieldStatus] = control_plane::kStatusRejected;
                data[control_plane::kFieldReason] = control_plane::kReasonSessionNotDisconnected;
                data[control_plane::kFieldMessage] = "session is already active or in transition";
            }
            return {ipc::MessageType::Response, "connect", ok_payload("connect", std::move(data))};
        } else if (req.command == "disconnect") {
            const auto previous_state = session_state_.load();
            const bool accepted = (previous_state == SessionState::Connected || previous_state == SessionState::Connecting);
            disconnect_session();
            auto data = parse_data_payload(get_session_status());
            data[control_plane::kFieldAccepted] = accepted;
            if (!accepted) {
                data[control_plane::kFieldStatus] = control_plane::kStatusRejected;
                data[control_plane::kFieldReason] = control_plane::kReasonSessionNotActive;
                data[control_plane::kFieldMessage] = "no active session or connection in progress";
            }
            return {ipc::MessageType::Response, "disconnect", ok_payload("disconnect", std::move(data))};
        }
        return {ipc::MessageType::Response,
                req.command,
                error_payload(req.command, control_plane::kReasonUnknownCommand)};
    });

    ipc_server_->start(address);
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        effective_ipc_address_ = address;
    }
    logger_->info("IPC server started at " + address);
}

ipc::IpcClient& Application::ipc_client() {
    if (!ipc_client_) {
        ipc_client_ = ipc::create_client(logger_);
    }
    return *ipc_client_;
}

std::string Application::get_session_status() const {
    using json = nlohmann::json;

    std::string session_id;
    std::string connect_phase;
    std::string connect_reason;
    std::string connect_message;
    std::string effective_ipc_address;
    std::string effective_transport_signature;
    std::string effective_logging_signature;
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        session_id = session_id_;
        connect_phase = last_connect_phase_;
        connect_reason = last_connect_reason_;
        connect_message = last_connect_message_;
        effective_ipc_address = effective_ipc_address_;
        effective_transport_signature = effective_transport_signature_;
        effective_logging_signature = effective_logging_signature_;
    }

    std::string state_str;
    switch (session_state_.load()) {
        case SessionState::Disconnected:  state_str = control_plane::kStatusDisconnected; break;
        case SessionState::Connecting:    state_str = control_plane::kStatusConnecting; break;
        case SessionState::Connected:     state_str = control_plane::kStatusConnected; break;
        case SessionState::Disconnecting: state_str = control_plane::kStatusDisconnecting; break;
    }
    json result{{control_plane::kFieldStatus, state_str},
                {control_plane::kFieldSessionId, session_id},
                {control_plane::kFieldConnectPhase, connect_phase},
                {control_plane::kFieldConnectReason, connect_reason},
                {control_plane::kFieldActiveSessions, state_str == control_plane::kStatusConnected ? 1 : 0},
                {control_plane::kFieldTrackedSessions, state_str == control_plane::kStatusDisconnected ? 0 : 1},
                {control_plane::kFieldRestartRequired, false},
                {control_plane::kFieldRestartReasons, json::array()},
                {control_plane::kFieldConfigReloadSupported, false}};

    try {
        if (!options_.config_path.empty() && std::filesystem::exists(options_.config_path)) {
            const auto current_config = config::Configuration::load_from_file(options_.config_path);
            json restart_reasons = json::array();

            const std::string configured_ipc_address = resolve_ipc_address(current_config);
            if (configured_ipc_address != effective_ipc_address) {
                restart_reasons.push_back(control_plane::kConfigDomainIpcAddress);
            }
            if (build_transport_signature(current_config) != effective_transport_signature) {
                restart_reasons.push_back(control_plane::kConfigDomainTransportRuntime);
            }
            if (build_logging_signature(current_config) != effective_logging_signature) {
                restart_reasons.push_back(control_plane::kConfigDomainLogging);
            }

            result[control_plane::kFieldRestartRequired] = !restart_reasons.empty();
            result[control_plane::kFieldRestartReasons] = std::move(restart_reasons);
            if (!effective_ipc_address.empty() || !configured_ipc_address.empty()) {
                result[control_plane::kFieldEffectiveIpcAddress] = effective_ipc_address;
                result[control_plane::kFieldConfiguredIpcAddress] = configured_ipc_address;
            }
        }
    } catch (const std::exception& e) {
        result[control_plane::kFieldConfigStatus] = std::string("unreadable: ") + e.what();
    }

    if (!connect_message.empty()) {
        result[control_plane::kFieldConnectMessage] = connect_message;
    }
    return result.dump();
}

void Application::connect_session() {
    {
        std::lock_guard<std::mutex> command_lock(session_command_mutex_);
        if (session_state_.load() != SessionState::Disconnected) {
            logger_->warn("Cannot connect: session is already active or in transition");
            update_connect_status(control_plane::kStatusRejected,
                                  control_plane::kReasonSessionNotDisconnected,
                                  "session is already active or in transition");
            return;
        }

        if (session_thread_.joinable()) {
            session_thread_.join();
        }

        session_state_ = SessionState::Connecting;
    }
    update_connect_status(control_plane::kStatusConnecting, control_plane::kValueNone);

    logger_->info("Starting session connection process...");

    try {
        session_thread_ = std::thread([this]() {
#ifdef _WIN32
            WSADATA wsaData;
            WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif

            try {
                std::string server_endpoint;
                if (configuration_.contains("transport.server_endpoint")) {
                    server_endpoint = configuration_.get_string("transport.server_endpoint");
                } else if (configuration_.contains("client.remote_endpoint")) {
                    server_endpoint = configuration_.get_string("client.remote_endpoint");
                    logger_->info("Using client.remote_endpoint as server endpoint (consider setting transport.server_endpoint)");
                } else {
                    logger_->error("No server endpoint configured (need transport.server_endpoint or client.remote_endpoint)");
                    update_connect_status(control_plane::kStatusFailed,
                                          control_plane::kReasonMissingEndpoint,
                                          "No server endpoint configured");
                    session_state_ = SessionState::Disconnected;
                    return;
                }

                logger_->info("Connecting to server via TLS: " + server_endpoint);

                auto adapter = std::make_shared<network::TlsTransportAdapter>(io_context_, logger_);
                {
                    std::lock_guard<std::mutex> lock(session_adapter_mutex_);
                    active_adapter_ = adapter;
                }

                std::string ca_cert = configuration_.get_string("network.tls.ca_cert", "config/certs/ca.crt");
                std::string client_cert = configuration_.get_string("network.tls.client_cert", "config/certs/client.crt");
                std::string client_key = configuration_.get_string("network.tls.client_key", "config/certs/client.key");

                adapter->set_certificates(ca_cert, client_cert, client_key);

                if (configuration_.contains("network.tls.pinned_server_cert")) {
                    adapter->set_pinned_certificate_hash(configuration_.get_string("network.tls.pinned_server_cert"));
                }

                auto ec = adapter->start(server_endpoint);

                if (ec) {
                    logger_->error("Failed to connect to server: " + ec.message());
                    update_connect_status(control_plane::kStatusFailed,
                                          control_plane::kReasonTransportStartFailed,
                                          ec.message());
                    session_state_ = SessionState::Disconnected;
                    return;
                }

                adapter->on_receive([this](const uint8_t* data, size_t size) {
                    std::string msg(reinterpret_cast<const char*>(data), size);
                    logger_->debug("Received data from server: " + msg);
                });

                constexpr auto handshake_wait = std::chrono::seconds(10);
                const auto wait_deadline = std::chrono::steady_clock::now() + handshake_wait;
                while (std::chrono::steady_clock::now() < wait_deadline && !adapter->is_connected()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }

                if (!adapter->is_connected()) {
                    logger_->error("TLS handshake did not complete before timeout");
                    adapter->stop();
                    update_connect_status(control_plane::kStatusFailed,
                                          control_plane::kReasonHandshakeTimeout,
                                          "TLS handshake did not complete before timeout");
                    session_state_ = SessionState::Disconnected;
                    return;
                }

                static std::atomic<uint64_t> session_counter{0};
#ifdef _WIN32
                const uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
#else
                const uint64_t pid = static_cast<uint64_t>(getpid());
#endif
                std::string connected_session_id = "sess_" + std::to_string(pid) +
                                                    "_" + std::to_string(session_counter.fetch_add(1));
                {
                    std::lock_guard<std::mutex> lock(control_state_mutex_);
                    session_id_ = connected_session_id;
                }
                session_state_ = SessionState::Connected;
                update_connect_status(control_plane::kStatusConnected, control_plane::kValueNone);
                logger_->info("Session connected via TLS: " + connected_session_id);

                while (session_state_.load() == SessionState::Connected && adapter->is_connected()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                if (session_state_.load() == SessionState::Connected) {
                    logger_->warn("Connection lost unexpectedly");
                    update_connect_status(control_plane::kStatusDisconnected,
                                          control_plane::kReasonConnectionLost,
                                          "connection lost unexpectedly");
                }

                adapter->stop();
            } catch (const std::exception& e) {
                logger_->error("Connection thread error: " + std::string(e.what()));
                update_connect_status(control_plane::kStatusFailed,
                                      control_plane::kReasonConnectionThreadException,
                                      e.what());
            } catch (...) {
                logger_->error("Connection thread error: unknown exception");
                update_connect_status(control_plane::kStatusFailed,
                                      control_plane::kReasonConnectionThreadException,
                                      "unknown exception");
            }

            {
                std::lock_guard<std::mutex> lock(session_adapter_mutex_);
                active_adapter_.reset();
            }

            {
                std::lock_guard<std::mutex> lock(control_state_mutex_);
                session_id_ = control_plane::kValueNone;
            }
            if (session_state_.load() == SessionState::Disconnecting) {
                update_connect_status(running_.load() ? control_plane::kStatusDisconnected : control_plane::kStatusStopped,
                                      running_.load() ? control_plane::kReasonDisconnectComplete : control_plane::kReasonShutdown);
            }
            session_state_ = SessionState::Disconnected;
            logger_->info("Session thread terminated");

#ifdef _WIN32
            WSACleanup();
#endif
        });
    } catch (const std::exception& e) {
        logger_->error("Failed to start session thread: " + std::string(e.what()));
        update_connect_status(control_plane::kStatusFailed, control_plane::kReasonThreadStartFailed, e.what());
        session_state_ = SessionState::Disconnected;
    } catch (...) {
        logger_->error("Failed to start session thread: unknown exception");
        update_connect_status(control_plane::kStatusFailed,
                              control_plane::kReasonThreadStartFailed,
                              "unknown exception");
        session_state_ = SessionState::Disconnected;
    }
}

void Application::disconnect_session() {
    {
        std::lock_guard<std::mutex> command_lock(session_command_mutex_);
        if (session_state_.load() != SessionState::Connected && session_state_.load() != SessionState::Connecting) {
            logger_->warn("Cannot disconnect: no active session or connection in progress");
            update_connect_status(control_plane::kStatusRejected,
                                  control_plane::kReasonSessionNotActive,
                                  "no active session or connection in progress");
            return;
        }

        logger_->info("Initiating manual disconnection...");
        session_state_ = SessionState::Disconnecting;
    }
    update_connect_status(control_plane::kStatusDisconnecting, control_plane::kValueNone);

    std::shared_ptr<network::TlsTransportAdapter> adapter_to_stop;
    {
        std::lock_guard<std::mutex> lock(session_adapter_mutex_);
        adapter_to_stop = active_adapter_;
    }
    if (adapter_to_stop) {
        adapter_to_stop->stop();
    }
}

}  // namespace clink::core
