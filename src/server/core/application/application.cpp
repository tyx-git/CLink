#include "src/server/core/application/application.hpp"
#include "src/share/core/config/config_signature.hpp"
#include "src/share/core/config/log_path_utils.hpp"
#include "src/share/core/logging/config.hpp"
#include "src/server/core/network/session_manager_impl.hpp"
#include "src/server/core/network/tcp_adapter.hpp"
#include "src/server/core/network/tls_adapter.hpp"
#include "src/server/core/network/acl.hpp"
#include "src/server/core/security/psk_provider.hpp"
#include "src/server/core/security/windows_store.hpp"
#include "src/server/core/security/dpapi_helper.hpp"
#include "src/server/core/policy/engine.hpp"
#include "src/server/core/observability/telemetry.hpp"
#include "src/server/modules/heartbeat/heartbeat.hpp"
#include "src/server/modules/metrics/metrics.hpp"
#include "src/server/modules/process_manager/process_manager.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"
#include <cstdint>

#include <thread>
#include <fstream>
#include <future>
#include <stdexcept>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <codecvt>
#include <locale>
#include <type_traits>

#ifdef _WIN32
#include <winsock2.h>
#endif

namespace clink::core {

namespace {
namespace control_plane = clink::protocol::control_plane;
using clink::core::config::build_prefixed_signature;
using clink::core::config::build_logging_signature;
using clink::core::config::resolve_log_file_path;

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

std::string session_status_to_string(network::SessionStatus status) {
    switch (status) {
        case network::SessionStatus::Idle:
            return control_plane::kStatusIdle;
        case network::SessionStatus::Handshaking:
            return control_plane::kStatusHandshaking;
        case network::SessionStatus::Active:
            return control_plane::kStatusActive;
        case network::SessionStatus::Closing:
            return control_plane::kStatusClosing;
        case network::SessionStatus::Error:
            return control_plane::kStatusError;
    }
    return control_plane::kStatusUnknown;
}

struct SessionSnapshotSummary {
    std::size_t tracked_count{0};
    std::size_t active_count{0};
    std::size_t handshaking_count{0};
    std::size_t closing_count{0};
    std::size_t error_count{0};
    std::string primary_active_session_id{control_plane::kValueNone};
};

SessionSnapshotSummary summarize_sessions(const std::vector<network::SessionContext>& sessions) {
    SessionSnapshotSummary summary;
    summary.tracked_count = sessions.size();

    for (const auto& session : sessions) {
        switch (session.status) {
            case network::SessionStatus::Active:
                ++summary.active_count;
                if (summary.primary_active_session_id == control_plane::kValueNone) {
                    summary.primary_active_session_id = session.session_id;
                }
                break;
            case network::SessionStatus::Handshaking:
                ++summary.handshaking_count;
                break;
            case network::SessionStatus::Closing:
                ++summary.closing_count;
                break;
            case network::SessionStatus::Error:
                ++summary.error_count;
                break;
            case network::SessionStatus::Idle:
                break;
        }
    }

    return summary;
}

std::string build_listener_signature(const config::Configuration& configuration) {
    const std::string endpoint = configuration.get_string("network.listen_endpoint", "0.0.0.0:443");
    if (endpoint.empty()) {
        return {};
    }

    std::string signature = endpoint;
    if (endpoint.rfind("tls://", 0) == 0) {
        signature += "|ca=" + configuration.get_string("network.tls.ca_cert", "config/certs/ca.crt");
        signature += "|cert=" + configuration.get_string("network.tls.server_cert", "config/certs/server.crt");
        signature += "|key=" + configuration.get_string("network.tls.server_key", "config/certs/server.key");
        signature += "|pin=" + configuration.get_string("network.tls.pinned_client_cert", "");
    }

    return signature;
}

std::string resolve_ipc_address(const config::Configuration& configuration) {
#ifdef _WIN32
    return configuration.get_string("ipc.address", "\\\\.\\pipe\\clink-ipc");
#else
    return configuration.get_string("ipc.address", "/tmp/clink-ipc.sock");
#endif
}

bool resolve_process_manager_enabled(const config::Configuration& configuration) {
    bool enable_process_manager = configuration.get_bool("process_manager.enabled", true);
    if (const char* env_disable_pm = std::getenv("CLINK_DISABLE_PROCESS_MANAGER")) {
        if (std::string(env_disable_pm) == "1") {
            enable_process_manager = false;
        }
    }
    return enable_process_manager;
}

std::string build_process_manager_signature(const config::Configuration& configuration) {
    std::string signature = std::string("enabled=") + (resolve_process_manager_enabled(configuration) ? "true" : "false");
    signature += "|";
    signature += build_prefixed_signature(configuration, {"process_manager.", "socks.", "process.inject."});
    return signature;
}

} // namespace

Application::Application(ApplicationOptions options)
    : io_work_(std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(io_context_.get_executor())),
      options_(std::move(options)),
      logger_(std::make_shared<logging::Logger>(options_.identity)),
      module_registry_(std::make_shared<ModuleRegistry>()) {
    // Set initial log level from options
    logger_->set_level(options_.log_level);
}

// ===== 初始化阶段 =====
// 严格按依赖顺序创建各子系统。三步幂等——compare_exchange 防止重复进入
void Application::initialize() {
    bool expected = false;
    if (!initialized_.compare_exchange_strong(expected, true)) {
        return;  // 已初始化，跳过
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
        {
            std::lock_guard<std::mutex> lock(control_state_mutex_);
            effective_logging_signature_ = build_logging_signature(configuration_);
        }
        logger_->info("[init] stage=initialize_logging.ok");

        logger_->info("[init] stage=security_policy_init.begin");
        credential_store_ = std::make_shared<security::WindowsCredentialStore>();
        auth_service_ = std::make_shared<security::PskAuthProvider>();
        policy_engine_ = std::make_shared<policy::PolicyEngine>();
        policy_engine_->load_from_config(configuration_);
        logger_->info("[init] stage=security_policy_init.ok");

        logger_->info("[init] stage=apply_configuration.begin");
        const bool apply_ok = apply_configuration();
        logger_->info(std::string("[init] stage=apply_configuration.") + (apply_ok ? "ok" : "degraded"));

        if (!ipc_server_ && options_.role == "service") {
            logger_->info("[init] stage=ipc_server.prepare_default.begin");
            ipc_server_ = ipc::create_server(io_context_, logger_);
            logger_->info("[init] stage=ipc_server.prepare_default.ok");
        }

        logger_->info("[init] stage=ipc_handlers.begin");
        setup_ipc_handlers();
        logger_->info("[init] stage=ipc_handlers.ok");

        if (ipc_server_ && options_.role == "service") {
            const std::string ipc_address = resolve_ipc_address(configuration_);

            logger_->info("[init] stage=ipc_server.start_default.begin address=" + ipc_address);
            ipc_server_->start(ipc_address);
            {
                std::lock_guard<std::mutex> lock(control_state_mutex_);
                effective_ipc_address_ = ipc_address;
            }
            logger_->info("[init] stage=ipc_server.start_default.ok address=" + ipc_address);
        }

        if (options_.role == "service") {
            const bool enable_process_manager = resolve_process_manager_enabled(configuration_);

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

            {
                std::lock_guard<std::mutex> lock(control_state_mutex_);
                effective_process_manager_signature_ = build_process_manager_signature(configuration_);
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

bool Application::apply_process_manager_runtime_configuration() {
    const bool enable_process_manager = resolve_process_manager_enabled(configuration_);

    if (process_manager_) {
        const auto current_signature = build_process_manager_signature(configuration_);
        std::string effective_process_manager_signature;
        {
            std::lock_guard<std::mutex> lock(control_state_mutex_);
            effective_process_manager_signature = effective_process_manager_signature_;
        }

        if (current_signature == effective_process_manager_signature) {
            return true;
        }

        auto pm = std::static_pointer_cast<clink::server::modules::ProcessManager>(process_manager_);
        if (pm) {
            pm->stop();
        }
        process_manager_.reset();
    }

    if (!enable_process_manager || options_.role != "service") {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        effective_process_manager_signature_ = build_process_manager_signature(configuration_);
        return true;
    }

    bool applied = false;
    try {
        auto pm = std::make_shared<clink::server::modules::ProcessManager>(io_context_, logger_, session_manager_);
        const bool pm_started = pm->start(configuration_);
        if (pm_started) {
            process_manager_ = pm;
            applied = true;
        } else {
            logger_->warn("[apply] stage=process_manager.start.failed_return_false");
        }
    } catch (const std::exception& ex) {
        logger_->error(std::string("[apply] stage=process_manager.start.exception: ") + ex.what());
    } catch (...) {
        logger_->error("[apply] stage=process_manager.start.exception: unknown");
    }

    if (applied) {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        effective_process_manager_signature_ = build_process_manager_signature(configuration_);
    }

    return applied;
}

bool Application::apply_configuration() {
    bool apply_ok = true;
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
            apply_ok = false;
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
                apply_ok = false;
            } else {
                logger_->info("[apply] stage=session_manager.initialize.ok");
            }
        }
    }

    if (session_manager_) {
        const std::string desired_listener_signature = build_listener_signature(configuration_);
        const bool listener_changed = (desired_listener_signature != applied_listener_signature_);

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

            if (listener_changed) {
                impl->reset_listeners();
                applied_listener_signature_.clear();
            }
        }

        // 2. 应用全局带宽限制
        const int limit = configuration_.get_int("network.bandwidth_limit", 0);
        if (limit > 0) {
            session_manager_->set_default_rate_limit(static_cast<size_t>(limit), static_cast<size_t>(limit * 2));
            logger_->info("[apply] stage=session_manager.bandwidth_limit", limit);
        } else {
            session_manager_->set_default_rate_limit(0, 0);
            logger_->info("[apply] stage=session_manager.bandwidth_limit disabled");
        }

        // 3. 启动监听
        std::string endpoint = configuration_.get_string("network.listen_endpoint", "0.0.0.0:443");
        if (!listener_changed) {
            logger_->info("[apply] stage=listener.skip_unchanged endpoint=" + endpoint);
        } else if (!endpoint.empty()) {
            network::TransportListenerPtr listener;
            logger_->info("[apply] stage=listener.prepare endpoint=" + endpoint);

            if (endpoint.rfind("tls://", 0) == 0) {
                auto tls_listener = std::make_shared<network::TlsTransportListener>(io_context_, logger_);

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
                listener = std::make_shared<network::TcpTransportListener>(io_context_, logger_);
                if (endpoint.rfind("tcp://", 0) == 0) {
                    endpoint = endpoint.substr(6);
                }
                logger_->info("[apply] stage=listener.transport tcp endpoint=" + endpoint);
            }

            logger_->info("[apply] stage=listener.start.begin endpoint=" + endpoint);
            const auto listen_ec = session_manager_->start_listen(std::move(listener), endpoint);
            if (listen_ec) {
                logger_->error("[apply] stage=listener.start.failed endpoint=" + endpoint + " msg=" + listen_ec.message());
                apply_ok = false;
            } else {
                applied_listener_signature_ = desired_listener_signature;
                logger_->info("[apply] stage=listener.start.ok endpoint=" + endpoint);
            }
        } else {
            applied_listener_signature_.clear();
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
            psk_provider->clear_users();
            bool config_changed = false;
            // 从配置中加载加密的 PSK 列表
            // 配置格式示例: auth.psk_list = ["user1:Base64EncryptedSecret", "user2:..."]
            if (configuration_.contains("auth.psk_list")) {
                auto list = configuration_.get_list("auth.psk_list");
                std::vector<std::string> updated_list;
#ifndef _WIN32
                bool warned_plaintext_psk = false;
#endif

                for (const auto& entry : list) {
                    auto pos = entry.find(':');
                    if (pos != std::string::npos) {
                        std::string user_id = entry.substr(0, pos);
                        std::string secret_part = entry.substr(pos + 1);
                        
                        try {
                            std::string psk;
#ifdef _WIN32
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
                                std::string new_encrypted = security::DpapiHelper::encrypt(psk);
                                std::string new_base64 = security::DpapiHelper::to_base64(new_encrypted);
                                updated_list.push_back(user_id + ":" + new_base64);
                                config_changed = true;
                                logger_->info("[app] auto-encrypted psk for user: " + user_id);
                            } else {
                                updated_list.push_back(entry);
                            }
#else
                            psk = secret_part;
                            if (!warned_plaintext_psk) {
                                logger_->warn("[app] DPAPI unavailable on this platform; auth.psk_list entries are treated as plaintext and will not be auto-rewritten");
                                warned_plaintext_psk = true;
                            }
#endif
                            
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

    return apply_ok;
}

void Application::reload_configuration() {
    const auto previous_configuration = configuration_;
    try {
        configuration_ = config::Configuration::load_from_file(options_.config_path);
    } catch (const std::exception& e) {
        logger_->error(std::string("[app] configuration reload load failed: ") + e.what());
        configuration_ = previous_configuration;
        return;
    }
    
    // 重新初始化日志 (如果配置变了)
    initialize_logging();
    
    const bool apply_ok = apply_configuration();
    if (!apply_ok) {
        logger_->error("[app] configuration reload apply failed; restoring previous configuration");
        configuration_ = previous_configuration;
        initialize_logging();
        const bool rollback_ok = apply_configuration();
        if (!rollback_ok) {
            logger_->error("[app] configuration rollback apply failed");
        } else {
            logger_->warn("[app] configuration restored to previous snapshot after failed reload");
        }
        return;
    }

    if (!apply_process_manager_runtime_configuration()) {
        logger_->error("[app] configuration reload process manager apply failed; status will continue reporting restart requirement");
    }

    logger_->info("[app] configuration reloaded successfully");

    std::string effective_ipc_address;
    std::string effective_process_manager_signature;
    std::string effective_logging_signature;
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        effective_ipc_address = effective_ipc_address_;
        effective_process_manager_signature = effective_process_manager_signature_;
        effective_logging_signature = effective_logging_signature_;
    }

    nlohmann::json restart_reasons = nlohmann::json::array();
    if (!effective_ipc_address.empty() && resolve_ipc_address(configuration_) != effective_ipc_address) {
        restart_reasons.push_back(control_plane::kConfigDomainIpcAddress);
    }
    if (!effective_process_manager_signature.empty() &&
        build_process_manager_signature(configuration_) != effective_process_manager_signature) {
        restart_reasons.push_back(control_plane::kConfigDomainProcessManagerRuntime);
    }
    if (!effective_logging_signature.empty() &&
        build_logging_signature(configuration_) != effective_logging_signature) {
        restart_reasons.push_back(control_plane::kConfigDomainLogging);
    }

    if (!restart_reasons.empty()) {
        logger_->warn("[app] reload completed with deferred config requiring restart reasons=" + restart_reasons.dump());
    }
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

// ===== IPC 命令分发表 =====
// 将收到的 IPC 命令（reload/status/connect/disconnect/monitor/diag/logs/encrypt）映射到内部操作
// 所有非空命令都通过 invoke_on_io 序列化到 io_context 线程执行，避免并发问题
// 10 秒超时保护——被阻塞的 IPC 请求不会永久挂起
void Application::setup_ipc_handlers() {
    if (ipc_server_) {
        ipc_server_->set_handler([this](const ipc::Message& req) -> ipc::Message {
            using json = nlohmann::json;

            constexpr auto kIpcDispatchTimeout = std::chrono::seconds(10);

            // invoke_on_io：将操作投递到 io_context 线程执行，避免多线程竞争
            // 如果当前已经在 io_context 线程上，直接执行不走 post
            auto invoke_on_io = [this, kIpcDispatchTimeout]<typename Fn>(Fn&& fn) -> decltype(auto) {
                using Result = std::invoke_result_t<Fn>;

                const bool should_serialize_to_io = control_runtime_ready_.load() &&
                                                    io_thread_.joinable() &&
                                                    std::this_thread::get_id() != io_thread_.get_id();
                if (!should_serialize_to_io) {
                    return fn();
                }

                auto promise = std::make_shared<std::promise<Result>>();
                auto future = promise->get_future();
                asio::post(io_context_, [func = std::forward<Fn>(fn), promise]() mutable {
                    try {
                        if constexpr (std::is_void_v<Result>) {
                            func();
                            promise->set_value();
                        } else {
                            promise->set_value(func());
                        }
                    } catch (...) {
                        promise->set_exception(std::current_exception());
                    }
                });

                if (future.wait_for(kIpcDispatchTimeout) != std::future_status::ready) {
                    throw std::runtime_error("control_plane_dispatch_timeout");
                }

                if constexpr (std::is_void_v<Result>) {
                    future.get();
                } else {
                    return future.get();
                }
            };

            // 解析 IPC 载荷中的 JSON 字符串
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

            // 构造成功信封：{"ok":true, "command":"xxx", "data":{...}}
            auto ok_payload = [&](const std::string& command, json data) -> std::string {
                if (!data.is_object()) {
                    data = json{{control_plane::kFieldValue, std::move(data)}};
                }
                if (!data.contains(control_plane::kFieldAccepted)) {
                    data[control_plane::kFieldAccepted] = true;
                }
                json payload;
                payload[control_plane::kEnvelopeOk] = true;
                payload[control_plane::kEnvelopeCommand] = command;
                payload[control_plane::kEnvelopeData] = std::move(data);
                return payload.dump();
            };

            // 构造失败信封：{"ok":false, "command":"xxx", "error":"...", "data":{...}}
            auto error_payload = [&](const std::string& command, const std::string& message,
                                     const std::string& reason = std::string{}) -> std::string {
                json data;
                data[control_plane::kFieldAccepted] = false;
                data[control_plane::kFieldStatus] = control_plane::kStatusFailed;
                data[control_plane::kFieldMessage] = to_utf8_safe(message);
                data[control_plane::kFieldReason] = reason.empty() ? to_utf8_safe(message) : to_utf8_safe(reason);

                json payload;
                payload[control_plane::kEnvelopeOk] = false;
                payload[control_plane::kEnvelopeCommand] = command;
                payload[control_plane::kEnvelopeError] = to_utf8_safe(message);
                payload[control_plane::kEnvelopeData] = std::move(data);
                return payload.dump();
            };

            // 判断 daemon 是否已就绪/正在关闭，返回对应原因码
            auto control_runtime_unavailable_reason = [&]() -> std::string {
                return shutdown_called_.load() ? control_plane::kReasonServiceShuttingDown
                                               : control_plane::kReasonServiceNotRunning;
            };

            auto control_runtime_unavailable_response = [&](const std::string& command) -> ipc::Message {
                const std::string reason = control_runtime_unavailable_reason();
                return {ipc::MessageType::Response, command, error_payload(command, reason, reason)};
            };

            try {
                // ---- reload：热重载配置 ----
                if (req.command == "reload") {
                    if (!control_runtime_ready_.load()) {
                        return control_runtime_unavailable_response("reload");
                    }
                    invoke_on_io([this]() { reload_configuration(); });
                    const auto status_payload = invoke_on_io([this]() { return get_session_status(); });
                    auto data = parse_data_payload(status_payload);
                    data["reload"] = "ok";
                    return {ipc::MessageType::Response, "reload", ok_payload("reload", std::move(data))};
                }
                // ---- status：收集 daemon 状态并返回 JSON ----
                if (req.command == "status") {
                    const auto status_payload = invoke_on_io([this]() { return get_session_status(); });
                    return {ipc::MessageType::Response, "status", ok_payload("status", parse_data_payload(status_payload))};
                }
                // ---- connect：发起出站连接（TLS/TCP）到远端 daemon ----
                if (req.command == "connect") {
                    if (!control_runtime_ready_.load()) {
                        return control_runtime_unavailable_response("connect");
                    }
                    const auto connect_result = invoke_on_io([this, payload = req.payload]() { return connect_session(payload); });
                    return {ipc::MessageType::Response, "connect", ok_payload("connect", parse_data_payload(connect_result))};
                }
                // ---- disconnect：断开当前会话 ----
                if (req.command == "disconnect") {
                    if (!control_runtime_ready_.load()) {
                        return control_runtime_unavailable_response("disconnect");
                    }
                    const auto disconnect_data = invoke_on_io([this]() {
                        using json = nlohmann::json;

                        const auto previous_state = session_state_.load();
                        const bool accepted = (previous_state == SessionState::Connected || previous_state == SessionState::Connecting);
                        disconnect_session();

                        auto data = json::parse(get_session_status(), nullptr, false);
                        if (data.is_discarded()) {
                            data = json::object();
                        }
                        data[control_plane::kFieldAccepted] = accepted;
                        if (!accepted) {
                            data[control_plane::kFieldStatus] = control_plane::kStatusRejected;
                            data[control_plane::kFieldReason] = control_plane::kReasonSessionNotActive;
                            data[control_plane::kFieldMessage] = "no active session or connection in progress";
                        }
                        return data;
                    });
                    return {ipc::MessageType::Response, "disconnect", ok_payload("disconnect", std::move(disconnect_data))};
                }
                // ---- logs：读取 daemon 日志文件内容 ----
                if (req.command == "logs") {
                    const std::string log_path = resolve_log_file_path(configuration_);
                    std::ifstream log_file(log_path, std::ios::binary);
                    if (!log_file.is_open()) {
                        return {ipc::MessageType::Response, "logs",
                                error_payload("logs", "failed to open log file: " + log_path,
                                              control_plane::kReasonLogOpenFailed)};
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
                        ok_payload("logs", json{{control_plane::kFieldContent, to_utf8_safe(content)},
                                                 {control_plane::kFieldPath, log_path}})
                    };
                }
                // ---- 未知命令 ----
                return {ipc::MessageType::Response, req.command,
                        error_payload(req.command, "unknown command", control_plane::kReasonUnknownCommand)};
            } catch (const std::exception& ex) {
                logger_->error(std::string("[ipc] handler exception command=") + req.command + " error=" + ex.what());
                return {ipc::MessageType::Response, req.command,
                        error_payload(req.command, std::string("handler_exception: ") + ex.what(),
                                      control_plane::kReasonHandlerException)};
            } catch (...) {
                logger_->error(std::string("[ipc] handler unknown exception command=") + req.command);
                return {ipc::MessageType::Response, req.command,
                        error_payload(req.command, "handler_exception: unknown",
                                      control_plane::kReasonHandlerException)};
            }
        });
    }
}

// ===== 运行阶段 =====
// 启动 Asio 事件循环到独立线程，然后主线程停留在一个心跳循环中
// running_ = false 时退出主循环，由 shutdown() 做资源清理
void Application::run() {
    if (!initialized_) {
        initialize();
    }

    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;  // 已在运行
    }

    log_lifecycle("entering event loop");

    {
        std::lock_guard<std::mutex> lock(io_thread_state_mutex_);
        io_thread_stopped_ = false;
    }

    // 异步 IO 在独立线程中运行，主线程不阻塞在 io_context 上
    io_thread_ = std::thread([this]() {
        logger_->info("[app] asio io_context started");
        io_context_.run();
        logger_->info("[app] asio io_context stopped");
        {
            std::lock_guard<std::mutex> lock(io_thread_state_mutex_);
            io_thread_stopped_ = true;
        }
        io_thread_stopped_cv_.notify_all();
    });

    start_modules();
    control_runtime_ready_.store(true);

    // 主循环：以心跳间隔轮询 running_ 标志，等待 request_stop() 或信号触发退出
    while (running_.load()) {
        std::this_thread::sleep_for(options_.heartbeat_interval);
    }

    log_lifecycle("event loop exited");
    // 模块在 shutdown() 中停止，不在 run() 中停——避免信号驱动的 shutdown 重复停止
}

// ===== 关停阶段 =====
// 逆序关停：IPC → PM → 模块 → SessionManager → IO 线程
// compare_exchange 防止重复关停；timeout 控制 IO 线程等待上限
void Application::shutdown(std::chrono::milliseconds timeout) {
    bool expected_shutdown = false;
    if (!shutdown_called_.compare_exchange_strong(expected_shutdown, true)) {
        return; // 已在关停中
    }

    if (!initialized_) {
        return;
    }

    running_.store(false);
    control_runtime_ready_.store(false);
    log_lifecycle("shutting down subsystems");

    if (ipc_server_) {
        ipc_server_->stop();
        ipc_server_.reset();
    }

    if (ipc_client_) {
        ipc_client_->disconnect();
        ipc_client_.reset();
    }

    if (process_manager_) {
        auto pm = std::static_pointer_cast<clink::server::modules::ProcessManager>(process_manager_);
        if (pm) {
            pm->stop();
        }
        process_manager_.reset();
    }

    // Stop modules first, then network resources, then I/O thread/resources.
    stop_modules();

    config_watcher_timer_.cancel();

    if (session_manager_) {
        session_manager_->shutdown();
    }

    // Stop Asio with timeout.
    io_work_.reset();
    io_context_.stop();
    if (io_thread_.joinable()) {
        bool stopped = false;
        if (timeout.count() > 0) {
            std::unique_lock<std::mutex> lock(io_thread_state_mutex_);
            stopped = io_thread_stopped_cv_.wait_for(lock, timeout, [this]() {
                return io_thread_stopped_;
            });
            if (!stopped) {
                log_lifecycle("shutdown timeout reached, I/O thread still running");
            }
        }
        io_thread_.join();
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
        ipc_server_ = ipc::create_server(io_context_, logger_);
    }
    
    setup_ipc_handlers();
    ipc_server_->start(address);
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        effective_ipc_address_ = address;
    }
}

ipc::IpcClient& Application::ipc_client() {
    if (!ipc_client_) {
        ipc_client_ = ipc::create_client(logger_);
    }
    return *ipc_client_;
}

std::string Application::get_session_status() const {
    using json = nlohmann::json;

    const auto state = session_state_.load();
    std::string session_id;
    std::string last_connect_phase;
    std::string last_connect_reason;
    std::string last_connect_message;
    std::string effective_ipc_address;
    std::string effective_process_manager_signature;
    std::string effective_logging_signature;
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        session_id = session_id_;
        last_connect_phase = last_connect_phase_;
        last_connect_reason = last_connect_reason_;
        last_connect_message = last_connect_message_;
        effective_ipc_address = effective_ipc_address_;
        effective_process_manager_signature = effective_process_manager_signature_;
        effective_logging_signature = effective_logging_signature_;
    }

    std::string state_str;
    switch (state) {
        case SessionState::Disconnected:  state_str = control_plane::kStatusDisconnected; break;
        case SessionState::Connecting:    state_str = control_plane::kStatusConnecting; break;
        case SessionState::Connected:     state_str = control_plane::kStatusConnected; break;
        case SessionState::Disconnecting: state_str = control_plane::kStatusDisconnecting; break;
    }

    json result;
    json restart_reasons = json::array();
    const std::string configured_ipc_address = resolve_ipc_address(configuration_);
    if (!effective_ipc_address.empty() && configured_ipc_address != effective_ipc_address) {
        restart_reasons.push_back(control_plane::kConfigDomainIpcAddress);
    }
    if (!effective_process_manager_signature.empty() &&
        build_process_manager_signature(configuration_) != effective_process_manager_signature) {
        restart_reasons.push_back(control_plane::kConfigDomainProcessManagerRuntime);
    }
    if (!effective_logging_signature.empty() &&
        build_logging_signature(configuration_) != effective_logging_signature) {
        restart_reasons.push_back(control_plane::kConfigDomainLogging);
    }
    result[control_plane::kFieldRestartRequired] = !restart_reasons.empty();
    result[control_plane::kFieldRestartReasons] = std::move(restart_reasons);
    if (!effective_ipc_address.empty()) {
        result[control_plane::kFieldEffectiveIpcAddress] = effective_ipc_address;
        result[control_plane::kFieldConfiguredIpcAddress] = configured_ipc_address;
    }

    {
        bool pm_enabled = false;
        bool pm_socks_available = false;
        std::string pm_state = control_plane::kStateNotStarted;
        std::string pm_reason = control_plane::kStateNotStarted;

        if (process_manager_) {
            pm_enabled = true;
            auto pm = std::static_pointer_cast<clink::server::modules::ProcessManager>(process_manager_);
            if (pm) {
                pm_socks_available = pm->socks_available();
                pm_reason = pm->start_reason();
                const auto s = pm->start_state();
                if (s == clink::server::modules::ProcessManager::StartState::Ready) {
                    pm_state = control_plane::kStateReady;
                } else if (s == clink::server::modules::ProcessManager::StartState::Degraded) {
                    pm_state = control_plane::kStateDegraded;
                } else {
                    pm_state = control_plane::kStatusFailed;
                }
            } else {
                pm_state = control_plane::kStateInvalidRef;
            }
        }

        std::string health = control_plane::kHealthGreen;
        if (!pm_enabled || pm_state == control_plane::kStatusFailed) {
            health = control_plane::kHealthRed;
        } else if (pm_state == control_plane::kStateDegraded) {
            health = control_plane::kHealthYellow;
        }

        std::string pm_socks_backend = control_plane::kValueNone;
        if (process_manager_) {
            auto pm = std::static_pointer_cast<clink::server::modules::ProcessManager>(process_manager_);
            if (pm) {
                pm_socks_backend = pm->socks_backend();
            }
        }

        result[control_plane::kFieldHealth] = health;
        result[control_plane::kFieldProcessManager] = json{{"enabled", pm_enabled},
                                                           {control_plane::kFieldState, pm_state},
                                                           {control_plane::kFieldReason, pm_reason},
                                                           {control_plane::kFieldSocksBackend, pm_socks_backend},
                                                           {control_plane::kFieldSocksAvailable, pm_socks_available}};
    }

    if (session_manager_) {
        auto sessions = session_manager_->get_active_sessions();
        const auto summary = summarize_sessions(sessions);
        if (state != SessionState::Disconnecting) {
            if (summary.active_count > 0) {
                state_str = control_plane::kStatusConnected;
            } else if (summary.handshaking_count > 0) {
                state_str = control_plane::kStatusConnecting;
            } else {
                state_str = control_plane::kStatusDisconnected;
            }
        }
        result[control_plane::kFieldStatus] = state_str;
        result[control_plane::kFieldSessionId] = session_id;
        result[control_plane::kFieldConnectPhase] = last_connect_phase;
        result[control_plane::kFieldConnectReason] = last_connect_reason;
        if (!last_connect_message.empty()) {
            result[control_plane::kFieldConnectMessage] = to_utf8_safe(last_connect_message);
        }
        result[control_plane::kFieldActiveSessions] = summary.active_count;
        result[control_plane::kFieldTrackedSessions] = summary.tracked_count;
        
        if (!sessions.empty()) {
            json session_items = json::array();
            for (size_t i = 0; i < sessions.size(); ++i) {
                const auto& s = sessions[i];
                session_items.push_back(json{{control_plane::kFieldId, s.session_id},
                                             {control_plane::kFieldStatus, session_status_to_string(s.status)},
                                             {"user_id", s.user_id},
                                             {"remote_endpoint", s.remote_endpoint},
                                             {"bytes_sent", s.bytes_sent},
                                             {"bytes_received", s.bytes_received},
                                             {"rtt_ms", s.rtt.count()},
                                             {"rto_ms", s.rto.count()},
                                             {"retrans_count", s.retransmission_count},
                                             {"corrupted_packets", s.corrupted_packets},
                                             {"latency_distribution",
                                              json{{"<10ms", s.latency_bucket_10ms},
                                                   {"10-50ms", s.latency_bucket_50ms},
                                                   {"50-100ms", s.latency_bucket_100ms},
                                                   {"100-200ms", s.latency_bucket_200ms},
                                                   {"200-500ms", s.latency_bucket_500ms},
                                                   {"500ms-1s", s.latency_bucket_1s},
                                                   {">1s", s.latency_bucket_inf}}}});
            }
            result[control_plane::kFieldSessions] = std::move(session_items);
        }
    } else {
        result[control_plane::kFieldStatus] = state_str;
        result[control_plane::kFieldSessionId] = session_id;
        result[control_plane::kFieldConnectPhase] = last_connect_phase;
        result[control_plane::kFieldConnectReason] = last_connect_reason;
        if (!last_connect_message.empty()) {
            result[control_plane::kFieldConnectMessage] = to_utf8_safe(last_connect_message);
        }
        result[control_plane::kFieldActiveSessions] = 0;
        result[control_plane::kFieldTrackedSessions] = 0;
    }

    return result.dump();
}

void Application::on_session_event(network::SessionEvent event, const std::string& event_session_id) {
    std::vector<network::SessionContext> sessions;
    if (session_manager_) {
        sessions = session_manager_->get_active_sessions();
    }

    const auto summary = summarize_sessions(sessions);
    active_session_count_.store(static_cast<int>(summary.active_count));

    const auto prev_state = session_state_.load();
    SessionState next_state = SessionState::Disconnected;
    if (summary.active_count > 0) {
        next_state = SessionState::Connected;
    } else if (summary.handshaking_count > 0) {
        next_state = SessionState::Connecting;
    }

    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        session_id_ = summary.primary_active_session_id;
    }

    switch (event) {
        case network::SessionEvent::Connected: {
            session_state_ = next_state;
            if (summary.active_count > 0) {
                {
                    std::lock_guard<std::mutex> lock(control_state_mutex_);
                    last_connect_phase_ = control_plane::kStatusConnected;
                    last_connect_reason_ = control_plane::kValueNone;
                    last_connect_message_.clear();
                }
                logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev_state)) + "->" +
                              std::to_string(static_cast<int>(next_state)) +
                              " reason=engine_start_ok session_id=" + event_session_id +
                              " active_count=" + std::to_string(summary.active_count));
            } else {
                logger_->warn("[connect.state] connected_event_without_active_snapshot session_id=" + event_session_id);
            }
            break;
        }
        case network::SessionEvent::Disconnected: {
            session_state_ = next_state;
            logger_->info("[connect.state] disconnected_event session_id=" + event_session_id +
                          " active_count=" + std::to_string(summary.active_count) +
                          " handshaking_count=" + std::to_string(summary.handshaking_count));
            logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev_state)) + "->" +
                          std::to_string(static_cast<int>(next_state)) +
                          " reason=session_closed");
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
        {
            std::lock_guard<std::mutex> lock(control_state_mutex_);
            last_connect_phase_ = status;
            last_connect_reason_ = reason;
            last_connect_message_ = message;
        }

        json data;
        data["accepted"] = accepted;
        data["status"] = std::move(status);
        data["reason"] = std::move(reason);
        if (!message.empty()) data["message"] = std::move(message);
        if (!endpoint.empty()) data["endpoint"] = std::move(endpoint);
        if (!session_id.empty()) data["session_id"] = std::move(session_id);
        return data.dump();
    };

    if (!session_manager_) {
        logger_->error("[app] cannot connect: session manager unavailable");
        span->set_attribute("error", control_plane::kReasonNoSessionManager);
        logger_->info("connect.final status=rejected reason=no_session_manager");
        return make_result(false, control_plane::kStatusRejected, control_plane::kReasonNoSessionManager);
    }

    logger_->info("[connect.stage] parse_override.begin");
    const auto ov = parse_override(endpoint_override);
    logger_->info("[connect.stage] parse_override.ok endpoint_present=" + std::string(ov.endpoint.empty() ? "false" : "true") +
                  " transport_override=" + (ov.transport.empty() ? std::string(control_plane::kValueNone) : ov.transport) +
                  " timeout_ms=" + std::to_string(ov.timeout_ms) +
                  " no_self_check=" + std::string(ov.no_self_check ? "true" : "false"));

    std::string endpoint = ov.endpoint;
    if (endpoint.empty()) {
        endpoint = configuration_.get_string("transport.server_endpoint");
    }
    if (endpoint.empty()) {
        endpoint = configuration_.get_string("client.remote_endpoint");
    }
    if (endpoint.empty()) {
        logger_->error("[app] cannot connect: endpoint not set (payload/config both empty)");
        span->set_attribute("error", control_plane::kReasonMissingEndpoint);
        logger_->info("connect.final status=rejected reason=missing_endpoint");
        return make_result(false, control_plane::kStatusRejected, control_plane::kReasonMissingEndpoint);
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

    auto parse_hostport = [](const std::string& hostport) {
        std::string host;
        std::string port;
        if (!hostport.empty() && hostport.front() == '[') {
            const auto right_bracket = hostport.find(']');
            if (right_bracket != std::string::npos) {
                host = hostport.substr(1, right_bracket - 1);
                if (right_bracket + 2 <= hostport.size() && hostport[right_bracket + 1] == ':') {
                    port = hostport.substr(right_bracket + 2);
                }
                return std::pair<std::string, std::string>{host, port};
            }
        }

        const auto colon = hostport.rfind(':');
        if (colon == std::string::npos) {
            return std::pair<std::string, std::string>{std::string{}, std::string{}};
        }

        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
        return std::pair<std::string, std::string>{host, port};
    };

    if (!ov.transport.empty() && (ov.transport == "tcp" || ov.transport == "tls")) {
        auto [existing_transport, hostport] = normalize_endpoint(endpoint);
        (void)existing_transport;
        endpoint = ov.transport + "://" + hostport;
    }

    auto [target_transport, target_hostport] = normalize_endpoint(endpoint);
    logger_->info("[connect.stage] normalized_target transport=" + target_transport + " hostport=" + target_hostport);
    auto [target_host, target_port] = parse_hostport(target_hostport);

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
        auto [listen_host, listen_port] = parse_hostport(listen_hostport);

        if (!listen_transport.empty() && !target_transport.empty() && listen_transport != target_transport) {
            bool allow_mismatch = false;
            if (const char* env_allow = std::getenv("CLINK_ALLOW_TRANSPORT_MISMATCH")) {
                if (std::string(env_allow) == "1") {
                    allow_mismatch = true;
                }
            }

            if (!allow_mismatch) {
                logger_->warn("[app] connect rejected: transport mismatch (target=" + target_transport + ", listener=" + listen_transport + ")");
                span->set_attribute("error", control_plane::kReasonTransportMismatch);
                const std::string msg = "target transport does not match listener transport (listener=" + listen_transport + ")";
                logger_->info("connect.final status=rejected reason=transport_mismatch endpoint=" + endpoint);
                return make_result(false, control_plane::kStatusRejected, control_plane::kReasonTransportMismatch, msg, endpoint);
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
            span->set_attribute("error", control_plane::kReasonSelfConnectBlocked);
            logger_->info("connect.final status=rejected reason=self_connect_blocked endpoint=" + endpoint);
            return make_result(false,
                               control_plane::kStatusRejected,
                               control_plane::kReasonSelfConnectBlocked,
                               "Connecting to local listener is disabled by default",
                               endpoint);
        }

        if (self_connect && allow_self_connect_effective) {
            logger_->warn("[app] self-connect override enabled, proceeding: " + endpoint);
        }
    }

    span->set_attribute("endpoint", endpoint);

    SessionState expected_state = SessionState::Disconnected;
    if (!session_state_.compare_exchange_strong(expected_state, SessionState::Connecting)) {
        logger_->warn("Cannot connect: session is already active or in transition");
        span->add_event("connection_aborted_active_session");
        logger_->info("connect.final status=rejected reason=session_not_disconnected");
        return make_result(false, control_plane::kStatusRejected, control_plane::kReasonSessionNotDisconnected);
    }

    logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(expected_state)) + "->" +
                  std::to_string(static_cast<int>(SessionState::Connecting)) +
                  " reason=transport_start.begin endpoint=" + endpoint);
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
        return make_result(false, control_plane::kStatusFailed, control_plane::kReasonTransportStartFailed, err_message, endpoint);
    }
    span->add_event("transport_connected");
    logger_->info("[connect.stage] transport.start.ok endpoint=" + endpoint);

    try {
        logger_->info("[connect.stage] session.create.begin endpoint=" + endpoint);
        session_manager_->create_session(adapter);
        logger_->info("[connect.stage] session.create.ok endpoint=" + endpoint);
    if (session_manager_) {
        const auto sessions_after_create = session_manager_->get_active_sessions();
        logger_->info("[connect.stage] session.create.snapshot tracked_sessions=" + std::to_string(sessions_after_create.size()));
    }
    } catch (const std::exception& ex) {
        logger_->error(std::string("[app] create_session failed: ") + ex.what());
        span->set_attribute("error", ex.what());
        session_state_ = SessionState::Disconnected;
        logger_->info("connect.final status=failed reason=create_session_exception endpoint=" + endpoint);
        return make_result(false, control_plane::kStatusFailed, control_plane::kReasonCreateSessionException, ex.what(), endpoint);
    } catch (...) {
        logger_->error("[app] create_session failed: unknown exception");
        span->set_attribute("error", control_plane::kReasonCreateSessionExceptionUnknown);
        session_state_ = SessionState::Disconnected;
        logger_->info("connect.final status=failed reason=create_session_exception_unknown endpoint=" + endpoint);
        return make_result(false,
                           control_plane::kStatusFailed,
                           control_plane::kReasonCreateSessionExceptionUnknown,
                           "unknown exception",
                           endpoint);
    }

    logger_->info("[connect.stage] state=pending endpoint=" + endpoint);
    logger_->info("Session accepted (pending): endpoint=" + endpoint);
    logger_->info("connect.final status=pending endpoint=" + endpoint);
    span->add_event("session_pending");
    return make_result(true,
                       control_plane::kStatusPending,
                       control_plane::kValueNone,
                       "engine starting asynchronously",
                       endpoint);
}

void Application::disconnect_session() {
    SessionState current_state = session_state_.load();
    while (current_state == SessionState::Connected || current_state == SessionState::Connecting) {
        if (session_state_.compare_exchange_weak(current_state, SessionState::Disconnecting)) {
            break;
        }
    }

    if (current_state != SessionState::Connected && current_state != SessionState::Connecting) {
        logger_->warn("Cannot disconnect: no active session or connection in progress");
        return;
    }

    const auto prev_state = current_state;
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

    std::vector<network::SessionContext> remaining_sessions;
    if (session_manager_) {
        remaining_sessions = session_manager_->get_active_sessions();
    }

    const auto summary = summarize_sessions(remaining_sessions);
    active_session_count_.store(static_cast<int>(summary.active_count));
    {
        std::lock_guard<std::mutex> lock(control_state_mutex_);
        session_id_ = summary.primary_active_session_id;
    }

    SessionState next_state = SessionState::Disconnected;
    if (summary.active_count > 0) {
        next_state = SessionState::Connected;
    } else if (summary.handshaking_count > 0) {
        next_state = SessionState::Connecting;
    }

    const auto prev = session_state_.load();
    session_state_ = next_state;
    logger_->info("[connect.state] transition " + std::to_string(static_cast<int>(prev)) + "->" +
                  std::to_string(static_cast<int>(next_state)) +
                  " reason=disconnect_command active_count=" + std::to_string(summary.active_count) +
                  " handshaking_count=" + std::to_string(summary.handshaking_count));
    if (next_state == SessionState::Disconnected) {
        {
            std::lock_guard<std::mutex> lock(control_state_mutex_);
            last_connect_phase_ = control_plane::kStatusIdle;
            last_connect_reason_ = control_plane::kValueNone;
            last_connect_message_.clear();
        }
        logger_->info("Session disconnected");
    }
}

}  // namespace clink::core
