#pragma once

#include "clink/core/network/session_manager.hpp"
#include "clink/core/network/virtual_interface.hpp"
#include "clink/core/logging/logger.hpp"
#include "clink/core/network/reliability_engine.hpp"
#include "clink/core/network/acl.hpp"
#include <asio.hpp>
#include <mutex>
#include <atomic>
#include <thread>

namespace clink::core::network {

/**
 * @brief 会话管理器的默认实现
 */
class DefaultSessionManager : public SessionManager {
public:
    explicit DefaultSessionManager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    ~DefaultSessionManager() override;

    std::error_code initialize() override;
    std::error_code start_listen(TransportListenerPtr listener, const std::string& endpoint) override;
    void create_session(TransportAdapterPtr adapter) override;
    void handle_new_connection(TransportAdapterPtr adapter) override;
    void add_listener(TransportListenerPtr listener) override;
    void terminate_session(const std::string& session_id) override;
    std::vector<SessionContext> get_active_sessions() const override;
    std::error_code route_packet(const uint8_t* data, size_t size) override;
    void broadcast(const uint8_t* data, size_t size) override;
    void shutdown() override;

    void set_default_rate_limit(size_t bytes_per_second, size_t burst_size) override {
        default_bytes_per_second_ = bytes_per_second;
        default_burst_size_ = burst_size;
    }

    void set_acl(std::shared_ptr<AccessControlList> acl) { acl_ = std::move(acl); }
    void set_policy_engine(std::shared_ptr<policy::PolicyEngine> engine) { policy_engine_ = std::move(engine); }

protected:
    virtual VirtualInterfacePtr create_interface();

private:
    void start_heartbeat_timer();
    void start_tun_read();

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    mutable std::shared_mutex sessions_mutex_;
    std::unordered_map<std::string, SessionContext> sessions_;
    std::unordered_map<std::string, TransportAdapterPtr> adapters_;
    std::unordered_map<std::string, std::shared_ptr<ReliabilityEngine>> engines_;
    std::vector<TransportListenerPtr> listeners_;
    std::shared_ptr<AccessControlList> acl_;
    std::shared_ptr<policy::PolicyEngine> policy_engine_;
    
    size_t default_bytes_per_second_{0};
    size_t default_burst_size_{0};

    VirtualInterfacePtr virtual_interface_;
    std::atomic<bool> running_{false};
    
    asio::steady_timer heartbeat_timer_;
};

/**
 * @brief 工厂函数，创建 SessionManager 实例
 */
std::unique_ptr<SessionManager> create_session_manager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);

}  // namespace clink::core::network
