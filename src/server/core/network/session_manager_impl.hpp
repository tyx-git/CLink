#pragma once

#include "src/server/core/network/session_manager.hpp"
#include "src/server/core/network/virtual_interface.hpp"
#include "src/share/core/logging/logger.hpp"
#include "src/server/core/network/reliability_engine.hpp"
#include "src/server/core/network/acl.hpp"
#include <asio.hpp>
#include <mutex>
#include <atomic>
#include <thread>

namespace clink::core::network {

// SessionManager 的默认实现：绑定传输适配器、虚拟网卡、可靠性引擎、ACL
class DefaultSessionManager : public SessionManager {
public:
    explicit DefaultSessionManager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);
    ~DefaultSessionManager() override;

    std::error_code initialize() override;            // 初始化：创建虚拟网卡、启动心跳
    std::error_code start_listen(TransportListenerPtr listener, const std::string& endpoint) override; // 启动监听
    void create_session(TransportAdapterPtr adapter) override;      // 创建新会话（客户端主动）
    void handle_new_connection(TransportAdapterPtr adapter) override; // listener 新连接到达
    void add_listener(TransportListenerPtr listener) override;      // 注册 listener
    void terminate_session(const std::string& session_id) override;  // 终止会话
    std::vector<SessionContext> get_active_sessions() const override; // 快照所有会话
    std::string get_virtual_interface_address() const override;      // 虚拟网卡 IP
    std::error_code route_packet(const uint8_t* data, size_t size) override; // IP 包路由到目标会话
    void broadcast(const uint8_t* data, size_t size) override;       // 广播到所有会话
    void shutdown() override;                                        // 关停所有资源

    void set_default_rate_limit(size_t bytes_per_second, size_t burst_size) override {
        default_bytes_per_second_ = bytes_per_second;
        default_burst_size_ = burst_size;
    }

    void set_virtual_interface_config(std::string name, std::string address, std::string netmask) {
        interface_name_ = std::move(name);
        interface_address_ = std::move(address);
        interface_netmask_ = std::move(netmask);
    }

    void set_virtual_interface_enabled(bool enabled) {
        virtual_interface_enabled_ = enabled;
    }

    void set_zero_copy_enabled(bool enabled) {
        zero_copy_enabled_ = enabled;
    }

    void set_acl(std::shared_ptr<AccessControlList> acl) { acl_ = std::move(acl); }
    void set_policy_engine(std::shared_ptr<policy::PolicyEngine> engine) { policy_engine_ = std::move(engine); }
    void set_session_event_callback(SessionEventCallback cb) override { session_event_cb_ = std::move(cb); }
    void set_session_idle_timeout(std::chrono::seconds timeout) override { session_idle_timeout_ = timeout; }
    void set_reliability_timer_enabled(bool enabled) { reliability_timer_enabled_ = enabled; }
    void reset_listeners();

protected:
    virtual VirtualInterfacePtr create_interface();

private:
    void start_heartbeat_timer();
    void start_tun_read();

    asio::io_context& io_context_;                               // Asio 事件循环引用
    std::shared_ptr<logging::Logger> logger_;
    mutable std::shared_mutex sessions_mutex_;                    // 保护下面四张表（读写锁，容器操作才持锁）
    std::unordered_map<std::string, SessionContext> sessions_;     // 会话元数据表：会话ID → SessionContext
    std::unordered_map<std::string, TransportAdapterPtr> adapters_; // 传输适配器表：会话ID → TCP/TLS 适配器
    std::unordered_map<std::string, std::shared_ptr<ReliabilityEngine>> engines_; // 可靠性引擎表：会话ID → ReliabilityEngine
    std::unordered_map<std::string, std::vector<uint8_t>> pending_receive_buffers_; // 未处理收到的数据缓冲区
    std::vector<TransportListenerPtr> listeners_;
    std::shared_ptr<AccessControlList> acl_;
    std::shared_ptr<policy::PolicyEngine> policy_engine_;
    SessionEventCallback session_event_cb_;
    
    size_t default_bytes_per_second_{0};
    size_t default_burst_size_{0};

    VirtualInterfacePtr virtual_interface_;   // 虚拟网卡实例（Wintun / TUN）
    std::string virtual_interface_address_;
    std::atomic<bool> running_{false};
    std::string interface_name_{"clink0"};        // 虚拟网卡设备名
    std::string interface_address_{"10.8.0.1"};    // 虚拟网卡 IP（服务端默认 .1，客户端从 .2 起分配）
    std::string interface_netmask_{"255.255.255.0"};
    bool virtual_interface_enabled_{true};        // 是否启用虚拟网卡（可被 CLINK_DISABLE_VIF=1 关闭）
    bool zero_copy_enabled_{true};
    std::chrono::seconds session_idle_timeout_{std::chrono::seconds(0)};
    bool reliability_timer_enabled_{true};

    std::atomic<uint32_t> tun_read_error_streak_{0};      // TUN 读错误连续计数（用于分级退避）
    std::atomic<uint64_t> tun_read_loop_counter_{0};      // TUN 读循环总次数
    std::atomic<uint64_t> network_to_tun_counter_{0};     // 隧道→虚拟网卡方向的包计数
    uint32_t telemetry_sample_every_{64};                  // 遥测采样率（默认 64 取 1）

    asio::steady_timer heartbeat_timer_;
    asio::steady_timer tun_retry_timer_;
};

/**
 * @brief 工厂函数，创建 SessionManager 实例
 */
std::shared_ptr<SessionManager> create_session_manager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger);

}  // namespace clink::core::network
