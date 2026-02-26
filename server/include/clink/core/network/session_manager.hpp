#pragma once

#include <memory>
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_map>

#include "server/include/clink/core/network/transport_adapter.hpp"
#include "server/include/clink/core/network/transport_listener.hpp"
#include "server/include/clink/core/policy/engine.hpp"

namespace clink::core::network {

/**
 * @brief 会话状态定义
 */
enum class SessionStatus {
    Idle,
    Handshaking,
    Active,
    Closing,
    Error
};

/**
 * @brief 会话上下文，存储单个连接的所有状态
 */
struct SessionContext {
    std::string session_id;
    std::string user_id;
    std::string device_id;
    std::string remote_endpoint;
    SessionStatus status{SessionStatus::Idle};
    std::chrono::system_clock::time_point last_activity;
    uint64_t bytes_sent{0};
    uint64_t bytes_received{0};
    std::chrono::milliseconds rtt{0};
    std::chrono::milliseconds rto{200};
    float packet_loss_rate{0.0f};
    policy::Policy policy;
    
    // Quality Metrics
    uint64_t retransmission_count{0};
    uint64_t corrupted_packets{0};
    uint32_t latency_bucket_10ms{0};
    uint32_t latency_bucket_50ms{0};
    uint32_t latency_bucket_100ms{0};
    uint32_t latency_bucket_200ms{0};
    uint32_t latency_bucket_500ms{0};
    uint32_t latency_bucket_1s{0};
    uint32_t latency_bucket_inf{0};
};

/**
 * @brief 会话管理器接口，负责管理所有活动的网络会话和虚拟接口
 */
class SessionManager : public std::enable_shared_from_this<SessionManager> {
public:
    virtual ~SessionManager() = default;

    /**
     * @brief 初始化管理器 (如创建虚拟网卡)
     */
    virtual std::error_code initialize() = 0;

    /**
     * @brief 处理新连接请求
     */
    virtual void handle_new_connection(TransportAdapterPtr adapter) = 0;

    /**
     * @brief 添加传输监听器
     */
    virtual void add_listener(TransportListenerPtr listener) = 0;

    /**
     * @brief 开始在指定端点监听新连接
     */
    virtual std::error_code start_listen(TransportListenerPtr listener, const std::string& endpoint) = 0;

    /**
     * @brief 手动创建一个会话 (通常用于客户端主动发起连接)
     */
    virtual void create_session(TransportAdapterPtr adapter) = 0;

    /**
     * @brief 终止特定会话
     */
    virtual void terminate_session(const std::string& session_id) = 0;

    /**
     * @brief 获取所有活跃会话的快照
     */
    virtual std::vector<SessionContext> get_active_sessions() const = 0;

    /**
     * @brief 获取虚拟接口的 IP 地址
     */
    virtual std::string get_virtual_interface_address() const = 0;

    /**
     * @brief 路由数据包到对应的会话或虚拟接口
     */
    virtual std::error_code route_packet(const uint8_t* data, size_t size) = 0;

    /**
     * @brief 广播数据包到所有活跃会话 (用于控制消息或特定广播流)
     */
    virtual void broadcast(const uint8_t* data, size_t size) = 0;

    /**
     * @brief 关闭管理器，释放所有资源
     */
    virtual void shutdown() = 0;

    /**
     * @brief 设置全局默认带宽限制
     */
    virtual void set_default_rate_limit(size_t bytes_per_second, size_t burst_size) = 0;
};

using SessionManagerPtr = std::shared_ptr<SessionManager>;

}  // namespace clink::core::network
