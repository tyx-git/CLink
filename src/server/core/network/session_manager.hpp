#pragma once

#include <memory>
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_map>
#include <functional>
#include <chrono>

#include "src/server/core/network/transport_adapter.hpp"
#include "src/server/core/network/transport_listener.hpp"
#include "src/server/core/policy/engine.hpp"

namespace clink::core::network {

// 会话状态机：Idle → Handshaking → Active → Closing / Error
enum class SessionStatus {
    Idle,        // 空闲：新创建或已回收
    Handshaking, // 握手：正在进行初始协商
    Active,      // 活跃：数据可双向传输
    Closing,     // 关闭：正在清理资源
    Error        // 错误：异常终止
};

enum class SessionEvent {
    Connected,
    Disconnected
};

// 单个会话的完整上下文：基础信息 + 流量统计 + QoS 指标
struct SessionContext {
    std::string session_id;             // 全局唯一会话标识符
    std::string user_id;                 // 用户身份（来自 PSK 鉴权）
    std::string device_id;              // 设备标识
    std::string remote_endpoint;         // 远端端点 (IP:Port)
    SessionStatus status{SessionStatus::Idle}; // 当前状态
    std::chrono::system_clock::time_point last_activity; // 最后活动时间（用于空闲回收）
    uint64_t bytes_sent{0};              // 累计发送字节数
    uint64_t bytes_received{0};          // 累计接收字节数
    std::chrono::milliseconds rtt{0};    // 当前往返时间估计
    std::chrono::milliseconds rto{200};  // 重传超时（指数退避）
    float packet_loss_rate{0.0f};        // 丢包率
    policy::Policy policy;
    
    // QoS 指标：重传次数、损坏包数、延迟分布（7个桶，<10ms 到 >1s）
    uint64_t retransmission_count{0};
    uint64_t corrupted_packets{0};
    uint32_t latency_bucket_10ms{0};    // < 10ms
    uint32_t latency_bucket_50ms{0};    // 10-50ms
    uint32_t latency_bucket_100ms{0};   // 50-100ms
    uint32_t latency_bucket_200ms{0};   // 100-200ms
    uint32_t latency_bucket_500ms{0};   // 200-500ms
    uint32_t latency_bucket_1s{0};      // 500ms-1s
    uint32_t latency_bucket_inf{0};     // > 1s
};

// 会话管理器接口：管理所有活跃网络会话和虚拟网卡的生命周期
class SessionManager : public std::enable_shared_from_this<SessionManager> {
public:
    using SessionEventCallback = std::function<void(SessionEvent, const std::string&)>;

    virtual ~SessionManager() = default;

    virtual std::error_code initialize() = 0;                        // 初始化（创建虚拟网卡等）
    virtual void handle_new_connection(TransportAdapterPtr adapter) = 0;  // 新连接从 listener 到达
    virtual void add_listener(TransportListenerPtr listener) = 0;     // 注册传输监听器
    virtual std::error_code start_listen(TransportListenerPtr listener, const std::string& endpoint) = 0; // 开始在端点监听
    virtual void create_session(TransportAdapterPtr adapter) = 0;     // 手动创建会话（客户端主动发起）
    virtual void terminate_session(const std::string& session_id) = 0; // 终止指定会话
    virtual std::vector<SessionContext> get_active_sessions() const = 0; // 获取会话快照
    virtual std::string get_virtual_interface_address() const = 0;    // 获取虚拟网卡 IP
    virtual std::error_code route_packet(const uint8_t* data, size_t size) = 0; // 数据包路由到对应会话
    virtual void broadcast(const uint8_t* data, size_t size) = 0;     // 广播数据到所有会话
    virtual void shutdown() = 0;                                       // 关闭管理器释放资源
    virtual void set_default_rate_limit(size_t bytes_per_second, size_t burst_size) = 0; // 带宽限制
    virtual void set_session_event_callback(SessionEventCallback cb) = 0; // 会话事件回调
    virtual void set_session_idle_timeout(std::chrono::seconds timeout) = 0; // 空闲超时回收
};

using SessionManagerPtr = std::shared_ptr<SessionManager>;

}  // namespace clink::core::network
