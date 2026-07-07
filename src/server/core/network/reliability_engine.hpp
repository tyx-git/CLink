#pragma once

#include <asio.hpp>
#include <memory>
#include "src/share/core/logging/logger.hpp"
#include "src/share/core/network/packet.hpp"
#include "src/server/core/network/rate_limiter.hpp"
#include <set>
#include <map>
#include <mutex>
#include <functional>
#include <atomic>
#include "src/server/core/memory/buffer_pool.hpp"

namespace clink::core::network {

// 可靠传输引擎：序列号、重传队列、SACK、拥塞控制、RTT/RTO 估计
class ReliabilityEngine : public std::enable_shared_from_this<ReliabilityEngine> {
public:
    using SendFunction = std::function<void(const Packet&)>;

    explicit ReliabilityEngine(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, SendFunction send_fn);
    ~ReliabilityEngine();

    void send_reliable(PacketType type, std::shared_ptr<clink::core::memory::Block> payload); // 可靠发送：分配 seq + 入重传队列
    void process_ack(uint32_t ack_num);            // 处理 ACK：从重传队列移除已确认包
    void process_sack(const std::vector<std::pair<uint32_t, uint32_t>>& sack_blocks); // 处理 SACK 块
    std::vector<std::pair<uint32_t, uint32_t>> get_sack_blocks() const; // 获取乱序包区间 → 生成 SACK
    uint32_t get_next_seq() { return next_seq_num_++; }  // 分配下一个序列号（原子递增）
    uint32_t get_last_received_seq() const { return last_received_seq_; }
    void set_last_received_seq(uint32_t seq);

    // Compatibility helper for tests/legacy call sites.
    void start();                                              // 同步启动定时器
    void start_async(std::function<void(std::error_code)> on_started = {}); // 异步启动（timer 在 io_context 线程创建）
    void stop();                                               // 幂等停止
    void send_heartbeat();                                     // 发送心跳包
    void send_ack(uint32_t ack_num = 0);                       // 发送纯确认包
    void set_rate_limit(size_t bytes_per_second, size_t burst_size); // 令牌桶限速
    void report_corrupted_packet();                            // 记录校验和失败

    void set_timer_enabled(bool enabled) { timer_enabled_.store(enabled, std::memory_order_relaxed); }

    /**
     * @brief 记录收到的字节数
     */
    void record_received_bytes(size_t bytes) {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.bytes_received += bytes;
    }

    /**
     * @brief 获取统计信息
     */
    struct Stats {
        std::chrono::milliseconds rtt{0};          // 当前 RTT
        std::chrono::milliseconds rttvar{0};       // RTT 变化量（用于计算 RTO）
        std::chrono::milliseconds rto{200};        // 重传超时时间
        uint64_t retransmission_count{0};           // 总重传次数
        uint64_t total_sent{0};                     // 总发送包数
        uint64_t total_acked{0};                    // 总确认包数
        uint64_t bytes_sent{0};                     // 总发送字节数
        uint64_t bytes_received{0};                 // 总接收字节数
        uint32_t cwnd{10};                          // 拥塞窗口（以包为单位）
        uint32_t ssthresh{64};                      // 慢启动阈值
        uint64_t corrupted_packets{0};              // 校验和失败包数
        uint32_t latency_bucket_10ms{0};            // 延迟分布：< 10ms
        uint32_t latency_bucket_50ms{0};            // 10-50ms
        uint32_t latency_bucket_100ms{0};           // 50-100ms
        uint32_t latency_bucket_200ms{0};           // 100-200ms
        uint32_t latency_bucket_500ms{0};           // 200-500ms
        uint32_t latency_bucket_1s{0};              // 500ms-1s
        uint32_t latency_bucket_inf{0};             // > 1s
    };
    Stats get_stats() const;

private:
    void ensure_timer();
    void start_timer();
    void update_rto(std::chrono::milliseconds rtt_sample);

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    SendFunction send_fn_;
    
    std::atomic<uint32_t> next_seq_num_{1};      // 下一个待分配的序列号（从 1 开始）
    std::atomic<uint32_t> last_received_seq_{0};  // 已收到的最大连续序列号
    
    mutable std::mutex received_packets_mutex_;
    std::set<uint32_t> out_of_order_packets_;    // 乱序到达的序列号集合（用于生成 SACK）

    std::atomic<uint32_t> last_ack_num_{0};      // 上次收到的 ACK 号
    std::atomic<uint32_t> dup_ack_count_{0};     // 重复 ACK 计数
    std::atomic<uint32_t> ack_count_{0};          // ACK 总数（拥塞避免用）
    const uint32_t fast_retransmit_threshold_{3}; // 快速重传阈值：连续 3 个重复 ACK 触发
    
    std::mutex queue_mutex_;
    std::map<uint32_t, RetransmissionEntry> unacked_packets_; // 重传队列：seq → RetransmissionEntry
    
    std::unique_ptr<RateLimiter> rate_limiter_;
    
    mutable std::mutex stats_mutex_;
    Stats stats_;

    std::atomic<bool> running_{false};
    std::atomic<bool> shutting_down_{false};
    std::atomic<bool> timer_enabled_{true};
    std::atomic<bool> timer_active_{false};
    std::unique_ptr<asio::steady_timer> timer_;
    std::mutex timer_mutex_;
    std::once_flag timer_once_;

    // 指数退避参数：起始 200ms → 最大 5000ms，最多重试 10 次
    const std::chrono::milliseconds initial_rto_{200};
    const std::chrono::milliseconds max_rto_{5000};
    const int max_retries_{10};
};

} // namespace clink::core::network
