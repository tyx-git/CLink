#pragma once

#include <asio.hpp>
#include <memory>
#include "clink/core/logging/logger.hpp"
#include "clink/core/network/packet.hpp"
#include "clink/core/network/rate_limiter.hpp"
#include <set>
#include <map>
#include <mutex>
#include <functional>
#include <atomic>
#include "clink/core/memory/buffer_pool.hpp"

namespace clink::core::network {

/**
 * @brief 可靠传输引擎，负责序列号生成、确认处理和重传逻辑
 */
class ReliabilityEngine : public std::enable_shared_from_this<ReliabilityEngine> {
public:
    using SendFunction = std::function<void(const Packet&)>;

    explicit ReliabilityEngine(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, SendFunction send_fn);
    ~ReliabilityEngine();

    /**
     * @brief 发送数据包，并加入重传队列
     */
    void send_reliable(PacketType type, std::shared_ptr<clink::core::memory::Block> payload);

    /**
     * @brief 处理收到的确认号
     */
    void process_ack(uint32_t ack_num);

    /**
     * @brief 处理收到的选择性确认 (SACK)
     * @param sack_blocks 已经收到的不连续序列号范围 (start_seq, end_seq)
     */
    void process_sack(const std::vector<std::pair<uint32_t, uint32_t>>& sack_blocks);

    /**
     * @brief 获取当前由于丢包而需要发送 SACK 的块
     */
    std::vector<std::pair<uint32_t, uint32_t>> get_sack_blocks() const;

    /**
     * @brief 处理收到的数据包 (更新本地期待的确认号等)
     */
    uint32_t get_next_seq() { return next_seq_num_++; }
    uint32_t get_last_received_seq() const { return last_received_seq_; }
    void set_last_received_seq(uint32_t seq);

    void start();
    void stop();

    /**
     * @brief 发送心跳包
     */
    void send_heartbeat();

    /**
     * @brief 发送纯确认包
     */
    void send_ack();

    /**
     * @brief 设置带宽限制 (字节/秒)
     */
    void set_rate_limit(size_t bytes_per_second, size_t burst_size);

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
        std::chrono::milliseconds rtt{0};
        std::chrono::milliseconds rttvar{0}; // RTT 变化量
        std::chrono::milliseconds rto{200};  // 当前计算出的 RTO
        uint64_t retransmission_count{0};
        uint64_t total_sent{0};
        uint64_t total_acked{0};
        uint64_t bytes_sent{0};
        uint64_t bytes_received{0};
        uint32_t cwnd{10};           // 当前拥塞窗口 (以包为单位)
        uint32_t ssthresh{64};       // 慢启动阈值
    };
    Stats get_stats() const;

private:
    void start_timer();
    void update_rto(std::chrono::milliseconds rtt_sample);

    asio::io_context& io_context_;
    std::shared_ptr<logging::Logger> logger_;
    SendFunction send_fn_;
    
    std::atomic<uint32_t> next_seq_num_{1};
    std::atomic<uint32_t> last_received_seq_{0};
    
    // 接收端乱序包跟踪
    mutable std::mutex received_packets_mutex_;
    std::set<uint32_t> out_of_order_packets_;

    // 快速重传相关
    std::atomic<uint32_t> last_ack_num_{0};
    std::atomic<uint32_t> dup_ack_count_{0};
    std::atomic<uint32_t> ack_count_{0}; // For congestion avoidance
    const uint32_t fast_retransmit_threshold_{3};
    
    std::mutex queue_mutex_;
    std::map<uint32_t, RetransmissionEntry> unacked_packets_;
    
    std::unique_ptr<RateLimiter> rate_limiter_;
    
    mutable std::mutex stats_mutex_;
    Stats stats_;

    std::atomic<bool> running_{false};
    asio::steady_timer timer_;

    // 指数退避参数
    const std::chrono::milliseconds initial_rto_{200};
    const std::chrono::milliseconds max_rto_{5000};
    const int max_retries_{10};
};

} // namespace clink::core::network
