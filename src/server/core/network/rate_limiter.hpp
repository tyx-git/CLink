#pragma once

#include <chrono>
#include <mutex>
#include <algorithm>

namespace clink::core::network {

// 令牌桶限流器：控制带宽上限
// 被 ReliabilityEngine 调用，限制每个会话的发送速率
class RateLimiter {
public:
    RateLimiter(size_t bytes_per_second, size_t burst_size);
    bool consume(size_t bytes);           // 消费令牌：成功返回 true，失败（限流）返回 false
    void update_limits(size_t bytes_per_second, size_t burst_size); // 动态更新限流参数
private:
    void refill();                        // 按时间间隔补充令牌
    size_t bytes_per_second_;             // 每秒令牌数（字节）
    size_t burst_size_;                   // 最大突发
    double tokens_;                       // 当前令牌数
    std::chrono::steady_clock::time_point last_refill_time_;
    std::mutex mutex_;
};

} // namespace clink::core::network
