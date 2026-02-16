#pragma once

#include <chrono>
#include <mutex>
#include <algorithm>

namespace clink::core::network {

/**
 * @brief 令牌桶限流器，用于控制带宽
 */
class RateLimiter {
public:
    /**
     * @param bytes_per_second 每秒允许通过的字节数 (0 表示不限流)
     * @param burst_size 允许的最大突发字节数
     */
    RateLimiter(size_t bytes_per_second, size_t burst_size);

    /**
     * @brief 尝试获取发送指定大小数据的许可
     * @return 如果允许发送则返回 true，否则返回 false
     */
    bool consume(size_t bytes);

    /**
     * @brief 动态更新限流参数
     */
    void update_limits(size_t bytes_per_second, size_t burst_size);

private:
    void refill();

    size_t bytes_per_second_;
    size_t burst_size_;
    double tokens_;
    std::chrono::steady_clock::time_point last_refill_time_;
    std::mutex mutex_;
};

} // namespace clink::core::network
