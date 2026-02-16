#include "clink/core/network/rate_limiter.hpp"

namespace clink::core::network {

RateLimiter::RateLimiter(size_t bytes_per_second, size_t burst_size)
    : bytes_per_second_(bytes_per_second),
      burst_size_(burst_size),
      tokens_(static_cast<double>(burst_size)),
      last_refill_time_(std::chrono::steady_clock::now()) {
}

bool RateLimiter::consume(size_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (bytes_per_second_ == 0) {
        return true;
    }

    refill();

    if (tokens_ >= static_cast<double>(bytes)) {
        tokens_ -= static_cast<double>(bytes);
        return true;
    }

    return false;
}

void RateLimiter::update_limits(size_t bytes_per_second, size_t burst_size) {
    std::lock_guard<std::mutex> lock(mutex_);
    bytes_per_second_ = bytes_per_second;
    burst_size_ = burst_size;
    // 限制当前令牌不超过新的突发大小
    tokens_ = std::min(tokens_, static_cast<double>(burst_size));
}

void RateLimiter::refill() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration<double>(now - last_refill_time_).count();
    
    double new_tokens = elapsed * static_cast<double>(bytes_per_second_);
    tokens_ = std::min(static_cast<double>(burst_size_), tokens_ + new_tokens);
    last_refill_time_ = now;
}

} // namespace clink::core::network
