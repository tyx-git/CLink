#include "clink/core/network/reliability_engine.hpp"
#include "clink/core/network/packet.hpp"
#include <algorithm>

namespace clink::core::network {

ReliabilityEngine::ReliabilityEngine(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, SendFunction send_fn)
    : io_context_(io_context), logger_(std::move(logger)), send_fn_(std::move(send_fn)),
      rate_limiter_(std::make_unique<RateLimiter>(0, 0)), timer_(io_context) {
}

ReliabilityEngine::~ReliabilityEngine() {
    stop();
}

void ReliabilityEngine::start() {
    if (running_) return;
    running_ = true;
    start_timer();
}

void ReliabilityEngine::stop() {
    running_ = false;
    timer_.cancel();
}

void ReliabilityEngine::start_timer() {
    if (!running_) return;

    timer_.expires_after(std::chrono::milliseconds(50));
    auto self = shared_from_this();
    timer_.async_wait([self](std::error_code ec) {
        if (ec) return;

        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(self->queue_mutex_);
        
        for (auto& [seq, entry] : self->unacked_packets_) {
            // 1. 处理尚未进行初始发送的包 (受限于 CWND 和速率)
            if (!entry.sent) {
                bool can_send = false;
                {
                    std::lock_guard<std::mutex> stats_lock(self->stats_mutex_);
                    if (self->unacked_packets_.size() < self->stats_.cwnd) {
                        can_send = true;
                    }
                }
                
                if (can_send) {
                    auto raw_data = entry.packet->serialize();
                    if (self->rate_limiter_ && self->rate_limiter_->consume(raw_data.size())) {
                        entry.sent = true;
                        entry.last_send_time = now;
                        if (self->send_fn_) self->send_fn_(raw_data);
                        continue;
                    }
                }
                continue;
            }

            // 2. 处理超时重传
            auto current_rto = std::max(entry.current_timeout, self->get_stats().rto);
            if (std::chrono::steady_clock::now() - entry.last_send_time >= current_rto) {
                if (entry.retry_count >= self->max_retries_) {
                    if (self->logger_) self->logger_->error("[reliability] max retries reached for seq " + std::to_string(seq));
                    continue;
                }

                auto raw_data = entry.packet->serialize();
                if (self->rate_limiter_ && !self->rate_limiter_->consume(raw_data.size())) continue;

                entry.retry_count++;
                {
                    std::lock_guard<std::mutex> stats_lock(self->stats_mutex_);
                    self->stats_.retransmission_count++;
                    self->stats_.ssthresh = std::max(self->stats_.cwnd / 2, 2u);
                    self->stats_.cwnd = 2;
                }
                entry.current_timeout = std::min(entry.current_timeout * 2, self->max_rto_);
                entry.last_send_time = std::chrono::steady_clock::now();

                if (self->logger_) self->logger_->warn("[reliability] retransmitting seq " + std::to_string(seq));
                if (self->send_fn_) self->send_fn_(raw_data);
            }
        }

        self->start_timer();
    });
}

void ReliabilityEngine::set_rate_limit(size_t bytes_per_second, size_t burst_size) {
    if (rate_limiter_) {
        rate_limiter_->update_limits(bytes_per_second, burst_size);
    }
}

void ReliabilityEngine::send_reliable(PacketType type, std::vector<uint8_t> payload) {
    auto packet = std::make_unique<Packet>();
    packet->header.type = static_cast<uint8_t>(type);
    packet->header.flags = 0;
    packet->header.payload_size = static_cast<uint16_t>(payload.size());
    packet->header.seq_num = next_seq_num_++;
    packet->header.ack_num = last_received_seq_.load();
    packet->payload = std::move(payload);

    auto raw_data = packet->serialize();
    
    uint32_t seq = 0;
    bool can_send_now = false;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        RetransmissionEntry entry;
        entry.packet = std::move(packet);
        entry.last_send_time = std::chrono::steady_clock::now();
        entry.current_timeout = initial_rto_;
        entry.retry_count = 0;
        entry.sent = false;
        
        seq = entry.packet->header.seq_num;
        
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            if (unacked_packets_.size() < stats_.cwnd) {
                can_send_now = true;
                entry.sent = true;
            }
        }
        
        unacked_packets_[seq] = std::move(entry);
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_sent++;
        stats_.bytes_sent += raw_data.size();
    }

    if (can_send_now && send_fn_) {
        if (rate_limiter_ && rate_limiter_->consume(raw_data.size())) {
            send_fn_(raw_data);
        } else {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (unacked_packets_.count(seq)) {
                unacked_packets_[seq].sent = false;
            }
        }
    }
}

void ReliabilityEngine::process_ack(uint32_t ack_num) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    if (ack_num > 0 && ack_num == last_ack_num_) {
        dup_ack_count_++;
        if (dup_ack_count_ == fast_retransmit_threshold_) {
            auto it = unacked_packets_.find(ack_num + 1);
            if (it != unacked_packets_.end()) {
                auto raw_data = it->second.packet->serialize();
                if (send_fn_) send_fn_(raw_data);
                
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.ssthresh = std::max(2u, stats_.cwnd / 2);
                stats_.cwnd = stats_.ssthresh + static_cast<uint32_t>(fast_retransmit_threshold_);
                stats_.retransmission_count++;
            }
        } else if (dup_ack_count_ > fast_retransmit_threshold_) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.cwnd++;
        }
    } else if (ack_num > last_ack_num_) {
        if (dup_ack_count_ >= fast_retransmit_threshold_) {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.cwnd = stats_.ssthresh;
        }
        last_ack_num_ = ack_num;
        dup_ack_count_ = 0;
    }

    bool new_ack = false;
    auto it = unacked_packets_.begin();
    while (it != unacked_packets_.end()) {
        if (it->first > ack_num) break;

        new_ack = true;
        if (it->second.retry_count == 0) {
            auto rtt_sample = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_send_time);
            update_rto(rtt_sample);
        }
        
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.total_acked++;
        }
        it = unacked_packets_.erase(it);
    }

    if (new_ack) {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        if (stats_.cwnd < stats_.ssthresh) {
            stats_.cwnd += 1;
        } else {
            // Congestion Avoidance
            if (++ack_count_ >= stats_.cwnd) {
                stats_.cwnd += 1;
                ack_count_ = 0;
            }
        }
    }
}

void ReliabilityEngine::process_sack(const std::vector<std::pair<uint32_t, uint32_t>>& sack_blocks) {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    uint32_t max_sacked_seq = 0;
    for (const auto& block : sack_blocks) {
        uint32_t start = block.first;
        uint32_t end = block.second;
        if (end > max_sacked_seq) max_sacked_seq = end;
        
        auto it = unacked_packets_.lower_bound(start);
        while (it != unacked_packets_.end() && it->first <= end) {
            if (it->second.retry_count == 0) {
                auto rtt_sample = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second.last_send_time);
                update_rto(rtt_sample);
            }
            {
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.total_acked++;
            }
            it = unacked_packets_.erase(it);
        }
    }

    if (max_sacked_seq > 0) {
        for (auto& [seq, entry] : unacked_packets_) {
            if (seq < max_sacked_seq) {
                entry.sack_count++;
                if (entry.sack_count == fast_retransmit_threshold_) {
                    auto raw_data = entry.packet->serialize();
                    if (send_fn_) send_fn_(raw_data);
                    
                    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                    stats_.retransmission_count++;
                    if (dup_ack_count_ < fast_retransmit_threshold_) {
                        stats_.ssthresh = std::max(2u, stats_.cwnd / 2);
                        stats_.cwnd = stats_.ssthresh;
                    }
                }
            }
        }
    }
}

std::vector<std::pair<uint32_t, uint32_t>> ReliabilityEngine::get_sack_blocks() const {
    std::lock_guard<std::mutex> lock(received_packets_mutex_);
    std::vector<std::pair<uint32_t, uint32_t>> blocks;
    if (out_of_order_packets_.empty()) return blocks;
    
    uint32_t start = 0, last = 0;
    for (uint32_t seq : out_of_order_packets_) {
        if (start == 0) { start = seq; last = seq; }
        else if (seq == last + 1) last = seq;
        else { blocks.push_back({start, last}); start = seq; last = seq; }
    }
    blocks.push_back({start, last});
    if (blocks.size() > 4) blocks.erase(blocks.begin(), blocks.end() - 4);
    return blocks;
}

void ReliabilityEngine::set_last_received_seq(uint32_t seq) {
    std::lock_guard<std::mutex> lock(received_packets_mutex_);
    if (seq <= last_received_seq_) return;
    if (seq == last_received_seq_ + 1) {
        last_received_seq_ = seq;
        auto it = out_of_order_packets_.begin();
        while (it != out_of_order_packets_.end() && *it == last_received_seq_ + 1) {
            last_received_seq_ = *it;
            it = out_of_order_packets_.erase(it);
        }
    } else {
        out_of_order_packets_.insert(seq);
    }
}

void ReliabilityEngine::update_rto(std::chrono::milliseconds rtt_sample) {
    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
    if (stats_.rtt.count() == 0) {
        stats_.rtt = rtt_sample;
        stats_.rttvar = rtt_sample / 2;
    } else {
        auto delta = (stats_.rtt > rtt_sample) ? (stats_.rtt - rtt_sample) : (rtt_sample - stats_.rtt);
        stats_.rttvar = (stats_.rttvar * 3 + delta) / 4;
        stats_.rtt = (stats_.rtt * 7 + rtt_sample) / 8;
    }
    auto rto = stats_.rtt + std::max(std::chrono::milliseconds(10), 4 * stats_.rttvar);
    stats_.rto = std::clamp(rto, initial_rto_, max_rto_);
}

ReliabilityEngine::Stats ReliabilityEngine::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void ReliabilityEngine::send_heartbeat() {
    send_reliable(PacketType::Heartbeat, {});
}

void ReliabilityEngine::send_ack() {
    Packet packet;
    packet.header.type = static_cast<uint8_t>(PacketType::Ack);
    packet.header.ack_num = last_received_seq_;
    // Pure ACK usually doesn't need seq_num, or can use 0.
    
    auto raw = packet.serialize();
    if (send_fn_) send_fn_(raw);

    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_sent++;
    stats_.bytes_sent += raw.size();
}

} // namespace clink::core::network
