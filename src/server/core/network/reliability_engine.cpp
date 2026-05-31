#include "src/server/core/network/reliability_engine.hpp"
#include "src/share/core/network/packet.hpp"
#include <algorithm>
#include <cstdlib>
#include <sstream>
#include <thread>

namespace {
std::string tid_str() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}

std::size_t in_flight_packet_count_locked(
    const std::map<uint32_t, clink::core::network::RetransmissionEntry>& packets) {
    return static_cast<std::size_t>(std::count_if(packets.begin(), packets.end(), [](const auto& item) {
        return item.second.sent;
    }));
}
}

namespace clink::core::network {

ReliabilityEngine::ReliabilityEngine(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, SendFunction send_fn)
    : io_context_(io_context), logger_(std::move(logger)), send_fn_(std::move(send_fn)),
      rate_limiter_(nullptr), timer_(nullptr) {
    if (logger_) logger_->info("[reliability.stage] ctor.enter tid=" + tid_str());
    try {
        if (logger_) logger_->info("[reliability.stage] ctor.rate_limiter.create.begin tid=" + tid_str());
        rate_limiter_ = std::make_unique<RateLimiter>(0, 0);
        if (logger_) logger_->info("[reliability.stage] ctor.rate_limiter.create.ok tid=" + tid_str());

        if (logger_) logger_->info("[reliability.stage] ctor.timer.defer tid=" + tid_str());
        if (logger_) logger_->info("[reliability.stage] ctor.exit.ok tid=" + tid_str());
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("[reliability.stage] ctor.exception: ") + ex.what());
        throw;
    } catch (...) {
        if (logger_) logger_->error("[reliability.stage] ctor.exception: unknown");
        throw;
    }
}

ReliabilityEngine::~ReliabilityEngine() {
    stop();
}

void ReliabilityEngine::report_corrupted_packet() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.corrupted_packets++;
}

void ReliabilityEngine::ensure_timer() {
    if (shutting_down_.load()) {
        if (logger_) logger_->warn("[reliability] ensure_timer called during shutdown, ignoring");
        return;
    }

    if (logger_) logger_->info("[reliability] timer.ensure.enter tid=" + tid_str());
    std::call_once(timer_once_, [this]() {
        if (shutting_down_.load()) {
            if (logger_) logger_->warn("[reliability] timer.ensure.once skipped due to shutdown");
            return;
        }
        if (logger_) logger_->info("[reliability] timer.ensure.once.begin tid=" + tid_str());
        timer_ = std::make_unique<asio::steady_timer>(io_context_);
        if (logger_) logger_->info("[reliability] timer.ensure.once.ok tid=" + tid_str());
    });
    if (logger_) logger_->info("[reliability] timer.ensure.exit tid=" + tid_str());
}

void ReliabilityEngine::start() {
    std::atomic<bool> done{false};
    std::error_code start_ec;

    start_async([&](std::error_code ec) {
        start_ec = ec;
        done.store(true, std::memory_order_release);
    });

    while (!done.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    (void)start_ec;
}

void ReliabilityEngine::start_async(std::function<void(std::error_code)> on_started) {
    if (logger_) logger_->info("[reliability] start_async.post tid=" + tid_str());

    auto self = shared_from_this();
    asio::post(io_context_, [self, cb = std::move(on_started)]() mutable {
        if (self->shutting_down_.load()) {
            if (self->logger_) self->logger_->warn("[reliability] start_async ignored during shutdown");
            if (cb) cb(std::make_error_code(std::errc::operation_canceled));
            return;
        }

        if (self->logger_) self->logger_->info("[reliability] start.begin tid=" + tid_str());

        if (self->running_) {
            if (self->logger_) self->logger_->info("[reliability.stage] start.skip_already_running tid=" + tid_str());
            if (cb) cb({});
            return;
        }

        try {
            self->running_ = true;

            bool enable_timer = self->timer_enabled_.load(std::memory_order_relaxed);
            if (const char* env = std::getenv("CLINK_ENABLE_RELIABILITY_TIMER")) {
                if (std::string(env) == "1") {
                    enable_timer = true;
                } else if (std::string(env) == "0") {
                    enable_timer = false;
                }
            }

            if (enable_timer) {
                self->ensure_timer();
                if (self->logger_) self->logger_->info("[reliability.stage] start.timer.begin tid=" + tid_str());
                self->start_timer();
            } else if (self->logger_) {
                self->logger_->warn("[reliability.stage] timer.disabled_for_stability");
            }

            if (self->logger_) self->logger_->info("[reliability] start.ok tid=" + tid_str());
            if (cb) cb({});
        } catch (const std::exception& ex) {
            if (self->logger_) self->logger_->error(std::string("[reliability] start.exception: ") + ex.what());
            if (cb) cb(std::make_error_code(std::errc::operation_canceled));
        } catch (...) {
            if (self->logger_) self->logger_->error("[reliability] start.exception tid=" + tid_str());
            if (cb) cb(std::make_error_code(std::errc::operation_canceled));
        }
    });
}

void ReliabilityEngine::stop() {
    if (shutting_down_.exchange(true)) {
        return;
    }

    running_ = false;
    if (timer_) {
        try {
            timer_->cancel();
        } catch (const std::exception& ex) {
            if (logger_) {
                logger_->warn(std::string("[reliability] timer cancel exception during stop: ") + ex.what());
            }
        }
    }
}

void ReliabilityEngine::start_timer() {
    if (shutting_down_.load()) {
        if (logger_) logger_->warn("[reliability.stage] timer.skip_shutting_down tid=" + tid_str());
        return;
    }

    ensure_timer();
    if (!running_) {
        if (logger_) logger_->info("[reliability.stage] timer.skip_not_running tid=" + tid_str());
        return;
    }

    if (!timer_) {
        if (logger_) logger_->error("[reliability.stage] timer.missing tid=" + tid_str());
        return;
    }

    if (logger_) logger_->info("[reliability.stage] timer.schedule tid=" + tid_str());
    timer_->expires_after(std::chrono::milliseconds(50));
    auto self = shared_from_this();
    timer_->async_wait([self](std::error_code ec) {
        if (ec) {
            if (self->logger_) self->logger_->info(std::string("[reliability.stage] timer.wait.cancelled ec=") + ec.message());
            return;
        }

        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(self->queue_mutex_);
        if (self->logger_) self->logger_->info("[reliability.stage] timer.tick unacked=" + std::to_string(self->unacked_packets_.size()));

        for (auto& [seq, entry] : self->unacked_packets_) {
            // 1. 处理尚未进行初始发送的包 (受限于 CWND 和速率)
            if (!entry.sent) {
                bool can_send = false;
                {
                    std::lock_guard<std::mutex> stats_lock(self->stats_mutex_);
                    if (in_flight_packet_count_locked(self->unacked_packets_) < self->stats_.cwnd) {
                        can_send = true;
                    }
                }
                
                if (can_send) {
                    size_t packet_size = sizeof(PacketHeader) + entry.packet->header.payload_size;
                    if (self->rate_limiter_ && self->rate_limiter_->consume(packet_size)) {
                        entry.sent = true;
                        entry.last_send_time = now;
                        if (self->send_fn_) self->send_fn_(*entry.packet);
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

                size_t packet_size = sizeof(PacketHeader) + entry.packet->header.payload_size;
                if (self->rate_limiter_ && !self->rate_limiter_->consume(packet_size)) continue;

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
                if (self->send_fn_) self->send_fn_(*entry.packet);
            }
        }

        self->start_timer();
    });
}

void ReliabilityEngine::set_rate_limit(size_t bytes_per_second, size_t burst_size) {
    if (shutting_down_.load()) {
        if (logger_) logger_->warn("[reliability] set_rate_limit ignored during shutdown");
        return;
    }
    if (rate_limiter_) {
        rate_limiter_->update_limits(bytes_per_second, burst_size);
    }
}

void ReliabilityEngine::send_reliable(PacketType type, std::shared_ptr<clink::core::memory::Block> payload) {
    auto packet = std::make_unique<Packet>(payload);
    packet->header.type = static_cast<uint8_t>(type);
    packet->header.flags = 0;
    // payload_size is set by Packet constructor
    packet->header.seq_num = next_seq_num_++;
    packet->header.ack_num = last_received_seq_.load();
    
    // Finalize packet (calculate checksum) before storing/sending
    packet->finalize();

    size_t packet_size = sizeof(PacketHeader) + packet->header.payload_size;
    
    uint32_t seq = 0;
    bool can_send_now = false;
    Packet packet_copy;

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        RetransmissionEntry entry;
        entry.last_send_time = std::chrono::steady_clock::now();
        entry.current_timeout = initial_rto_;
        entry.retry_count = 0;
        entry.sent = false;
        
        seq = packet->header.seq_num;
        
        {
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            if (in_flight_packet_count_locked(unacked_packets_) < stats_.cwnd) {
                can_send_now = true;
                entry.sent = true;
            }
        }
        
        if (can_send_now) {
            packet_copy = *packet;
        }
        entry.packet = std::move(packet);
        
        unacked_packets_[seq] = std::move(entry);
    }

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_sent++;
        stats_.bytes_sent += packet_size;
    }

    if (can_send_now && send_fn_) {
        if (rate_limiter_ && rate_limiter_->consume(packet_size)) {
            send_fn_(packet_copy);
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
                if (send_fn_) send_fn_(*it->second.packet);
                
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
                    if (send_fn_) send_fn_(*entry.packet);
                    
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

    // Update latency distribution buckets
    if (rtt_sample < std::chrono::milliseconds(10)) stats_.latency_bucket_10ms++;
    else if (rtt_sample < std::chrono::milliseconds(50)) stats_.latency_bucket_50ms++;
    else if (rtt_sample < std::chrono::milliseconds(100)) stats_.latency_bucket_100ms++;
    else if (rtt_sample < std::chrono::milliseconds(200)) stats_.latency_bucket_200ms++;
    else if (rtt_sample < std::chrono::milliseconds(500)) stats_.latency_bucket_500ms++;
    else if (rtt_sample < std::chrono::seconds(1)) stats_.latency_bucket_1s++;
    else stats_.latency_bucket_inf++;

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

void ReliabilityEngine::send_ack(uint32_t ack_num) {
    Packet packet;
    packet.header.type = static_cast<uint8_t>(PacketType::Ack);
    packet.header.ack_num = (ack_num != 0) ? ack_num : last_received_seq_.load();
    // Pure ACK usually doesn't need seq_num, or can use 0.
    packet.finalize();

    if (send_fn_) send_fn_(packet);

    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.total_sent++;
    stats_.bytes_sent += sizeof(PacketHeader);
}

} // namespace clink::core::network
