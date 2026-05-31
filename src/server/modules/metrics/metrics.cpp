#include "src/server/modules/metrics/metrics.hpp"
#include "src/share/core/network/packet.hpp"
#include <iostream>

namespace clink::modules {

MetricsModule::MetricsModule(std::shared_ptr<core::logging::Logger> logger,
                           std::shared_ptr<core::network::SessionManager> session_manager)
    : logger_(std::move(logger)), session_manager_(std::move(session_manager)) {}

void MetricsModule::configure(const core::config::Configuration& configuration) {
    endpoint_ = configuration.get_string("observability.metrics_endpoint", endpoint_);
    if (logger_) {
        logger_->debug("[metrics] endpoint set to " + endpoint_);
    }
}

void MetricsModule::start() {
    if (active_) {
        return;
    }
    active_ = true;
    worker_thread_ = std::thread(&MetricsModule::collect_loop, this);
    if (logger_) {
        logger_->info("[metrics] exporter active at " + endpoint_);
    }
}

void MetricsModule::stop() {
    if (!active_) {
        return;
    }
    active_ = false;
    stop_cv_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    if (logger_) {
        logger_->info("[metrics] exporter stopped");
    }
}

void MetricsModule::collect_loop() {
    while (active_) {
        {
            std::unique_lock<std::mutex> lock(stop_mutex_);
            stop_cv_.wait_for(lock, std::chrono::seconds(5), [this]() { return !active_.load(); });
        }
        if (!active_) {
            break;
        }

        if (!session_manager_) continue;

        auto sessions = session_manager_->get_active_sessions();
        
        // 模拟 Prometheus 格式输出到日志 (实际应启动 HTTP 服务)
        if (logger_) {
            logger_->info("[metrics] snapshot: " + std::to_string(sessions.size()) + " active sessions");
            for (const auto& sess : sessions) {
                logger_->debug("[metrics] sess=" + sess.session_id + 
                               " rtt=" + std::to_string(sess.rtt.count()) + "ms" +
                               " loss=" + std::to_string(sess.packet_loss_rate * 100.0f) + "%" +
                               " sent=" + std::to_string(sess.bytes_sent) + 
                               " recv=" + std::to_string(sess.bytes_received));
            }

            const auto& zc = core::network::packet_copy_stats();
            const uint64_t raw_packets = zc.packets_deserialize_raw.load(std::memory_order_relaxed);
            const uint64_t block_packets = zc.packets_deserialize_block.load(std::memory_order_relaxed);
            const uint64_t raw_bytes = zc.bytes_copied_raw.load(std::memory_order_relaxed);
            const uint64_t block_bytes = zc.bytes_copied_block.load(std::memory_order_relaxed);
            const uint64_t total_packets = raw_packets + block_packets;
            const uint64_t total_copied_bytes = raw_bytes + block_bytes;
            const uint64_t corrupted_packets = zc.packets_corrupted.load(std::memory_order_relaxed);
            const uint64_t incomplete_packets = zc.packets_incomplete.load(std::memory_order_relaxed);
            const uint64_t block_ratio_pct = (total_packets == 0) ? 0 : (block_packets * 100 / total_packets);

            logger_->info("[metrics.zero_copy] packets_total=" + std::to_string(total_packets) +
                          " raw=" + std::to_string(raw_packets) +
                          " block=" + std::to_string(block_packets) +
                          " block_ratio_pct=" + std::to_string(block_ratio_pct) +
                          " copied_bytes_total=" + std::to_string(total_copied_bytes) +
                          " copied_bytes_raw=" + std::to_string(raw_bytes) +
                          " copied_bytes_block=" + std::to_string(block_bytes) +
                          " corrupted=" + std::to_string(corrupted_packets) +
                          " incomplete=" + std::to_string(incomplete_packets));
        }
    }
}

}  // namespace clink::modules
