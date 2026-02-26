#include "server/include/clink/server/modules/metrics.hpp"
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
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }
    if (logger_) {
        logger_->info("[metrics] exporter stopped");
    }
}

void MetricsModule::collect_loop() {
    while (active_) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
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
        }
    }
}

}  // namespace clink::modules
