#include "clink/server/modules/heartbeat.hpp"

namespace clink::modules {

HeartbeatModule::HeartbeatModule(std::shared_ptr<core::logging::Logger> logger)
    : logger_(std::move(logger)) {}

void HeartbeatModule::configure(const core::config::Configuration& configuration) {
    auto value = configuration.get_int("transport.heartbeat_ms", static_cast<int>(heartbeat_interval_.count()));
    heartbeat_interval_ = std::chrono::milliseconds{value};
    if (logger_) {
        logger_->debug("[heartbeat] interval configured to", heartbeat_interval_.count(), "ms");
    }
}

void HeartbeatModule::start() {
    active_ = true;
    if (logger_) {
        logger_->info("[heartbeat] supervision ON interval", heartbeat_interval_.count(), "ms");
    }
}

void HeartbeatModule::stop() {
    if (!active_) {
        return;
    }
    active_ = false;
    if (logger_) {
        logger_->info("[heartbeat] supervision OFF");
    }
}

}  // namespace clink::modules
