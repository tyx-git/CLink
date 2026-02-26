#pragma once

#include "server/include/clink/core/module.hpp"
#include "server/include/clink/core/logging/logger.hpp"
#include <chrono>
#include <memory>
#include <atomic>

namespace clink::modules {

class HeartbeatModule : public core::Module {
public:
    explicit HeartbeatModule(std::shared_ptr<core::logging::Logger> logger);

    std::string_view name() const noexcept override { return "heartbeat"; }
    void configure(const core::config::Configuration& configuration) override;
    void start() override;
    void stop() override;

private:
    std::shared_ptr<core::logging::Logger> logger_;
    std::chrono::milliseconds heartbeat_interval_{1000};
    std::atomic<bool> active_{false};
};

}  // namespace clink::modules
