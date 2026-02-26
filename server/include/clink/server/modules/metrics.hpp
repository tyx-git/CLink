#pragma once

#include "server/include/clink/core/module.hpp"
#include "server/include/clink/core/logging/logger.hpp"
#include "server/include/clink/core/network/session_manager.hpp"
#include <memory>
#include <string>
#include <atomic>
#include <thread>

namespace clink::modules {

class MetricsModule : public core::Module {
public:
    explicit MetricsModule(std::shared_ptr<core::logging::Logger> logger, 
                          std::shared_ptr<core::network::SessionManager> session_manager);

    std::string_view name() const noexcept override { return "metrics"; }
    void configure(const core::config::Configuration& configuration) override;
    void start() override;
    void stop() override;

private:
    void collect_loop();

    std::shared_ptr<core::logging::Logger> logger_;
    std::shared_ptr<core::network::SessionManager> session_manager_;
    std::string endpoint_{"localhost:9100"};
    std::atomic<bool> active_{false};
    std::thread worker_thread_;
};

}  // namespace clink::modules
