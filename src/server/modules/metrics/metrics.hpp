#pragma once

#include "src/server/core/module.hpp"
#include "src/share/core/logging/logger.hpp"
#include "src/server/core/network/session_manager.hpp"
#include <memory>
#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <condition_variable>

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
    std::mutex stop_mutex_;
    std::condition_variable stop_cv_;
};

}  // namespace clink::modules
