#pragma once

#include "src/server/core/module.hpp"
#include "src/share/core/logging/logger.hpp"
#include <chrono>
#include <memory>
#include <atomic>

// HeartbeatModule：定时发送心跳包维持隧道活性
// 通过 SessionManager::broadcast() 广播心跳到所有活跃会话
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
    std::chrono::milliseconds heartbeat_interval_{1000};  // 默认 1s 间隔
    std::atomic<bool> active_{false};
};

}  // namespace clink::modules
