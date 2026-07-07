#pragma once

#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "src/server/core/module.hpp"

// ModuleRegistry：管理所有模块的注册表
// 提供 批量 configure/start/stop，由 Application 在对应阶段调用
namespace clink::core {

class ModuleRegistry {
public:
    ModuleRegistry() = default;

    void register_module(ModulePtr module);                                        // 注册单个模块

    template <typename ModuleType, typename... Args>
    ModuleType& emplace_module(Args&&... args) {                                   // 创建并注册
        auto module = std::make_shared<ModuleType>(std::forward<Args>(args)...);
        register_module(module);
        return *module;
    }

    void configure_all(const config::Configuration& configuration); // 批量调用所有模块的 configure()
    void start_all();                                               // 批量调用所有模块的 start()
    void stop_all();                                                // 批量调用所有模块的 stop()

    [[nodiscard]] bool empty() const;

private:
    std::vector<ModulePtr> modules_;
    const config::Configuration* configuration_{nullptr};
    bool configured_{false};   // 是否已执行 configure_all
    bool started_{false};      // 是否已执行 start_all（防重复）
    mutable std::mutex mutex_;
};

}  // namespace clink::core
