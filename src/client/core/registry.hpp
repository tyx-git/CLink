#pragma once

#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "src/client/core/module.hpp"

// 客户端 ModuleRegistry：与服务端接口一致，独立编译单元
namespace clink::core {

class ModuleRegistry {
public:
    ModuleRegistry() = default;

    void register_module(ModulePtr module);                                       // 注册模块
    template <typename ModuleType, typename... Args>
    ModuleType& emplace_module(Args&&... args) {                                  // 创建并注册
        auto module = std::make_shared<ModuleType>(std::forward<Args>(args)...);
        register_module(module);
        return *module;
    }
    void configure_all(const config::Configuration& configuration);  // 批量 configure
    void start_all();                                                  // 批量 start
    void stop_all();                                                   // 批量 stop
    [[nodiscard]] bool empty() const;
private:
    std::vector<ModulePtr> modules_;
    const config::Configuration* configuration_{nullptr};
    bool configured_{false};
    bool started_{false};
    mutable std::mutex mutex_;
};

}  // namespace clink::core
