#pragma once

#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "clink/core/module.hpp"

namespace clink::core {

class ModuleRegistry {
public:
    ModuleRegistry() = default;

    void register_module(ModulePtr module);

    template <typename ModuleType, typename... Args>
    ModuleType& emplace_module(Args&&... args) {
        auto module = std::make_shared<ModuleType>(std::forward<Args>(args)...);
        register_module(module);
        return *module;
    }

    void configure_all(const config::Configuration& configuration);
    void start_all();
    void stop_all();

    [[nodiscard]] bool empty() const;

private:
    std::vector<ModulePtr> modules_;
    const config::Configuration* configuration_{nullptr};
    bool configured_{false};
    bool started_{false};
    mutable std::mutex mutex_;
};

}  // namespace clink::core
