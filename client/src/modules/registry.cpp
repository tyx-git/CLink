#include "client/include/clink/core/registry.hpp"
#include "client/include/clink/core/logging/logger.hpp"

#include <stdexcept>

namespace clink::core {

void ModuleRegistry::register_module(ModulePtr module) {
    if (!module) {
        throw std::invalid_argument("module is null");
    }

    std::lock_guard lock{mutex_};
    if (started_) {
        throw std::runtime_error("Cannot register modules after start");
    }

    modules_.push_back(std::move(module));

    if (configured_ && configuration_) {
        modules_.back()->configure(*configuration_);
    }
}

void ModuleRegistry::configure_all(const config::Configuration& configuration) {
    std::lock_guard lock{mutex_};
    configuration_ = &configuration;
    for (auto& module : modules_) {
        try {
            module->configure(configuration);
        } catch (const std::exception& e) {
            // Log error but continue
        }
    }
    configured_ = true;
}

void ModuleRegistry::start_all() {
    std::lock_guard lock{mutex_};
    if (started_) {
        return;
    }
    for (auto& module : modules_) {
        try {
            module->start();
        } catch (const std::exception& e) {
            // Log error but continue
        }
    }
    started_ = true;
}

void ModuleRegistry::stop_all() {
    std::lock_guard lock{mutex_};
    if (!started_) {
        return;
    }
    for (auto it = modules_.rbegin(); it != modules_.rend(); ++it) {
        try {
            (*it)->stop();
        } catch (const std::exception& e) {
            // Log error but continue
        }
    }
    started_ = false;
}

bool ModuleRegistry::empty() const {
    std::lock_guard lock{mutex_};
    return modules_.empty();
}

}  // namespace clink::core
