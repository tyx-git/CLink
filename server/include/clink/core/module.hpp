#pragma once

#include <memory>
#include <string_view>

#include "server/include/clink/core/config/configuration.hpp"

namespace clink::core {

class Module {
public:
    virtual ~Module() = default;

    virtual std::string_view name() const noexcept = 0;
    virtual void configure(const config::Configuration& configuration) = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
};

using ModulePtr = std::shared_ptr<Module>;

}  // namespace clink::core
