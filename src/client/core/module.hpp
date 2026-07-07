#pragma once

#include <memory>
#include <string_view>

#include "src/share/core/config/configuration.hpp"

// 客户端 Module 基类：与服务端接口一致，独立编译单元
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
