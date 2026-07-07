#pragma once

#include <memory>
#include <string_view>

#include "src/share/core/config/configuration.hpp"

namespace clink::core {

// 模块抽象基类：三段式生命周期 — configure → start → stop
// 所有内置模块（Heartbeat/Metrics/SocksServer/ProcessManager）继承此类
class Module {
public:
    virtual ~Module() = default;

    virtual std::string_view name() const noexcept = 0;           // 模块名称（日志标识用）
    virtual void configure(const config::Configuration& configuration) = 0; // 配置阶段：读取配置参数
    virtual void start() = 0;                                      // 启动阶段：创建资源、开始工作
    virtual void stop() = 0;                                       // 停止阶段：释放资源
};

using ModulePtr = std::shared_ptr<Module>;

}  // namespace clink::core
