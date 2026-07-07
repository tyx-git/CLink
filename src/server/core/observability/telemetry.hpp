#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <map>
#include <any>

// 可观测性子系统：模拟 OpenTelemetry 的 Span/Tracer 接口
// 在数据面关键路径（tun_to_network / network_to_tun）上打点采样
// 未来可替换为真实 OpenTelemetry SDK
namespace clink::core::observability {

// Span：追踪跨度，记录一个操作的开始和结束
// 可附带属性和事件（键值对），用于后续分析
class Span {
public:
    virtual ~Span() = default;
    virtual void set_attribute(const std::string& key, std::string_view value) = 0; // 设置字符串属性
    virtual void set_attribute(const std::string& key, int64_t value) = 0;          // 设置数值属性
    virtual void add_event(const std::string& name) = 0;                            // 记录事件
    virtual void end() = 0;                                                         // 结束 span
};

using SpanPtr = std::shared_ptr<Span>;

// Tracer：追踪器，用于创建 Span
class Tracer {
public:
    virtual ~Tracer() = default;
    virtual SpanPtr start_span(const std::string& name) = 0; // 创建一个名为 name 的新 span
};

using TracerPtr = std::shared_ptr<Tracer>;

// Telemetry 工厂：获取 Tracer 实例
class Telemetry {
public:
    static TracerPtr get_tracer(const std::string& name); // 获取指定名称的追踪器
    static void initialize();                             // 全局初始化
};

// ScopedSpan：RAII 封装的 Span，析构时自动 end()
class ScopedSpan {
public:
    explicit ScopedSpan(SpanPtr span) : span_(std::move(span)) {}
    ~ScopedSpan() { if (span_) span_->end(); }
    Span* operator->() { return span_.get(); }
    [[nodiscard]] SpanPtr get() const { return span_; }
private:
    SpanPtr span_;
};

} // namespace clink::core::observability
