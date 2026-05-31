#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <map>
#include <any>

namespace clink::core::observability {

/**
 * @brief 追踪跨度接口 (Span Interface)
 * 模拟 OpenTelemetry Span 的基本操作，便于未来替换为真实 SDK
 */
class Span {
public:
    virtual ~Span() = default;
    virtual void set_attribute(const std::string& key, std::string_view value) = 0;
    virtual void set_attribute(const std::string& key, int64_t value) = 0;
    virtual void add_event(const std::string& name) = 0;
    virtual void end() = 0;
};

using SpanPtr = std::shared_ptr<Span>;

/**
 * @brief 追踪器接口 (Tracer Interface)
 */
class Tracer {
public:
    virtual ~Tracer() = default;
    virtual SpanPtr start_span(const std::string& name) = 0;
};

using TracerPtr = std::shared_ptr<Tracer>;

/**
 * @brief 遥测工厂类，用于获取 Tracer
 */
class Telemetry {
public:
    static TracerPtr get_tracer(const std::string& name);
    static void initialize();
};

/**
 * @brief 作用域内的 Span 管理器 (RAII)
 */
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
