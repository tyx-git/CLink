#include "clink/core/observability/telemetry.hpp"
#include <iostream>
#include <mutex>
#include <spdlog/spdlog.h>

namespace clink::core::observability {

/**
 * @brief 默认的空操作 Span 实现 (No-op)
 */
class NoopSpan : public Span {
public:
    void set_attribute(const std::string& /*key*/, std::string_view /*value*/) override {}
    void set_attribute(const std::string& /*key*/, int64_t /*value*/) override {}
    void add_event(const std::string& /*name*/) override {}
    void end() override {}
};

class NoOpTracer : public Tracer {
public:
    SpanPtr start_span(const std::string& /*name*/) override {
        return std::make_shared<NoopSpan>();
    }
};

class LogSpan : public Span {
    std::string name_;
public:
    explicit LogSpan(std::string name) : name_(std::move(name)) {
        spdlog::info("[telemetry] Start span: {}", name_);
    }
    void set_attribute(const std::string& key, std::string_view value) override {
        spdlog::info("[telemetry] Span {} attr: {}={}", name_, key, value);
    }
    void set_attribute(const std::string& key, int64_t value) override {
        spdlog::info("[telemetry] Span {} attr: {}={}", name_, key, value);
    }
    void add_event(const std::string& name) override {
        spdlog::info("[telemetry] Span {} event: {}", name_, name);
    }
    void end() override {
        spdlog::info("[telemetry] End span: {}", name_);
    }
};

class LogTracer : public Tracer {
public:
    SpanPtr start_span(const std::string& name) override {
        return std::make_shared<LogSpan>(name);
    }
};

static TracerPtr g_tracer = nullptr;
static std::mutex g_mutex;

TracerPtr Telemetry::get_tracer(const std::string& /*name*/) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_tracer) {
        g_tracer = std::make_shared<LogTracer>();
    }
    return g_tracer;
}

void Telemetry::initialize() {
    // 这里可以初始化真实的 OpenTelemetry SDK
}

} // namespace clink::core::observability
