#pragma once

#include "src/server/core/security/auth.hpp"
#include "src/server/core/observability/telemetry.hpp"
#include <unordered_map>
#include <mutex>

// PSK 鉴权提供者：基于预共享密钥的简单认证
// 用户列表从配置文件 auth.psk_list 加载，Windows 上自动加密为 DPAPI
namespace clink::core::security {

class PskAuthProvider : public AuthService {
public:
    void clear_users() {                              // 清空用户表（热重载时先调用）
        std::lock_guard<std::mutex> lock(mutex_);
        users_.clear();
    }

    void add_user(const std::string& id, const std::string& psk) {  // 添加用户
        std::lock_guard<std::mutex> lock(mutex_);
        users_[id] = psk;
    }

    bool authenticate(const std::string& id, const std::string& proof) override {  // 验证身份
        auto tracer = observability::Telemetry::get_tracer("clink-auth");
        observability::ScopedSpan span(tracer->start_span("authenticate"));
        span->set_attribute("user_id", id);
        span->set_attribute("auth_type", "psk");

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = users_.find(id);
        if (it != users_.end()) {
            bool success = (it->second == proof);
            span->set_attribute("success", success ? "true" : "false");
            return success;
        }
        span->set_attribute("success", "false");
        span->set_attribute("error", "user_not_found");
        return false;
    }

private:
    std::unordered_map<std::string, std::string> users_;
    std::mutex mutex_;
};

} // namespace clink::core::security
