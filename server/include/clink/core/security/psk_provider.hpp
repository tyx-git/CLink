#pragma once

#include "server/include/clink/core/security/auth.hpp"
#include "server/include/clink/core/observability/telemetry.hpp"
#include <unordered_map>
#include <mutex>

namespace clink::core::security {

class PskAuthProvider : public AuthService {
public:
    void add_user(const std::string& id, const std::string& psk) {
        std::lock_guard<std::mutex> lock(mutex_);
        users_[id] = psk;
    }

    bool authenticate(const std::string& id, const std::string& proof) override {
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
