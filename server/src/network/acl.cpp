#include "server/include/clink/core/network/acl.hpp"
#include <sstream>

namespace clink::core::network {

AccessControlList::AccessControlList(std::shared_ptr<logging::Logger> logger)
    : logger_(std::move(logger)) {
}

bool AccessControlList::is_allowed(const std::string& client_id) const {
    std::shared_lock lock(mutex_);
    
    // 如果列表为空，默认允许所有 (实际生产中应改为默认拒绝)
    if (allowed_clients_.empty()) {
        return true;
    }

    bool allowed = allowed_clients_.find(client_id) != allowed_clients_.end();
    if (!allowed && logger_) {
        logger_->warn("[acl] access denied for client: " + client_id);
    }
    return allowed;
}

void AccessControlList::allow_client(const std::string& client_id) {
    std::unique_lock lock(mutex_);
    allowed_clients_.insert(client_id);
}

void AccessControlList::deny_client(const std::string& client_id) {
    std::unique_lock lock(mutex_);
    allowed_clients_.erase(client_id);
}

void AccessControlList::load_from_string(const std::string& acl_str) {
    std::unique_lock lock(mutex_);
    allowed_clients_.clear();
    
    std::stringstream ss(acl_str);
    std::string item;
    while (std::getline(ss, item, ',')) {
        // 去除空格
        size_t first = item.find_first_not_of(' ');
        if (std::string::npos == first) continue;
        size_t last = item.find_last_not_of(' ');
        std::string client_id = item.substr(first, (last - first + 1));
        
        if (!client_id.empty()) {
            allowed_clients_.insert(client_id);
        }
    }
    
    if (logger_) {
        logger_->info("[acl] loaded " + std::to_string(allowed_clients_.size()) + " clients into whitelist");
    }
}

} // namespace clink::core::network
