#pragma once

#include "src/share/core/logging/logger.hpp"
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_set>

namespace clink::core::network {

// ACL 访问控制列表：基于客户端 ID 的白名单管理
class AccessControlList {
public:
    explicit AccessControlList(std::shared_ptr<logging::Logger> logger);

    bool is_allowed(const std::string& client_id) const; // 检查客户端是否在白名单中
    void allow_client(const std::string& client_id);      // 添加白名单条目
    void remove_client(const std::string& client_id);
    void deny_client(const std::string& client_id);

    /**
     * @brief 从配置字符串加载白名单 (如 "client1,client2,client3")
     */
    void load_from_string(const std::string& acl_str);

private:
    std::shared_ptr<logging::Logger> logger_;
    mutable std::shared_mutex mutex_;
    std::unordered_set<std::string> allowed_clients_;
};

} // namespace clink::core::network
