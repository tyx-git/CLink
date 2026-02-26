#pragma once

#include "server/include/clink/core/logging/logger.hpp"
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_set>

namespace clink::core::network {

/**
 * @brief 访问控制列表 (ACL) 管理器，负责验证客户端身份和权限
 */
class AccessControlList {
public:
    explicit AccessControlList(std::shared_ptr<logging::Logger> logger);

    /**
     * @brief 验证客户端 ID 是否在白名单中
     */
    bool is_allowed(const std::string& client_id) const;

    /**
     * @brief 添加允许的客户端 ID
     */
    void allow_client(const std::string& client_id);

    /**
     * @brief 移除客户端 ID
     */
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
