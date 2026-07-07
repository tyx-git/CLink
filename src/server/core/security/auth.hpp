#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>

// 安全子系统：凭据存储 + 认证服务接口
// 凭据通过 DPAPI 加密存储在 Windows Credential Store 中
namespace clink::core::security {

enum class CredentialType {
    Psk,          // 预共享密钥
    Ltoken,       // 长期 Token
    Certificate   // 证书
};

struct Credential {
    std::string id;        // 凭据标识（用户名）
    CredentialType type;    // 凭据类型
    std::string secret;    // 凭据密文（内存中加密存储）
    std::string metadata;  // 元数据
};

// 凭据存储抽象：Windows 上用 DPAPI 加密存入 Credential Store
class CredentialStore {
public:
    virtual ~CredentialStore() = default;
    virtual bool store_credential(const Credential& cred) = 0;
    virtual std::optional<Credential> get_credential(const std::string& id) = 0;
    virtual bool remove_credential(const std::string& id) = 0;
};

// 认证服务接口：PSK 鉴权
class AuthService {
public:
    virtual ~AuthService() = default;
    virtual bool authenticate(const std::string& id, const std::string& proof) = 0;
};

} // namespace clink::core::security
