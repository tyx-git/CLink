#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace clink::core::security {

enum class CredentialType {
    Psk,
    Ltoken,
    Certificate
};

struct Credential {
    std::string id;
    CredentialType type;
    std::string secret; // This will be stored encrypted in memory or store
    std::string metadata;
};

class CredentialStore {
public:
    virtual ~CredentialStore() = default;
    virtual bool store_credential(const Credential& cred) = 0;
    virtual std::optional<Credential> get_credential(const std::string& id) = 0;
    virtual bool remove_credential(const std::string& id) = 0;
};

class AuthService {
public:
    virtual ~AuthService() = default;
    virtual bool authenticate(const std::string& id, const std::string& proof) = 0;
};

} // namespace clink::core::security
