#pragma once

#include "src/server/core/security/auth.hpp"
#include <unordered_map>

#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#endif

// Windows 凭据存储：用 DPAPI 加密后存储在内存 map 中
// 提供 store/get/remove 凭据接口
namespace clink::core::security {

class WindowsCredentialStore : public CredentialStore {
public:
    bool store_credential(const Credential& cred) override {
#ifdef _WIN32
        DATA_BLOB input;
        DATA_BLOB output;

        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(cred.secret.data()));
        input.cbData = static_cast<DWORD>(cred.secret.size());

        if (CryptProtectData(&input, L"CLink Credential", nullptr, nullptr, nullptr, 0, &output)) {
            stored_data_[cred.id] = {cred.id, cred.type,
                std::string(reinterpret_cast<char*>(output.pbData), output.cbData),
                cred.metadata};
            LocalFree(output.pbData);
            return true;
        }
        return false;
#else
        // Linux/macOS fallback: plaintext in-memory store (for compatibility/testing)
        stored_data_[cred.id] = cred;
        return true;
#endif
    }

    std::optional<Credential> get_credential(const std::string& id) override {
        auto it = stored_data_.find(id);
        if (it == stored_data_.end()) return std::nullopt;

#ifdef _WIN32
        const auto& encrypted = it->second;
        DATA_BLOB input;
        DATA_BLOB output;

        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(encrypted.secret.data()));
        input.cbData = static_cast<DWORD>(encrypted.secret.size());

        if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
            Credential decrypted = encrypted;
            decrypted.secret = std::string(reinterpret_cast<char*>(output.pbData), output.cbData);
            LocalFree(output.pbData);
            return decrypted;
        }
        return std::nullopt;
#else
        return it->second;
#endif
    }

    bool remove_credential(const std::string& id) override {
        return stored_data_.erase(id) > 0;
    }

private:
    std::unordered_map<std::string, Credential> stored_data_;
};

} // namespace clink::core::security
