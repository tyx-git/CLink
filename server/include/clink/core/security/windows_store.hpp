#pragma once

#include "server/include/clink/core/security/auth.hpp"
#include <windows.h>
#include <dpapi.h>
#include <vector>

namespace clink::core::security {

class WindowsCredentialStore : public CredentialStore {
public:
    bool store_credential(const Credential& cred) override {
        DATA_BLOB input;
        DATA_BLOB output;
        
        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(cred.secret.data()));
        input.cbData = static_cast<DWORD>(cred.secret.size());

        if (CryptProtectData(&input, L"CLink Credential", nullptr, nullptr, nullptr, 0, &output)) {
            // In a real implementation, we would write this to a file or registry
            // For now, we simulate the storage
            stored_data_[cred.id] = {cred.id, cred.type, 
                std::string(reinterpret_cast<char*>(output.pbData), output.cbData), 
                cred.metadata};
            LocalFree(output.pbData);
            return true;
        }
        return false;
    }

    std::optional<Credential> get_credential(const std::string& id) override {
        auto it = stored_data_.find(id);
        if (it == stored_data_.end()) return std::nullopt;

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
    }

    bool remove_credential(const std::string& id) override {
        return stored_data_.erase(id) > 0;
    }

private:
    std::unordered_map<std::string, Credential> stored_data_;
};

} // namespace clink::core::security
