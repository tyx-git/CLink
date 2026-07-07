#pragma once

#include <string>
#include <stdexcept>
#include "src/share/core/security/base64.hpp"

#ifdef _WIN32
#include <windows.h>
#include <dpapi.h>
#endif

namespace clink::core::security {

// DPAPI 加密辅助：Windows 上用 CryptProtectData/CryptUnprotectData 加密凭据
// Linux 上为 no-op 占位（当前返回明文，待接入系统密钥链或 libsodium）
class DpapiHelper {
public:
    static std::string encrypt(const std::string& plain_text) {  // 加密
#ifdef _WIN32
        DATA_BLOB input;
        DATA_BLOB output;

        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(plain_text.data()));
        input.cbData = static_cast<DWORD>(plain_text.size());

        if (CryptProtectData(&input, L"CLink Security", nullptr, nullptr, nullptr, 0, &output)) {
            std::string encrypted(reinterpret_cast<char*>(output.pbData), output.cbData);
            LocalFree(output.pbData);
            return encrypted;
        }
        throw std::runtime_error("DPAPI encryption failed");
#else
        // Linux/macOS compatibility fallback: no-op encryption for now.
        // TODO: replace with platform keyring or libsodium-based encryption.
        return plain_text;
#endif
    }

    static std::string decrypt(const std::string& encrypted_data) {
#ifdef _WIN32
        DATA_BLOB input;
        DATA_BLOB output;

        input.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(encrypted_data.data()));
        input.cbData = static_cast<DWORD>(encrypted_data.size());

        if (CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0, &output)) {
            std::string decrypted(reinterpret_cast<char*>(output.pbData), output.cbData);
            LocalFree(output.pbData);
            return decrypted;
        }
        throw std::runtime_error("DPAPI decryption failed");
#else
        return encrypted_data;
#endif
    }

    // Base64 helpers — delegate to shared implementation
    static std::string to_base64(const std::string& data) {
        return clink::core::security::to_base64(data);
    }

    static std::string from_base64(const std::string& base64) {
        return clink::core::security::from_base64(base64);
    }
};

} // namespace clink::core::security
