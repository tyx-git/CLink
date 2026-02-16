#pragma once

#include <windows.h>
#include <dpapi.h>
#include <string>
#include <vector>
#include <stdexcept>

namespace clink::core::security {

class DpapiHelper {
public:
    static std::string encrypt(const std::string& plain_text) {
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
    }

    static std::string decrypt(const std::string& encrypted_data) {
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
    }

    // Base64 helpers for storing encrypted binary data in TOML
    static std::string to_base64(const std::string& data) {
        static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string base64;
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        for (char c : data) {
            char_array_3[i++] = static_cast<unsigned char>(c);
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++) base64 += base64_chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; j++) char_array_3[j] = '\0';
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

            for (j = 0; j < i + 1; j++) base64 += base64_chars[char_array_4[j]];
            while (i++ < 3) base64 += '=';
        }

        return base64;
    }

    static std::string from_base64(const std::string& base64) {
        static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string decoded;
        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) {
            T[static_cast<unsigned char>(base64_chars[static_cast<size_t>(i)])] = i;
        }

        int val = 0, valb = -8;
        for (char c : base64) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (T[uc] == -1) break;
            val = (val << 6) + T[uc];
            valb += 6;
            if (valb >= 0) {
                decoded.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return decoded;
    }
};

} // namespace clink::core::security
