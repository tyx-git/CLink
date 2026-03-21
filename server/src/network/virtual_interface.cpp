#include "server/include/clink/core/network/virtual_interface.hpp"
#include <cstdlib>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <winreg.h>
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#endif
#include "external/wintun/include/wintun.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#include <asio/windows/stream_handle.hpp>
#include <asio/windows/object_handle.hpp>
#include <optional>
#include <string_view>
#include <algorithm>
#include <mutex>
#include <vector>
#include <iostream>

// TAP-Windows IOCTLs
#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE(3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE(4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE(5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE(6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE(7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE(8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE(9, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_TUN            TAP_CONTROL_CODE(10, METHOD_BUFFERED)

namespace {

constexpr DWORD kDefaultRingCapacity = 4 * 1024 * 1024;  // 4MB ring buffer

std::weak_ptr<clink::core::logging::Logger> g_vif_logger;

std::shared_ptr<clink::core::logging::Logger> vif_logger() {
    return g_vif_logger.lock();
}

class WintunApi {
public:
    using OpenAdapterFn = WINTUN_OPEN_ADAPTER_FUNC*;
    using CreateAdapterFn = WINTUN_CREATE_ADAPTER_FUNC*;
    using CloseAdapterFn = WINTUN_CLOSE_ADAPTER_FUNC*;
    using StartSessionFn = WINTUN_START_SESSION_FUNC*;
    using EndSessionFn = WINTUN_END_SESSION_FUNC*;
    using ReceivePacketFn = WINTUN_RECEIVE_PACKET_FUNC*;
    using ReleaseReceivePacketFn = WINTUN_RELEASE_RECEIVE_PACKET_FUNC*;
    using AllocateSendPacketFn = WINTUN_ALLOCATE_SEND_PACKET_FUNC*;
    using SendPacketFn = WINTUN_SEND_PACKET_FUNC*;
    using GetReadWaitEventFn = WINTUN_GET_READ_WAIT_EVENT_FUNC*;

    static WintunApi& instance() {
        static WintunApi api;
        return api;
    }

    bool load() {
        if (module_) {
            return true;
        }

        const wchar_t* arch_dir = L"x86";
        const char* arch_tag = "x86";
#if defined(_M_X64) || defined(__x86_64__)
        arch_dir = L"amd64";
        arch_tag = "amd64";
#elif defined(_M_ARM64) || defined(__aarch64__)
        arch_dir = L"arm64";
        arch_tag = "arm64";
#endif

        auto dirname = [](const std::wstring& path) -> std::wstring {
            const size_t pos = path.find_last_of(L"\\/");
            if (pos == std::wstring::npos) {
                return {};
            }
            return path.substr(0, pos);
        };

        auto join = [](const std::wstring& a, const std::wstring& b) -> std::wstring {
            if (a.empty()) return b;
            if (a.back() == L'\\' || a.back() == L'/') return a + b;
            return a + L"\\" + b;
        };

        std::vector<std::wstring> candidates;
        auto push_unique = [&candidates](const std::wstring& path) {
            if (path.empty()) return;
            if (std::find(candidates.begin(), candidates.end(), path) == candidates.end()) {
                candidates.push_back(path);
            }
        };

        // 1) 优先同目录（可执行文件旁）
        wchar_t exe_path[MAX_PATH] = {};
        if (GetModuleFileNameW(nullptr, exe_path, MAX_PATH) > 0) {
            const std::wstring exe_dir = dirname(exe_path);
            if (!exe_dir.empty()) {
                push_unique(join(exe_dir, L"wintun.dll"));
            }
        }

        // 2) 明确从当前工作目录和其父目录递归寻找 external/wintun/bin/<arch>/wintun.dll
        wchar_t cwd_buf[MAX_PATH] = {};
        if (GetCurrentDirectoryW(MAX_PATH, cwd_buf) > 0) {
            std::wstring cur = cwd_buf;
            for (int depth = 0; depth < 8 && !cur.empty(); ++depth) {
                const std::wstring ext_root = join(cur, L"external\\wintun");
                push_unique(join(join(join(ext_root, L"bin"), arch_dir), L"wintun.dll"));
                push_unique(join(join(ext_root, arch_dir), L"wintun.dll"));
                push_unique(join(join(ext_root, L"bin"), L"wintun.dll"));
                push_unique(join(ext_root, L"wintun.dll"));
                cur = dirname(cur);
            }
        }

        // 3) 最后退回默认搜索与系统目录
        candidates.emplace_back(L"wintun.dll");
        wchar_t system_path[MAX_PATH] = {};
        if (GetSystemDirectoryW(system_path, MAX_PATH)) {
            std::wstring path(system_path);
            path += L"\\wintun.dll";
            candidates.push_back(std::move(path));
        }

        auto wide_to_utf8 = [](const std::wstring& ws) -> std::string {
            if (ws.empty()) return {};
            int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (len <= 0) return {};
            std::string out(static_cast<size_t>(len - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, out.data(), len, nullptr, nullptr);
            return out;
        };

        std::wstring loaded_path;
        for (const auto& dll_path : candidates) {
            module_ = LoadLibraryW(dll_path.c_str());
            if (module_) {
                loaded_path = dll_path;
                break;
            }
        }

        if (!module_) {
            if (vif_logger()) {
                vif_logger()->error(std::string("[vif] stage=wintun.load status=failed detail=dll arch=") + arch_tag);
            }
            return false;
        }

        if (vif_logger()) {
            vif_logger()->info(std::string("[vif] stage=wintun.load status=ok arch=") + arch_tag +
                               " path=" + wide_to_utf8(loaded_path));
        }

        auto load_proc = [this](auto& fn, const char* name) -> bool {
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
            fn = reinterpret_cast<std::decay_t<decltype(fn)>>(GetProcAddress(module_, name));
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
            if (!fn) {
                const DWORD err = GetLastError();
                if (vif_logger()) {
                    vif_logger()->error(std::string("[vif] stage=wintun.proc status=failed name=") + name +
                                        " err=" + std::to_string(err));
                }
                return false;
            }
            return true;
        };

        if (!load_proc(WintunOpenAdapter, "WintunOpenAdapter") ||
            !load_proc(WintunCreateAdapter, "WintunCreateAdapter") ||
            !load_proc(WintunCloseAdapter, "WintunCloseAdapter") ||
            !load_proc(WintunStartSession, "WintunStartSession") ||
            !load_proc(WintunEndSession, "WintunEndSession") ||
            !load_proc(WintunReceivePacket, "WintunReceivePacket") ||
            !load_proc(WintunReleaseReceivePacket, "WintunReleaseReceivePacket") ||
            !load_proc(WintunAllocateSendPacket, "WintunAllocateSendPacket") ||
            !load_proc(WintunSendPacket, "WintunSendPacket") ||
            !load_proc(WintunGetReadWaitEvent, "WintunGetReadWaitEvent")) {
            FreeLibrary(module_);
            module_ = nullptr;
            return false;
        }

        return true;
    }

    OpenAdapterFn WintunOpenAdapter{nullptr};
    CreateAdapterFn WintunCreateAdapter{nullptr};
    CloseAdapterFn WintunCloseAdapter{nullptr};
    StartSessionFn WintunStartSession{nullptr};
    EndSessionFn WintunEndSession{nullptr};
    ReceivePacketFn WintunReceivePacket{nullptr};
    ReleaseReceivePacketFn WintunReleaseReceivePacket{nullptr};
    AllocateSendPacketFn WintunAllocateSendPacket{nullptr};
    SendPacketFn WintunSendPacket{nullptr};
    GetReadWaitEventFn WintunGetReadWaitEvent{nullptr};

private:
    HMODULE module_{nullptr};
};

enum class AdapterType {
    Tap,
    Wintun
};

struct AdapterCandidate {
    AdapterType type{AdapterType::Tap};
    std::string identifier;
    std::wstring friendly_w;
    std::string friendly;
    std::string normalized_name;
    std::string normalized_identifier;
};

std::string narrow(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }
    const int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string utf8(static_cast<size_t>(len), '\0');
    const int written = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, utf8.data(), len, nullptr, nullptr);
    if (written <= 0) {
        return {};
    }
    if (!utf8.empty() && utf8.back() == '\0') {
        utf8.pop_back();
    }
    return utf8;
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring wide(static_cast<size_t>(len), L'\0');
    const int written = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), len);
    if (written <= 0) {
        return {};
    }
    if (!wide.empty() && wide.back() == L'\0') {
        wide.pop_back();
    }
    return wide;
}

std::string toLowerCopy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

std::string normalizeGuid(std::string text) {
    std::string normalized;
    normalized.reserve(text.size());
    for (char c : text) {
        if (c == '{' || c == '}' || c == '-') {
            continue;
        }
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return normalized;
}

std::wstring QueryTapFriendlyName(const std::wstring& netcfg_instance_id) {
    std::wstring friendly;
    std::wstring connection_key = L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\";
    connection_key += netcfg_instance_id;
    connection_key += L"\\Connection";

    HKEY hKeyConn;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, connection_key.c_str(), 0, KEY_READ, &hKeyConn) == ERROR_SUCCESS) {
        wchar_t name[256];
        DWORD len = sizeof(name);
        DWORD type = 0;
        if (RegQueryValueExW(hKeyConn, L"Name", NULL, &type, reinterpret_cast<LPBYTE>(name), &len) == ERROR_SUCCESS && len >= sizeof(wchar_t)) {
            size_t chars = (len / sizeof(wchar_t));
            if (chars > 0 && name[chars - 1] == L'\0') {
                --chars;
            }
            friendly.assign(name, chars);
        }
        RegCloseKey(hKeyConn);
    }
    return friendly;
}

std::vector<AdapterCandidate> EnumerateTapAdapters() {
    std::vector<AdapterCandidate> adapters;
    HKEY hKeyClass;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", 0, KEY_READ, &hKeyClass) != ERROR_SUCCESS) {
        return adapters;
    }

    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyLen = static_cast<DWORD>(std::size(subKeyName));

    while (RegEnumKeyExW(hKeyClass, index++, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        subKeyLen = static_cast<DWORD>(std::size(subKeyName));
        HKEY hKeySub;
        if (RegOpenKeyExW(hKeyClass, subKeyName, 0, KEY_READ, &hKeySub) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t componentId[256];
        DWORD type = 0;
        DWORD len = sizeof(componentId);
        if (RegQueryValueExW(hKeySub, L"ComponentId", NULL, &type, reinterpret_cast<LPBYTE>(componentId), &len) == ERROR_SUCCESS) {
            if (wcscmp(componentId, L"tap0901") == 0) {
                wchar_t netCfgInstanceId[256];
                len = sizeof(netCfgInstanceId);
                if (RegQueryValueExW(hKeySub, L"NetCfgInstanceId", NULL, &type, reinterpret_cast<LPBYTE>(netCfgInstanceId), &len) == ERROR_SUCCESS) {
                    std::wstring guid(netCfgInstanceId);
                    std::wstring friendly = QueryTapFriendlyName(guid);
                    if (friendly.empty()) {
                        friendly = guid;
                    }
                    AdapterCandidate cand;
                    cand.type = AdapterType::Tap;
                    cand.identifier = narrow(guid);
                    cand.friendly_w = friendly;
                    cand.friendly = narrow(friendly);
                    cand.normalized_name = toLowerCopy(cand.friendly);
                    cand.normalized_identifier = normalizeGuid(cand.identifier);
                    adapters.push_back(std::move(cand));
                }
            }
        }
        RegCloseKey(hKeySub);
    }
    RegCloseKey(hKeyClass);
    return adapters;
}

std::vector<AdapterCandidate> EnumerateWintunAdapters() {
    std::vector<AdapterCandidate> adapters;
    HKEY hKeyAdapters;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Wintun\\Parameters\\Adapters", 0, KEY_READ, &hKeyAdapters) != ERROR_SUCCESS) {
        return adapters;
    }

    DWORD index = 0;
    wchar_t subKeyName[256];
    DWORD subKeyLen = static_cast<DWORD>(std::size(subKeyName));
    while (RegEnumKeyExW(hKeyAdapters, index++, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        subKeyLen = static_cast<DWORD>(std::size(subKeyName));
        HKEY hKeyAdapter;
        if (RegOpenKeyExW(hKeyAdapters, subKeyName, 0, KEY_READ, &hKeyAdapter) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t name[256];
        DWORD type = 0;
        DWORD len = sizeof(name);
        std::wstring friendly;
        if (RegQueryValueExW(hKeyAdapter, L"Name", NULL, &type, reinterpret_cast<LPBYTE>(name), &len) == ERROR_SUCCESS && len >= sizeof(wchar_t)) {
            size_t chars = len / sizeof(wchar_t);
            if (chars > 0 && name[chars - 1] == L'\0') {
                --chars;
            }
            friendly.assign(name, chars);
        } else {
            friendly = subKeyName;
        }

        AdapterCandidate cand;
        cand.type = AdapterType::Wintun;
        cand.identifier = narrow(subKeyName);
        cand.friendly_w = friendly;
        cand.friendly = narrow(friendly);
        cand.normalized_name = toLowerCopy(cand.friendly);
        cand.normalized_identifier = normalizeGuid(cand.identifier);
        adapters.push_back(std::move(cand));
        RegCloseKey(hKeyAdapter);
    }
    RegCloseKey(hKeyAdapters);
    return adapters;
}

std::vector<AdapterCandidate> BuildAdapterPriorityList(const std::string& requested) {
    const std::string force_backend = []() {
        if (const char* env = std::getenv("CLINK_VIF_BACKEND")) {
            return toLowerCopy(std::string(env));
        }
        return std::string{};
    }();

    const bool skip_wintun = [&]() {
        if (force_backend == "tap") return true;
        if (const char* env = std::getenv("CLINK_VIF_SKIP_WINTUN")) {
            return std::string(env) == "1";
        }
        return false;
    }();
    const bool skip_tap = [&]() {
        if (force_backend == "wintun") return true;
        if (const char* env = std::getenv("CLINK_VIF_SKIP_TAP")) {
            return std::string(env) == "1";
        }
        return false;
    }();

    if (vif_logger()) {
        vif_logger()->info(std::string("[vif] stage=adapter.select status=ok requested=") + requested +
                           " force=" + (force_backend.empty() ? "auto" : force_backend) +
                           " skip_wintun=" + (skip_wintun ? "1" : "0") +
                           " skip_tap=" + (skip_tap ? "1" : "0"));
    }

    auto taps = skip_tap ? std::vector<AdapterCandidate>{} : EnumerateTapAdapters();

    std::vector<AdapterCandidate> wintuns;
    bool wintun_dll_loaded = false;
    if (!skip_wintun) {
        // 先主动尝试加载 DLL，明确输出 success/failed 日志
        wintun_dll_loaded = WintunApi::instance().load();
        wintuns = EnumerateWintunAdapters();

        // DLL 已加载但没有任何实例时，加入一个“可创建”的伪候选，
        // 让 open_wintun_adapter 走 OpenAdapter->CreateAdapter 流程。
        if (wintun_dll_loaded && wintuns.empty()) {
            AdapterCandidate bootstrap;
            bootstrap.type = AdapterType::Wintun;
            bootstrap.identifier = requested.empty() ? "clink0" : requested;
            bootstrap.friendly_w = widen(bootstrap.identifier);
            if (bootstrap.friendly_w.empty()) {
                bootstrap.friendly_w = L"clink0";
            }
            bootstrap.friendly = narrow(bootstrap.friendly_w);
            if (bootstrap.friendly.empty()) {
                bootstrap.friendly = "clink0";
            }
            bootstrap.normalized_name = toLowerCopy(bootstrap.friendly);
            bootstrap.normalized_identifier = normalizeGuid(bootstrap.identifier);
            wintuns.push_back(std::move(bootstrap));
            if (vif_logger()) {
                vif_logger()->warn("[vif] stage=adapter.select status=ok detail=wintun_bootstrap");
            }
        }
    }

    if (taps.empty() && wintuns.empty()) {
        if (vif_logger()) {
            if (!skip_wintun && !wintun_dll_loaded) {
                vif_logger()->warn("[vif] stage=adapter.select status=failed detail=wintun_dll_unavailable");
            } else {
                vif_logger()->warn("[vif] stage=adapter.select status=failed detail=no_adapter");
            }
        }
    }
    std::vector<AdapterCandidate> ordered;

    auto push_unique = [&ordered](const AdapterCandidate& cand) {
        auto it = std::find_if(ordered.begin(), ordered.end(), [&](const AdapterCandidate& existing) {
            return existing.type == cand.type && existing.identifier == cand.identifier;
        });
        if (it == ordered.end()) {
            ordered.push_back(cand);
        }
    };

    std::string normalized_request = toLowerCopy(requested);
    std::string normalized_guid = normalizeGuid(requested);

    if (!normalized_request.empty() || !normalized_guid.empty()) {
        for (const auto& cand : wintuns) {
            if ((!normalized_request.empty() && cand.normalized_name == normalized_request) ||
                (!normalized_guid.empty() && cand.normalized_identifier == normalized_guid)) {
                push_unique(cand);
            }
        }
        for (const auto& cand : taps) {
            if ((!normalized_request.empty() && cand.normalized_name == normalized_request) ||
                (!normalized_guid.empty() && cand.normalized_identifier == normalized_guid)) {
                push_unique(cand);
            }
        }
    }

    for (const auto& cand : wintuns) {
        push_unique(cand);
    }
    for (const auto& cand : taps) {
        push_unique(cand);
    }

    return ordered;
}

}  // namespace

#else
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <cstring>
#include <atomic>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <linux/splice.h>
#include <errno.h>
#include <asio/posix/stream_descriptor.hpp>
#endif

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <sstream>

namespace clink::core::network {

#ifdef _WIN32
/**
 * @brief Windows 平台的虚拟网卡实现（支持 TAP-Windows 与 Wintun 环形缓冲）
 */
#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t dest[6];
    uint8_t src[6];
    uint16_t type;
};

struct ArpHeader {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t hw_len;
    uint8_t proto_len;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint32_t sender_ip;
    uint8_t target_mac[6];
    uint32_t target_ip;
};
#pragma pack(pop)

class WindowsVirtualInterface : public VirtualInterface {
public:
    using VirtualInterface::write_packet;

    explicit WindowsVirtualInterface(asio::io_context& io_context)
        : io_context_(io_context) {}

    void set_logger(std::shared_ptr<logging::Logger> logger) override {
        logger_ = std::move(logger);
        if (logger_) {
            logger_->info("[vif] stage=logger status=ok detail=windows");
        }
    }

    std::error_code open(const std::string& name,
                         const std::string& address,
                         const std::string& netmask) override {
        if (logger_) {
            logger_->info(std::string("[vif] stage=open status=begin detail=windows name=") + name +
                          " address=" + address + " netmask=" + netmask);
        }
        close();

        std::string requested = name;
        if (requested.empty()) {
            if (const char* env = std::getenv("CLINK_VIF_NAME")) {
                requested = env;
            }
        }

        auto candidates = BuildAdapterPriorityList(requested);
        if (candidates.empty()) {
            if (logger_) logger_->warn("[vif] stage=open status=failed detail=no_adapter");
            return std::make_error_code(std::errc::no_such_device);
        }

        std::error_code last_error;
        if (logger_) logger_->info("[vif] stage=adapter.candidates status=ok count=" + std::to_string(candidates.size()));
        for (const auto& candidate : candidates) {
            const char* typ = (candidate.type == AdapterType::Wintun) ? "wintun" : "tap";
            if (logger_) {
                logger_->info(std::string("[vif] stage=adapter.try status=begin type=") + typ +
                              " id=" + candidate.identifier + " friendly=" + candidate.friendly);
            }
            if (candidate.type == AdapterType::Wintun) {
                auto ec = open_wintun_adapter(candidate);
                if (!ec) {
                    backend_ = BackendType::Wintun;
                    name_ = candidate.friendly.empty() ? "wintun" : candidate.friendly;
                    if (logger_) logger_->info(std::string("[vif] stage=adapter.try status=ok type=wintun name=") + name_);
                    return {};
                }
                if (logger_) {
                    logger_->warn(std::string("[vif] stage=adapter.try status=failed type=wintun ec=") +
                                  std::to_string(ec.value()) + " msg=" + ec.message());
                }
                last_error = ec;
            } else {
                auto ec = open_tap_adapter(candidate, address, netmask);
                if (!ec) {
                    backend_ = BackendType::Tap;
                    name_ = candidate.friendly.empty() ? candidate.identifier : candidate.friendly;
                    if (logger_) logger_->info(std::string("[vif] stage=adapter.try status=ok type=tap name=") + name_);
                    return {};
                }
                if (logger_) {
                    logger_->warn(std::string("[vif] stage=adapter.try status=failed type=tap ec=") +
                                  std::to_string(ec.value()) + " msg=" + ec.message());
                }
                last_error = ec;
            }
        }

        return last_error ? last_error : std::make_error_code(std::errc::no_such_device);
    }

    void close() override {
        if (backend_ == BackendType::Tap) {
            if (stream_handle_ && stream_handle_->is_open()) {
                std::error_code ignored;
                stream_handle_->cancel(ignored);
                stream_handle_->close(ignored);
            }
        } else if (backend_ == BackendType::Wintun) {
            if (wintun_wait_handle_ && wintun_wait_handle_->is_open()) {
                std::error_code ignored;
                wintun_wait_handle_->cancel(ignored);
                wintun_wait_handle_->close(ignored);
            }
            auto& api = WintunApi::instance();
            if (wintun_session_) {
                api.WintunEndSession(wintun_session_);
                wintun_session_ = nullptr;
            }
            if (wintun_adapter_) {
                api.WintunCloseAdapter(wintun_adapter_);
                if (logger_ && wintun_adapter_created_by_us_) {
                    logger_->info("[vif] stage=wintun.close status=ok detail=created_by_us");
                }
                wintun_adapter_ = nullptr;
                wintun_adapter_created_by_us_ = false;
            }
            wintun_wait_event_ = NULL;
        }
        write_queue_.clear();
        backend_ = BackendType::None;
        name_.clear();
    }

    void async_read_packet(std::shared_ptr<clink::core::memory::Block> buffer,
                           std::function<void(std::error_code, size_t)> callback) override {
        if (backend_ == BackendType::Wintun) {
            asio::post(io_context_, [this, buffer, callback]() {
                wintun_dispatch_read(buffer, callback);
            });
            return;
        }

        if (!stream_handle_ || !stream_handle_->is_open()) {
            callback(std::make_error_code(std::errc::not_connected), 0);
            return;
        }

        stream_handle_->async_read_some(
            asio::buffer(read_buffer_, sizeof(read_buffer_)),
            [this, buffer, callback](const std::error_code& ec, size_t bytes_transferred) {
                if (ec) {
                    callback(ec, bytes_transferred);
                    return;
                }

                if (bytes_transferred < sizeof(EthernetHeader)) {
                    // Too small, ignore and read again
                    async_read_packet(buffer, callback);
                    return;
                }

                EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(read_buffer_);
                uint16_t eth_type = ntohs(eth->type);

                if (eth_type == 0x0806) { // ARP
                    HandleArp(bytes_transferred);
                    async_read_packet(buffer, callback); // Continue reading
                    return;
                } else if (eth_type == 0x0800) { // IPv4
                    size_t ip_len = bytes_transferred - sizeof(EthernetHeader);
                    if (ip_len > buffer->tailroom()) {
                        // Packet too large for buffer
                        if (logger_) logger_->warn("[vif] stage=read status=skipped detail=packet_too_large bytes=" + std::to_string(ip_len));
                         async_read_packet(buffer, callback);
                         return;
                    }
                    std::memcpy(buffer->write_ptr(), read_buffer_ + sizeof(EthernetHeader), ip_len);
                    buffer->commit(ip_len);
                    callback(ec, ip_len);
                } else {
                    // Unknown protocol, ignore
                    async_read_packet(buffer, callback);
                }
            });
    }

    std::error_code write_packet(const uint8_t* data, size_t size) override {
        if (backend_ == BackendType::Wintun) {
            if (!wintun_session_) {
                return std::make_error_code(std::errc::not_connected);
            }
            auto& api = WintunApi::instance();
            std::lock_guard<std::mutex> lock(wintun_send_mutex_);
            BYTE* packet = api.WintunAllocateSendPacket(wintun_session_, static_cast<DWORD>(size));
            if (!packet) {
                return std::make_error_code(std::errc::resource_unavailable_try_again);
            }
            std::memcpy(packet, data, size);
            api.WintunSendPacket(wintun_session_, packet);
            return {};
        }

        if (!stream_handle_ || !stream_handle_->is_open()) {
             return std::make_error_code(std::errc::not_connected);
        }

        if (size + sizeof(EthernetHeader) > sizeof(read_buffer_)) {
            return std::make_error_code(std::errc::message_size);
        }

        auto packet = std::make_shared<std::vector<uint8_t>>(sizeof(EthernetHeader) + size);
        EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(packet->data());
        std::memcpy(eth->dest, mac_address_, 6);
        std::memcpy(eth->src, virtual_gateway_mac_, 6);
        eth->type = htons(0x0800);

        std::memcpy(packet->data() + sizeof(EthernetHeader), data, size);

        asio::post(io_context_, [this, packet]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(packet);
            if (!write_in_progress) {
                do_write();
            }
        });
        
        return {};
    }

    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return name_; }

private:
    enum class BackendType {
        None,
        Tap,
        Wintun
    };

    std::error_code open_tap_adapter(const AdapterCandidate& candidate,
                                     const std::string& address,
                                     const std::string& netmask);

    std::error_code open_wintun_adapter(const AdapterCandidate& candidate);

    bool ensure_stream_handle() {
        if (!stream_handle_) {
            try {
                stream_handle_ = std::make_unique<asio::windows::stream_handle>(io_context_);
                if (logger_) logger_->info("[vif] stage=stream_handle.init status=ok");
            } catch (const std::exception& ex) {
                if (logger_) logger_->error(std::string("[vif] stage=stream_handle.init status=failed detail=") + ex.what());
                return false;
            }
        }
        return true;
    }

    bool ensure_wintun_wait_handle() {
        if (!wintun_wait_handle_) {
            try {
                wintun_wait_handle_ = std::make_unique<asio::windows::object_handle>(io_context_);
                if (logger_) logger_->info("[vif] stage=wintun_wait_handle.init status=ok");
            } catch (const std::exception& ex) {
                if (logger_) logger_->error(std::string("[vif] stage=wintun_wait_handle.init status=failed detail=") + ex.what());
                return false;
            }
        }
        return true;
    }

    void wintun_dispatch_read(std::shared_ptr<clink::core::memory::Block> buffer,
                              std::function<void(std::error_code, size_t)> callback);

    void do_write() {
        auto buffer = write_queue_.front();
        if (!stream_handle_ || !stream_handle_->is_open()) {
            write_queue_.clear();
            return;
        }

        asio::async_write(*stream_handle_, asio::buffer(*buffer),
            [this, buffer](std::error_code ec, size_t /*length*/) {
                if (ec) {
                    if (logger_) logger_->warn(std::string("[vif] stage=write status=failed detail=async_write msg=") + ec.message());
                }
                write_queue_.pop_front();
                if (!write_queue_.empty()) {
                    do_write();
                }
            });
    }

    void HandleArp(size_t bytes) {
        if (bytes < sizeof(EthernetHeader) + sizeof(ArpHeader)) return;
        
        EthernetHeader* eth_req = reinterpret_cast<EthernetHeader*>(read_buffer_);
        ArpHeader* arp_req = reinterpret_cast<ArpHeader*>(read_buffer_ + sizeof(EthernetHeader));

        if (ntohs(arp_req->opcode) != 1) return; // Only handle Request

        auto reply = std::make_shared<std::vector<uint8_t>>(sizeof(EthernetHeader) + sizeof(ArpHeader));
        EthernetHeader* eth_res = reinterpret_cast<EthernetHeader*>(reply->data());
        ArpHeader* arp_res = reinterpret_cast<ArpHeader*>(reply->data() + sizeof(EthernetHeader));

        // Ethernet Header
        std::memcpy(eth_res->dest, eth_req->src, 6);
        std::memcpy(eth_res->src, virtual_gateway_mac_, 6); 
        eth_res->type = htons(0x0806);

        // ARP Header
        arp_res->hw_type = htons(1); // Ethernet
        arp_res->proto_type = htons(0x0800); // IPv4
        arp_res->hw_len = 6;
        arp_res->proto_len = 4;
        arp_res->opcode = htons(2); // Reply

        std::memcpy(arp_res->sender_mac, virtual_gateway_mac_, 6);
        arp_res->sender_ip = arp_req->target_ip; // We are who you are looking for

        std::memcpy(arp_res->target_mac, arp_req->sender_mac, 6);
        arp_res->target_ip = arp_req->sender_ip;

        asio::post(io_context_, [this, reply]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(reply);
            if (!write_in_progress) {
                do_write();
            }
        });
    }

    asio::io_context& io_context_;
    std::unique_ptr<asio::windows::stream_handle> stream_handle_;
    std::unique_ptr<asio::windows::object_handle> wintun_wait_handle_;
    BackendType backend_{BackendType::None};
    std::string name_;
    uint8_t mac_address_[6]{};
    uint8_t virtual_gateway_mac_[6]{};
    struct in_addr local_ip_{};
    struct in_addr netmask_ip_{};

    WINTUN_ADAPTER_HANDLE wintun_adapter_{nullptr};
    WINTUN_SESSION_HANDLE wintun_session_{nullptr};
    bool wintun_adapter_created_by_us_{false};
    HANDLE wintun_wait_event_{NULL};
    std::mutex wintun_send_mutex_;

    uint8_t read_buffer_[2048]{};
    std::deque<std::shared_ptr<std::vector<uint8_t>>> write_queue_;
};

std::error_code WindowsVirtualInterface::open_tap_adapter(const AdapterCandidate& candidate,
                                                          const std::string& address,
                                                          const std::string& netmask) {
    if (!ensure_stream_handle()) {
        return std::make_error_code(std::errc::not_connected);
    }

    std::string path = "\\\\.\\Global\\" + candidate.identifier + ".tap";
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING,
                                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (logger_) logger_->error(std::string("[vif] stage=tap.open status=failed id=") + candidate.identifier +
                                    " err=" + std::to_string(err));
        return std::error_code(static_cast<int>(err), std::system_category());
    }

    DWORD len = 0;
    if (!DeviceIoControl(handle, TAP_IOCTL_GET_MAC, mac_address_, sizeof(mac_address_),
                         mac_address_, sizeof(mac_address_), &len, NULL)) {
        DWORD err = GetLastError();
        CloseHandle(handle);
        return std::error_code(static_cast<int>(err), std::system_category());    }

    std::memcpy(virtual_gateway_mac_, mac_address_, 6);
    virtual_gateway_mac_[0] ^= 0x02;

    if (inet_pton(AF_INET, address.c_str(), &local_ip_) != 1 ||
        inet_pton(AF_INET, netmask.c_str(), &netmask_ip_) != 1) {
        CloseHandle(handle);
        return std::make_error_code(std::errc::invalid_argument);
    }

    struct in_addr network;
    network.s_addr = local_ip_.s_addr & netmask_ip_.s_addr;
    struct {
        struct in_addr local;
        struct in_addr network;
        struct in_addr netmask;
    } config = {local_ip_, network, netmask_ip_};

    if (!DeviceIoControl(handle, TAP_IOCTL_CONFIG_TUN, &config, sizeof(config), &config, sizeof(config), &len, NULL)) {
        DWORD err = GetLastError();
        CloseHandle(handle);
        return std::error_code(static_cast<int>(err), std::system_category());
    }

    uint32_t status = 1;
    DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);

    if (!stream_handle_) {
        return std::make_error_code(std::errc::not_connected);
    }
    stream_handle_->assign(handle);
    return {};
}

std::error_code WindowsVirtualInterface::open_wintun_adapter(const AdapterCandidate& candidate) {
    auto& api = WintunApi::instance();
    if (!api.load()) {
        return std::error_code(ERROR_MOD_NOT_FOUND, std::system_category());
    }

    std::wstring friendly = candidate.friendly_w;
    if (friendly.empty()) {
        friendly = widen(candidate.identifier);
    }
    if (friendly.empty()) {
        friendly = L"clink";
    }

    if (logger_) logger_->info(std::string("[vif] stage=wintun.open status=begin name=") + narrow(friendly));
    WINTUN_ADAPTER_HANDLE adapter = api.WintunOpenAdapter(friendly.c_str());

    bool created_by_us = false;
    if (!adapter) {
        const DWORD open_err = GetLastError();
        if (logger_) logger_->warn(std::string("[vif] stage=wintun.open status=failed name=") + narrow(friendly) +
                                   " err=" + std::to_string(open_err));

        if (logger_) logger_->info(std::string("[vif] stage=wintun.create status=begin name=") + narrow(friendly));
        adapter = api.WintunCreateAdapter(friendly.c_str(), L"CLink", nullptr);

        if (adapter) {
            created_by_us = true;
            if (logger_) logger_->info(std::string("[vif] stage=wintun.create status=ok name=") + narrow(friendly));
        }
    } else {
        if (logger_) logger_->info(std::string("[vif] stage=wintun.open status=ok name=") + narrow(friendly));
    }
    if (!adapter) {
        DWORD err = GetLastError();
        return std::error_code(static_cast<int>(err ? err : ERROR_FILE_NOT_FOUND), std::system_category());
    }

    if (logger_) logger_->info("[vif] stage=wintun.session status=begin");
    WINTUN_SESSION_HANDLE session = api.WintunStartSession(adapter, kDefaultRingCapacity);
    if (!session) {
        DWORD err = GetLastError();
        if (logger_) logger_->error(std::string("[vif] stage=wintun.session status=failed err=") + std::to_string(err));
        api.WintunCloseAdapter(adapter);
        return std::error_code(static_cast<int>(err ? err : ERROR_NOT_ENOUGH_MEMORY), std::system_category());
    }

    HANDLE evt = api.WintunGetReadWaitEvent(session);
    if (!evt) {
        api.WintunEndSession(session);
        api.WintunCloseAdapter(adapter);
        if (logger_) logger_->error("[vif] stage=wintun.wait_event status=failed");
        return std::make_error_code(std::errc::operation_not_permitted);
    }

    HANDLE duplicated = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), evt, GetCurrentProcess(), &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        DWORD err = GetLastError();
        if (logger_) logger_->warn(std::string("[vif] stage=wintun.wait_event status=failed detail=duplicate err=") + std::to_string(err));
        duplicated = NULL;
    } else {
        if (logger_) logger_->info("[vif] stage=wintun.wait_event status=ok detail=duplicated");
    }

    // 注意：asio::windows::object_handle 在部分环境下构造/assign 存在兼容性问题，
    // 先不绑定 wrapper，避免影响 VIF 主流程。
    wintun_wait_event_ = duplicated;
    if (wintun_wait_event_) {
        if (logger_) logger_->info("[vif] stage=wintun.wait_event status=ok detail=skipped_wrapper");
    }

    wintun_adapter_ = adapter;
    wintun_session_ = session;
    wintun_adapter_created_by_us_ = created_by_us;
    return {};
}

void WindowsVirtualInterface::wintun_dispatch_read(std::shared_ptr<clink::core::memory::Block> buffer,
                                                   std::function<void(std::error_code, size_t)> callback) {
    if (!wintun_session_) {
        callback(std::make_error_code(std::errc::not_connected), 0);
        return;
    }

    auto& api = WintunApi::instance();
    DWORD packet_size = 0;
    BYTE* packet = api.WintunReceivePacket(wintun_session_, &packet_size);
    if (packet) {
        size_t len = std::min(static_cast<size_t>(packet_size), buffer->tailroom());
        std::memcpy(buffer->write_ptr(), packet, len);
        buffer->commit(len);
        api.WintunReleaseReceivePacket(wintun_session_, packet);
        callback({}, len);
        return;
    }

    // 在某些 MinGW/Asio 组合下，object_handle 可能不可用。
    // 对该场景使用轻量轮询退避，避免向上层抛 Unknown error 导致读取链路中断。
    if (!wintun_wait_handle_ || !wintun_wait_handle_->is_open()) {
        callback(std::make_error_code(std::errc::operation_in_progress), 0);
        return;
    }

    wintun_wait_handle_->async_wait([this, buffer, callback](const std::error_code& ec) {
        if (ec) {
            callback(ec, 0);
            return;
        }
        wintun_dispatch_read(buffer, callback);
    });
}

#else

/**
 * @brief Linux 平台的虚拟网卡实现 (TUN/TAP)
 */
class LinuxVirtualInterface : public VirtualInterface {
public:
    using VirtualInterface::write_packet;

    explicit LinuxVirtualInterface(asio::io_context& io_context)
        : io_context_(io_context), stream_descriptor_(io_context) {}

    void set_logger(std::shared_ptr<logging::Logger> logger) override {
        logger_ = std::move(logger);
    }

    void set_zero_copy_enabled(bool enabled) override {
        zero_copy_enabled_.store(enabled, std::memory_order_relaxed);
    }

    std::error_code open(const std::string& name,
                         [[maybe_unused]] const std::string& address,
                         [[maybe_unused]] const std::string& netmask) override {
        name_ = name;
        zero_copy_reason_.clear();

        if (logger_) logger_->info("[vif] stage=open status=begin detail=linux_tun");

        // 打开 TUN 设备
        int fd = ::open("/dev/net/tun", O_RDWR);
        if (fd < 0) {
            zero_copy_reason_ = "open_tun_failed";
            if (logger_) logger_->error("[vif] stage=open status=failed detail=open_tun errno=" + std::to_string(errno));
            return std::error_code(errno, std::system_category());
        }

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IFF_NO_PI: 不包含包头信息
        if (!name.empty()) {
            std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
        }

        if (::ioctl(fd, TUNSETIFF, static_cast<void*>(&ifr)) < 0) {
            ::close(fd);
            zero_copy_reason_ = "tun_ioctl_failed";
            if (logger_) logger_->error("[vif] stage=open status=failed detail=tun_ioctl errno=" + std::to_string(errno));
            return std::error_code(errno, std::system_category());
        }

        name_ = ifr.ifr_name;
        stream_descriptor_.assign(fd);

        if (zero_copy_enabled_.load(std::memory_order_relaxed)) {
            init_zerocopy_resources();
        }

        if (logger_) logger_->info(std::string("[vif] stage=open status=ok detail=name=") + name_);

        return {};
    }

    void close() override {
        if (stream_descriptor_.is_open()) {
            stream_descriptor_.close();
        }
        write_queue_.clear();
        teardown_zerocopy_resources();
        if (logger_) logger_->info("[vif] stage=close status=ok detail=linux_tun");
    }

    void async_read_packet(std::shared_ptr<clink::core::memory::Block> buffer, 
                           std::function<void(std::error_code, size_t)> callback) override {
        if (!stream_descriptor_.is_open()) {
            callback(std::make_error_code(std::errc::not_connected), 0);
            return;
        }

        // Zero-Copy Read: 直接读取到 Block 的写入位置
        stream_descriptor_.async_read_some(
            asio::buffer(buffer->write_ptr(), buffer->tailroom()),
            [buffer, callback](const std::error_code& ec, size_t bytes_transferred) {
                if (!ec) {
                    buffer->commit(bytes_transferred);
                }
                callback(ec, bytes_transferred);
            });
    }

    void do_write() {
        if (write_queue_.empty()) {
            return;
        }
        if (!stream_descriptor_.is_open()) {
            write_queue_.clear();
            return;
        }

        auto packet = write_queue_.front();
        const int tun_fd = stream_descriptor_.native_handle();
        std::error_code write_ec;

        if (zero_copy_enabled_.load(std::memory_order_relaxed)) {
            if (!zerocopy_ready_) {
                init_zerocopy_resources();
            }
            if (zerocopy_ready_) {
                write_ec = write_packet_zerocopy(tun_fd, packet->data(), packet->size());
                if (write_ec) {
                    zero_copy_reason_ = "splice_failed";
                    if (logger_) logger_->warn("[vif] stage=zerocopy.write status=failed detail=splice ec=" + std::to_string(write_ec.value()));
                } else {
                    if (logger_) logger_->trace("[vif] stage=zerocopy.write status=ok bytes=" + std::to_string(packet->size()));
                }
            }
        }

        if (!write_ec) {
            // zero-copy ok
        } else {
            const ssize_t written = ::write(tun_fd, packet->data(), packet->size());
            if (written < 0) {
                write_ec = std::error_code(errno, std::system_category());
                if (logger_) logger_->error("[vif] stage=write status=failed detail=write ec=" + std::to_string(write_ec.value()));
            } else {
                if (logger_) logger_->trace("[vif] stage=write status=ok bytes=" + std::to_string(packet->size()) + " fallback=true");
            }
        }

        write_queue_.pop_front();
        if (!write_queue_.empty()) {
            asio::post(io_context_, [this]() { do_write(); });
        }
    }

    std::error_code write_packet(const uint8_t* data, size_t size) override {
        if (!stream_descriptor_.is_open()) {
            return std::make_error_code(std::errc::not_connected);
        }

        auto packet = std::make_shared<std::vector<uint8_t>>(data, data + size);
        asio::post(io_context_, [this, packet]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(packet);
            if (!write_in_progress) {
                do_write();
            }
        });

        return {};
    }

    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return name_; }

private:
    void init_zerocopy_resources() {
        if (zerocopy_ready_) {
            return;
        }

        if (logger_) logger_->info("[vif] stage=zerocopy.init status=begin");

        teardown_zerocopy_resources();

        if (::pipe(pipe_fds_) != 0) {
            zero_copy_reason_ = "pipe_create_failed";
            if (logger_) logger_->error("[vif] stage=zerocopy.init status=failed detail=pipe errno=" + std::to_string(errno));
            return;
        }

        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, socketpair_fds_) != 0) {
            zero_copy_reason_ = "socketpair_create_failed";
            if (logger_) logger_->error("[vif] stage=zerocopy.init status=failed detail=socketpair errno=" + std::to_string(errno));
            teardown_zerocopy_resources();
            return;
        }

        zerocopy_ready_ = true;
        zero_copy_reason_.clear();
        if (logger_) logger_->info("[vif] stage=zerocopy.init status=ok");
    }

    void teardown_zerocopy_resources() {
        if (pipe_fds_[0] >= 0) {
            ::close(pipe_fds_[0]);
        }
        if (pipe_fds_[1] >= 0) {
            ::close(pipe_fds_[1]);
        }
        if (socketpair_fds_[0] >= 0) {
            ::close(socketpair_fds_[0]);
        }
        if (socketpair_fds_[1] >= 0) {
            ::close(socketpair_fds_[1]);
        }
        pipe_fds_[0] = pipe_fds_[1] = -1;
        socketpair_fds_[0] = socketpair_fds_[1] = -1;
        zerocopy_ready_ = false;
        if (logger_) logger_->info("[vif] stage=zerocopy.close status=ok");
    }

    std::error_code write_packet_zerocopy(int tun_fd, const uint8_t* data, size_t size) {
        if (!zerocopy_ready_) {
            return std::make_error_code(std::errc::operation_not_permitted);
        }

        ssize_t written = ::write(socketpair_fds_[0], data, size);
        if (written < 0) {
            return std::error_code(errno, std::system_category());
        }
        if (static_cast<size_t>(written) != size) {
            return std::make_error_code(std::errc::io_error);
        }

        size_t remaining = size;
        while (remaining > 0) {
            ssize_t moved_in = ::splice(socketpair_fds_[1], nullptr, pipe_fds_[1], nullptr, remaining, SPLICE_F_MOVE);
            if (moved_in < 0) {
                if (errno == EINTR) continue;
                return std::error_code(errno, std::system_category());
            }
            if (moved_in == 0) {
                return std::make_error_code(std::errc::io_error);
            }

            size_t pending = static_cast<size_t>(moved_in);
            while (pending > 0) {
                ssize_t moved_out = ::splice(pipe_fds_[0], nullptr, tun_fd, nullptr, pending, SPLICE_F_MOVE);
                if (moved_out < 0) {
                    if (errno == EINTR) continue;
                    return std::error_code(errno, std::system_category());
                }
                if (moved_out == 0) {
                    return std::make_error_code(std::errc::io_error);
                }
                pending -= static_cast<size_t>(moved_out);
                remaining -= static_cast<size_t>(moved_out);
            }
        }

        return {};
    }

    asio::io_context& io_context_;
    asio::posix::stream_descriptor stream_descriptor_;
    std::shared_ptr<logging::Logger> logger_;
    std::string name_;
    std::atomic<bool> zero_copy_enabled_{true};
    std::atomic<bool> zerocopy_ready_{false};
    int pipe_fds_[2]{-1, -1};
    int socketpair_fds_[2]{-1, -1};
    std::string zero_copy_reason_;
    std::deque<std::shared_ptr<std::vector<uint8_t>>> write_queue_;
};
#endif

VirtualInterfacePtr create_virtual_interface(asio::io_context& io_context) {
#ifdef _WIN32
    try {
        auto vif = std::make_unique<WindowsVirtualInterface>(io_context);
        return vif;
    } catch (const std::exception& e) {
        if (vif_logger()) {
            vif_logger()->error(std::string("[vif] stage=create status=failed detail=exception msg=") + e.what());
        }
        return {};
    } catch (...) {
        if (vif_logger()) {
            vif_logger()->error("[vif] stage=create status=failed detail=unknown");
        }
        return {};
    }
#else
    return std::make_unique<LinuxVirtualInterface>(io_context);
#endif
}

}  // namespace clink::core::network
