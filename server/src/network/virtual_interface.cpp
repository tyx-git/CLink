#include "server/include/clink/core/network/virtual_interface.hpp"
#include <cstdlib>
#include <functional>

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <ws2tcpip.h>
#include <winreg.h>
#include <asio/windows/stream_handle.hpp>
#include <asio/windows/object_handle.hpp>
#include <optional>
#include <string_view>
#include <algorithm>
#include <mutex>
#include <vector>

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

struct WINTUN_ADAPTER;
struct WINTUN_SESSION;

namespace {

constexpr DWORD kDefaultRingCapacity = 4 * 1024 * 1024;  // 4MB ring buffer

class WintunApi {
public:
    using OpenAdapterFn = WINTUN_ADAPTER* (WINAPI*)(const wchar_t*);
    using CreateAdapterFn = WINTUN_ADAPTER* (WINAPI*)(const wchar_t*, const wchar_t*, const GUID*);
    using CloseAdapterFn = void (WINAPI*)(WINTUN_ADAPTER*);
    using StartSessionFn = WINTUN_SESSION* (WINAPI*)(WINTUN_ADAPTER*, DWORD);
    using EndSessionFn = void (WINAPI*)(WINTUN_SESSION*);
    using ReceivePacketFn = BYTE* (WINAPI*)(WINTUN_SESSION*, DWORD*);
    using ReleaseReceivePacketFn = void (WINAPI*)(WINTUN_SESSION*, BYTE*);
    using AllocateSendPacketFn = BYTE* (WINAPI*)(WINTUN_SESSION*, DWORD);
    using SendPacketFn = void (WINAPI*)(WINTUN_SESSION*, BYTE*);
    using GetReadWaitEventFn = HANDLE (WINAPI*)(WINTUN_SESSION*);

    static WintunApi& instance() {
        static WintunApi api;
        return api;
    }

    bool load() {
        if (module_) {
            return true;
        }

        std::vector<std::wstring> candidates;
        candidates.emplace_back(L"wintun.dll");
        wchar_t system_path[MAX_PATH] = {};
        if (GetSystemDirectoryW(system_path, MAX_PATH)) {
            std::wstring path(system_path);
            path += L"\\wintun.dll";
            candidates.push_back(std::move(path));
        }

        for (const auto& dll_path : candidates) {
            module_ = LoadLibraryW(dll_path.c_str());
            if (module_) {
                break;
            }
        }

        if (!module_) {
            return false;
        }

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#define LOAD_PROC(name) name = reinterpret_cast<decltype(name)>(GetProcAddress(module_, #name)); \
        if (!(name)) { FreeLibrary(module_); module_ = nullptr; return false; }
        LOAD_PROC(WintunOpenAdapter);
        LOAD_PROC(WintunCreateAdapter);
        LOAD_PROC(WintunCloseAdapter);
        LOAD_PROC(WintunStartSession);
        LOAD_PROC(WintunEndSession);
        LOAD_PROC(WintunReceivePacket);
        LOAD_PROC(WintunReleaseReceivePacket);
        LOAD_PROC(WintunAllocateSendPacket);
        LOAD_PROC(WintunSendPacket);
        LOAD_PROC(WintunGetReadWaitEvent);
#undef LOAD_PROC
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

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
    int len = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) {
        return {};
    }
    std::string utf8(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, utf8.data(), len, nullptr, nullptr);
    return utf8;
}

std::wstring widen(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    if (len <= 0) {
        return {};
    }
    std::wstring wide(static_cast<size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, wide.data(), len);
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
    auto taps = EnumerateTapAdapters();
    auto wintuns = EnumerateWintunAdapters();
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
#include <asio/posix/stream_descriptor.hpp>
#endif

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdint>
#include <deque>

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
        : io_context_(io_context), 
          strand_(asio::make_strand(io_context)),
          timer_(io_context), 
          stream_handle_(io_context),
          wintun_wait_handle_(io_context) {}

    std::error_code open(const std::string& name,
                         const std::string& address,
                         const std::string& netmask) override {
        close();

        std::string requested = name;
        if (requested.empty()) {
            if (const char* env = std::getenv("CLINK_VIF_NAME")) {
                requested = env;
            }
        }

        auto candidates = BuildAdapterPriorityList(requested);
        if (candidates.empty()) {
            std::cerr << "[virtual_interface] no TAP/Wintun adapters detected" << std::endl;
            return std::make_error_code(std::errc::no_such_device);
        }

        std::error_code last_error;
        for (const auto& candidate : candidates) {
            if (candidate.type == AdapterType::Wintun) {
                auto ec = open_wintun_adapter(candidate);
                if (!ec) {
                    backend_ = BackendType::Wintun;
                    name_ = candidate.friendly.empty() ? "wintun" : candidate.friendly;
                    return {};
                }
                last_error = ec;
            } else {
                auto ec = open_tap_adapter(candidate, address, netmask);
                if (!ec) {
                    backend_ = BackendType::Tap;
                    name_ = candidate.friendly.empty() ? candidate.identifier : candidate.friendly;
                    return {};
                }
                last_error = ec;
            }
        }

        return last_error ? last_error : std::make_error_code(std::errc::no_such_device);
    }

    void close() override {
        if (backend_ == BackendType::Tap) {
            if (stream_handle_.is_open()) {
                std::error_code ignored;
                stream_handle_.cancel(ignored);
                stream_handle_.close();
            }
            timer_.cancel();
        } else if (backend_ == BackendType::Wintun) {
            if (wintun_wait_handle_.is_open()) {
                std::error_code ignored;
                wintun_wait_handle_.cancel(ignored);
                wintun_wait_handle_.close();
            }
            auto& api = WintunApi::instance();
            if (wintun_session_) {
                api.WintunEndSession(wintun_session_);
                wintun_session_ = nullptr;
            }
            if (wintun_adapter_) {
                api.WintunCloseAdapter(wintun_adapter_);
                wintun_adapter_ = nullptr;
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
            asio::post(strand_, [this, buffer, callback]() {
                wintun_dispatch_read(buffer, callback);
            });
            return;
        }

        if (!stream_handle_.is_open()) {
            callback(std::make_error_code(std::errc::not_connected), 0);
            return;
        }

        stream_handle_.async_read_some(
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
                        std::cerr << "[virtual_interface] Packet too large: " << ip_len << std::endl;
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

        if (!stream_handle_.is_open()) {
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

        asio::post(strand_, [this, packet]() {
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

    void wintun_dispatch_read(std::shared_ptr<clink::core::memory::Block> buffer,
                              std::function<void(std::error_code, size_t)> callback);

    void do_write() {
        auto buffer = write_queue_.front();
        asio::async_write(stream_handle_, asio::buffer(*buffer),
            asio::bind_executor(strand_, [this, buffer](std::error_code ec, size_t /*length*/) {
                if (ec) {
                    std::cerr << "[virtual_interface] async_write failed: " << ec.message() << std::endl;
                }
                write_queue_.pop_front();
                if (!write_queue_.empty()) {
                    do_write();
                }
            }));
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

        asio::post(strand_, [this, reply]() {
            bool write_in_progress = !write_queue_.empty();
            write_queue_.push_back(reply);
            if (!write_in_progress) {
                do_write();
            }
        });
    }

    asio::io_context& io_context_;
    asio::strand<asio::io_context::executor_type> strand_;
    asio::steady_timer timer_;
    asio::windows::stream_handle stream_handle_;
    asio::windows::object_handle wintun_wait_handle_;
    BackendType backend_{BackendType::None};
    std::string name_;
    uint8_t mac_address_[6]{};
    uint8_t virtual_gateway_mac_[6]{};
    struct in_addr local_ip_{};
    struct in_addr netmask_ip_{};

    WINTUN_ADAPTER* wintun_adapter_{nullptr};
    WINTUN_SESSION* wintun_session_{nullptr};
    HANDLE wintun_wait_event_{NULL};
    std::mutex wintun_send_mutex_;
    
    uint8_t read_buffer_[2048]{};
    std::deque<std::shared_ptr<std::vector<uint8_t>>> write_queue_;
};

std::error_code WindowsVirtualInterface::open_tap_adapter(const AdapterCandidate& candidate,
                                                          const std::string& address,
                                                          const std::string& netmask) {
    std::string path = "\\\\.\\Global\\" + candidate.identifier + ".tap";
    HANDLE handle = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING,
                                FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        std::cerr << "[virtual_interface] failed to open TAP adapter " << candidate.identifier
                  << ": " << err << std::endl;
        return std::error_code(err, std::system_category());
    }

    DWORD len = 0;
    if (!DeviceIoControl(handle, TAP_IOCTL_GET_MAC, mac_address_, sizeof(mac_address_),
                         mac_address_, sizeof(mac_address_), &len, NULL)) {
        DWORD err = GetLastError();
        CloseHandle(handle);
        return std::error_code(err, std::system_category());
    }

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
        return std::error_code(err, std::system_category());
    }

    uint32_t status = 1;
    DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL);

    stream_handle_.assign(handle);
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

    WINTUN_ADAPTER* adapter = api.WintunOpenAdapter(friendly.c_str());
    if (!adapter) {
        adapter = api.WintunCreateAdapter(friendly.c_str(), L"clink", nullptr);
    }
    if (!adapter) {
        DWORD err = GetLastError();
        return std::error_code(err ? err : ERROR_FILE_NOT_FOUND, std::system_category());
    }

    WINTUN_SESSION* session = api.WintunStartSession(adapter, kDefaultRingCapacity);
    if (!session) {
        DWORD err = GetLastError();
        api.WintunCloseAdapter(adapter);
        return std::error_code(err ? err : ERROR_NOT_ENOUGH_MEMORY, std::system_category());
    }

    HANDLE evt = api.WintunGetReadWaitEvent(session);
    if (!evt) {
        api.WintunEndSession(session);
        api.WintunCloseAdapter(adapter);
        return std::make_error_code(std::errc::operation_not_permitted);
    }

    HANDLE duplicated = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), evt, GetCurrentProcess(), &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        DWORD err = GetLastError();
        api.WintunEndSession(session);
        api.WintunCloseAdapter(adapter);
        return std::error_code(err, std::system_category());
    }

    wintun_wait_event_ = duplicated;
    wintun_wait_handle_.assign(wintun_wait_event_);
    wintun_adapter_ = adapter;
    wintun_session_ = session;
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

    if (!wintun_wait_handle_.is_open()) {
        callback(std::make_error_code(std::errc::operation_in_progress), 0);
        return;
    }

    wintun_wait_handle_.async_wait(asio::bind_executor(
        strand_, [this, buffer, callback](const std::error_code& ec) {
            if (ec) {
                callback(ec, 0);
                return;
            }
            wintun_dispatch_read(buffer, callback);
        }));
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

    std::error_code open(const std::string& name, 
                         const std::string& address, 
                         const std::string& netmask) override {
        name_ = name;
        
        // 打开 TUN 设备
        int fd = ::open("/dev/net/tun", O_RDWR);
        if (fd < 0) {
            return std::error_code(errno, std::system_category());
        }

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // IFF_NO_PI: 不包含包头信息
        if (!name.empty()) {
            std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
        }

        if (::ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
            ::close(fd);
            return std::error_code(errno, std::system_category());
        }

        name_ = ifr.ifr_name;
        stream_descriptor_.assign(fd);
        
        std::cout << "[virtual_interface] opened linux interface: " << name_ << std::endl;
        
        // TODO: 配置 IP 地址和路由 (通常需要 root 权限或 netlink 交互)
        // 这里假设外部脚本已配置好，或者后续添加 Netlink 代码
        
        return {};
    }

    void close() override {
        if (stream_descriptor_.is_open()) {
            stream_descriptor_.close();
        }
        std::cout << "[virtual_interface] closing linux interface" << std::endl;
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

    std::error_code write_packet(const uint8_t* data, size_t size) override {
        if (!stream_descriptor_.is_open()) {
            return std::make_error_code(std::errc::not_connected);
        }
        
        // 同步写入
        // 注意：在高并发场景下，这里也应该改为异步
        ssize_t written = ::write(stream_descriptor_.native_handle(), data, size);
        if (written < 0) {
            return std::error_code(errno, std::system_category());
        }
        return {};
    }

    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return name_; }

private:
    asio::io_context& io_context_;
    asio::posix::stream_descriptor stream_descriptor_;
    std::string name_;
};
#endif

VirtualInterfacePtr create_virtual_interface(asio::io_context& io_context) {
#ifdef _WIN32
    return std::make_unique<WindowsVirtualInterface>(io_context);
#else
    return std::make_unique<LinuxVirtualInterface>(io_context);
#endif
}

}  // namespace clink::core::network
