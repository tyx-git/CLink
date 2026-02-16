#include "clink/core/network/virtual_interface.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#endif

#include <iostream>
#include <thread>
#include <chrono>
#include <cstdint>

namespace clink::core::network {

#ifdef _WIN32
/**
 * @brief Windows 平台的虚拟网卡实现 (占位)
 */
class WindowsVirtualInterface : public VirtualInterface {
public:
    explicit WindowsVirtualInterface(asio::io_context& io_context)
        : io_context_(io_context), timer_(io_context) {}

    std::error_code open(const std::string& name, 
                         const std::string& address, 
                         const std::string& netmask) override {
        name_ = name;
        std::cout << "[virtual_interface] opening windows interface: " << name 
                  << " (" << address << "/" << netmask << ")" << std::endl;
        return {}; 
    }

    void close() override {
        timer_.cancel();
        std::cout << "[virtual_interface] closing windows interface" << std::endl;
    }

    void async_read_packet(std::vector<uint8_t>& buffer, 
                           std::function<void(std::error_code, size_t)> callback) override {
        // 模拟异步读取：使用定时器延迟回调
        timer_.expires_after(std::chrono::milliseconds(100));
        timer_.async_wait([this, &buffer, callback](std::error_code ec) {
            if (ec) {
                callback(ec, 0);
                return;
            }
            // 模拟没有数据的情况，清空 buffer
            buffer.clear();
            callback({}, 0);
        });
    }

    std::error_code write_packet(const uint8_t* data, size_t size) override {
        (void)data;
        (void)size;
        return {};
    }

    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return name_; }

private:
    asio::io_context& io_context_;
    asio::steady_timer timer_;
    std::string name_;
};
#endif

VirtualInterfacePtr create_virtual_interface(asio::io_context& io_context) {
#ifdef _WIN32
    return std::make_unique<WindowsVirtualInterface>(io_context);
#else
    return nullptr;
#endif
}

}  // namespace clink::core::network
