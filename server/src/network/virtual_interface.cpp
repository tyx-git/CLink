#include "clink/core/network/virtual_interface.hpp"

#ifdef _WIN32
#include <windows.h>
#include <winioctl.h>
#include <asio/windows/stream_handle.hpp>
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

namespace clink::core::network {

#ifdef _WIN32
/**
 * @brief Windows 平台的虚拟网卡实现 (基于 TAP-Windows 或 Wintun)
 * 
 * TODO: 目前仅实现了基础的 Overlapped I/O 结构。
 * 对于 Wintun，建议使用 Ring Buffer 模式以获得更高性能 (Phase 4 目标)。
 */
class WindowsVirtualInterface : public VirtualInterface {
public:
    using VirtualInterface::write_packet;

    explicit WindowsVirtualInterface(asio::io_context& io_context)
        : io_context_(io_context), timer_(io_context), stream_handle_(io_context) {}

    std::error_code open(const std::string& name, 
                         const std::string& address, 
                         const std::string& netmask) override {
        name_ = name;
        std::cout << "[virtual_interface] opening windows interface: " << name 
                  << " (" << address << "/" << netmask << ")" << std::endl;
        
        // TODO: 实际打开 TAP 设备或 Wintun 适配器的逻辑
        // handle_ = CreateFile(...);
        // if (handle_ != INVALID_HANDLE_VALUE) {
        //     stream_handle_.assign(handle_);
        // }
        
        return {}; 
    }

    void close() override {
        if (stream_handle_.is_open()) {
            stream_handle_.close();
        }
        timer_.cancel();
        std::cout << "[virtual_interface] closing windows interface" << std::endl;
    }

    void async_read_packet(std::shared_ptr<clink::core::memory::Block> buffer, 
                           std::function<void(std::error_code, size_t)> callback) override {
        if (stream_handle_.is_open()) {
            // Zero-Copy Read: 直接读取到 Block 的写入位置
            stream_handle_.async_read_some(
                asio::buffer(buffer->write_ptr(), buffer->tailroom()),
                [buffer, callback](const std::error_code& ec, size_t bytes_transferred) {
                    if (!ec) {
                        buffer->commit(bytes_transferred);
                    }
                    callback(ec, bytes_transferred);
                });
        } else {
            // 模拟异步读取：使用定时器延迟回调
            timer_.expires_after(std::chrono::milliseconds(100));
            timer_.async_wait([this, buffer, callback](std::error_code ec) {
                if (ec) {
                    callback(ec, 0);
                    return;
                }
                // 模拟没有数据的情况
                callback({}, 0);
            });
        }
    }

    std::error_code write_packet(const uint8_t* data, size_t size) override {
        if (stream_handle_.is_open()) {
            // TODO: 实现异步写或同步写
            // 这里为了简化接口暂用同步写，或者应该扩展 VirtualInterface 支持 async_write
            // 目前 VirtualInterface 只有同步 write_packet 接口
            // 对于高性能场景，建议扩展为 async_write_packet
            
            // DWORD bytes_written = 0;
            // WriteFile(stream_handle_.native_handle(), data, size, &bytes_written, NULL);
            return {};
        }
        (void)data;
        (void)size;
        return {};
    }

    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return name_; }

private:
    asio::io_context& io_context_;
    asio::steady_timer timer_;
    asio::windows::stream_handle stream_handle_;
    std::string name_;
};

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
