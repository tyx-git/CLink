#pragma once

#include <asio.hpp>
#include <string>
#include <vector>
#include <system_error>
#include <functional>
#include <memory>
#include <cstdint>

namespace clink::core::network {

/**
 * @brief 虚拟网卡接口抽象，屏蔽平台差异 (Windows TAP-Windows/Wintun, Linux TUN/TAP)
 */
class VirtualInterface {
public:
    virtual ~VirtualInterface() = default;

    /**
     * @brief 打开并配置虚拟网卡
     * @param name 网卡名称 (如 "clink0")
     * @param address IP 地址 (如 "10.0.0.1")
     * @param netmask 子网掩码 (如 "255.255.255.0")
     */
    virtual std::error_code open(const std::string& name, 
                                 const std::string& address, 
                                 const std::string& netmask) = 0;

    /**
     * @brief 关闭网卡
     */
    virtual void close() = 0;

    /**
     * @brief 异步读取一个原始数据包 (IP Packet)
     * @param buffer 目标缓冲区
     * @param callback 读取完成后的回调
     */
    virtual void async_read_packet(std::vector<uint8_t>& buffer, 
                                   std::function<void(std::error_code, size_t)> callback) = 0;

    /**
     * @brief 写入一个原始数据包 (IP Packet)
     */
    virtual std::error_code write_packet(const uint8_t* data, size_t size) = 0;

    /**
     * @brief 获取接口 MTU
     */
    virtual uint32_t mtu() const noexcept = 0;

    /**
     * @brief 获取接口名称
     */
    virtual std::string name() const = 0;
};

using VirtualInterfacePtr = std::unique_ptr<VirtualInterface>;

/**
 * @brief 工厂函数，根据当前操作系统创建合适的虚拟网卡实例
 */
VirtualInterfacePtr create_virtual_interface(asio::io_context& io_context);

}  // namespace clink::core::network
