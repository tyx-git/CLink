#pragma once

#include <asio.hpp>
#include <string>
#include <vector>
#include <system_error>
#include <functional>
#include <memory>
#include <cstdint>
#include "src/server/core/memory/buffer_pool.hpp"
#include "src/share/core/logging/logger.hpp"

namespace clink::core::network {

// 虚拟网卡接口抽象：屏蔽 Windows Wintun 与 Linux TUN 的平台差异
class VirtualInterface {
public:
    virtual ~VirtualInterface() = default;

    /**
     * @brief 打开并配置虚拟网卡
     * @param name 网卡名称 (如 "clink0")
     * @param address IP 地址 (如 "10.0.0.1")
     * @param netmask 子网掩码 (如 "255.255.255.0")
     */
    virtual std::error_code open(const std::string& name,  // 打开并配置虚拟网卡
                                 const std::string& address,  // IP 地址
                                 const std::string& netmask) = 0; // 子网掩码
    virtual void close() = 0;                                          // 关闭网卡
    virtual void async_read_packet(                                     // 异步读一个 IP 包（从虚拟网卡到隧道）
        std::shared_ptr<clink::core::memory::Block> buffer, 
        std::function<void(std::error_code, size_t)> callback) = 0;
    virtual std::error_code write_packet(const uint8_t* data, size_t size) = 0; // 写入 IP 包（从隧道到虚拟网卡）
    virtual std::error_code write_packet(const clink::core::memory::Block& block) { // Block 版本
        return write_packet(block.begin(), block.size());
    }

    /**
     * @brief 设置日志句柄 (平台可忽略)
     */
    virtual void set_logger(std::shared_ptr<clink::core::logging::Logger> /*logger*/) {}

    /**
     * @brief 启用/禁用零拷贝优化 (平台可忽略)
     */
    virtual void set_zero_copy_enabled(bool /*enabled*/) {}

    /**
     * @brief 获取接口 MTU
     */
    virtual uint32_t mtu() const noexcept = 0;  // 接口 MTU
    virtual std::string name() const = 0;         // 接口名称
};

using VirtualInterfacePtr = std::unique_ptr<VirtualInterface>;

/**
 * @brief 工厂函数，根据当前操作系统创建合适的虚拟网卡实例
 */
VirtualInterfacePtr create_virtual_interface(asio::io_context& io_context);

}  // namespace clink::core::network
