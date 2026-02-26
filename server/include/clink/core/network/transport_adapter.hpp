#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <system_error>
#include "server/include/clink/core/memory/buffer_pool.hpp"
#include "server/include/clink/core/network/packet.hpp"

namespace clink::core::network {

/**
 * @brief 传输适配器接口，定义底层通信协议的通用行为
 */
class TransportAdapter {
public:
    virtual ~TransportAdapter() = default;

    /**
     * @brief 适配器类型名称 (如 "tls", "quic")
     */
    virtual std::string_view type() const noexcept = 0;

    /**
     * @brief 启动监听或连接
     * @param endpoint 监听地址或连接目标 (如 "0.0.0.0:443" 或 "server.com:443")
     */
    virtual std::error_code start(const std::string& endpoint) = 0;

    /**
     * @brief 停止传输服务
     */
    virtual void stop() = 0;

    /**
     * @brief 发送原始数据包
     * @param data 数据缓冲区
     * @param size 数据大小
     */
    virtual std::error_code send(const uint8_t* data, size_t size) = 0;

    /**
     * @brief 发送零拷贝数据包
     * @param packet 数据包对象
     */
    virtual std::error_code send(const Packet& packet) {
        // Default fallback to copying
        // Make a local copy to finalize checksum
        Packet temp = packet;
        temp.finalize();

        auto buffers = temp.serialize_to_buffers();
        std::vector<uint8_t> temp_buffer;
        size_t total_size = 0;
        for (const auto& buf : buffers) {
            total_size += buf.size();
        }
        temp_buffer.reserve(total_size);
        for (const auto& buf : buffers) {
            const uint8_t* p = static_cast<const uint8_t*>(buf.data());
            temp_buffer.insert(temp_buffer.end(), p, p + buf.size());
        }
        return send(temp_buffer.data(), temp_buffer.size());
    }

    /**
     * @brief 设置接收回调 (Legacy)
     */
    using ReceiveCallback = std::function<void(const uint8_t* data, size_t size)>;
    virtual void on_receive(ReceiveCallback callback) = 0;

    /**
     * @brief 设置零拷贝接收回调
     */
    using ZeroCopyReceiveCallback = std::function<void(std::shared_ptr<clink::core::memory::Block> block)>;
    virtual void on_receive(ZeroCopyReceiveCallback callback) = 0;

    /**
     * @brief 获取当前连接状态
     */
    virtual bool is_connected() const noexcept = 0;
    /**
     * @brief 获取远端端点信息 (如 IP:Port)
     */
    virtual std::string_view remote_endpoint() const noexcept = 0;
};

using TransportAdapterPtr = std::shared_ptr<TransportAdapter>;

}  // namespace clink::core::network
