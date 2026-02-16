#pragma once

#include <memory>
#include <string>
#include <vector>
#include <functional>
#include <system_error>

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
     * @brief 设置接收回调
     */
    using ReceiveCallback = std::function<void(const uint8_t* data, size_t size)>;
    virtual void on_receive(ReceiveCallback callback) = 0;

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
