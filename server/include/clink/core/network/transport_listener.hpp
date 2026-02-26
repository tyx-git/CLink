#pragma once

#include "server/include/clink/core/network/transport_adapter.hpp"
#include <memory>
#include <string>
#include <functional>
#include <system_error>

namespace clink::core::network {

/**
 * @brief 传输监听器接口，用于接收新的连接
 */
class TransportListener {
public:
    virtual ~TransportListener() = default;

    /**
     * @brief 监听器类型 (如 "tcp", "tls")
     */
    virtual std::string_view type() const noexcept = 0;

    /**
     * @brief 开始监听
     * @param endpoint 监听地址 (如 "0.0.0.0:443")
     */
    virtual std::error_code listen(const std::string& endpoint) = 0;

    /**
     * @brief 停止监听
     */
    virtual void stop() = 0;

    /**
     * @brief 设置新连接回调
     */
    using NewConnectionCallback = std::function<void(TransportAdapterPtr adapter)>;
    virtual void on_connection(NewConnectionCallback callback) = 0;
};

using TransportListenerPtr = std::shared_ptr<TransportListener>;

} // namespace clink::core::network
