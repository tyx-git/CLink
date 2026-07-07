#pragma once

#include <asio.hpp>
#include <memory>
#include <optional>
#include <string>

#include "src/share/core/logging/logger.hpp"

// VIP 绑定工具：将会话的出站 socket 绑定到虚拟网卡 IP 地址
// 确保从隧道出去的流量走虚拟网卡对应地址族（IPv4/IPv6）
namespace clink::core::network {

bool should_bind_to_virtual_interface(const std::string& vip);  // 是否需要绑定到 VIF
std::optional<asio::ip::address> parse_bind_address(const std::string& vip, // 从 VIP 字符串解析 bind 地址
    std::shared_ptr<logging::Logger> logger, const std::string& log_prefix);
// 过滤解析结果，只保留与 bind_addr 相同地址族的 endpoint
asio::ip::tcp::resolver::results_type filter_results_for_bind_address(
    const asio::ip::tcp::resolver::results_type& results,
    const asio::ip::address& bind_addr);
// 执行 bind 操作
bool bind_socket_to_virtual_interface(asio::ip::tcp::socket& socket,
    const asio::ip::address& bind_addr,
    std::shared_ptr<logging::Logger> logger, const std::string& log_prefix);

} // namespace clink::core::network
