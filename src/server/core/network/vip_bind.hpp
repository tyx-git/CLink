#pragma once

#include <asio.hpp>
#include <memory>
#include <optional>
#include <string>

#include "src/share/core/logging/logger.hpp"

namespace clink::core::network {

bool should_bind_to_virtual_interface(const std::string& vip);

std::optional<asio::ip::address> parse_bind_address(const std::string& vip,
                                                     std::shared_ptr<logging::Logger> logger,
                                                     const std::string& log_prefix);

asio::ip::tcp::resolver::results_type filter_results_for_bind_address(
    const asio::ip::tcp::resolver::results_type& results,
    const asio::ip::address& bind_addr);

bool bind_socket_to_virtual_interface(asio::ip::tcp::socket& socket,
                                      const asio::ip::address& bind_addr,
                                      std::shared_ptr<logging::Logger> logger,
                                      const std::string& log_prefix);

} // namespace clink::core::network
