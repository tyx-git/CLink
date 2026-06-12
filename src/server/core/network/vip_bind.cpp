#include "src/server/core/network/vip_bind.hpp"

#include <cstdlib>
#include <vector>

namespace clink::core::network {

bool should_bind_to_virtual_interface(const std::string& vip) {
    if (vip.empty()) {
        return false;
    }

    if (const char* disable_vif = std::getenv("CLINK_DISABLE_VIF")) {
        if (std::string(disable_vif) == "1") {
            return false;
        }
    }

    return true;
}

std::optional<asio::ip::address> parse_bind_address(const std::string& vip,
                                                     std::shared_ptr<logging::Logger> logger,
                                                     const std::string& log_prefix) {
    if (!should_bind_to_virtual_interface(vip)) {
        return std::nullopt;
    }

    asio::error_code ec;
    auto bind_addr = asio::ip::make_address(vip, ec);
    if (ec) {
        if (logger) {
            logger->warn(log_prefix + " invalid VIP address " + vip + ": " + ec.message());
        }
        return std::nullopt;
    }

    return bind_addr;
}

asio::ip::tcp::resolver::results_type filter_results_for_bind_address(
    const asio::ip::tcp::resolver::results_type& results,
    const asio::ip::address& bind_addr) {
    std::vector<asio::ip::tcp::endpoint> endpoints;
    std::string host_name;
    std::string service_name;
    for (const auto& entry : results) {
        const auto target_addr = entry.endpoint().address();
        if ((bind_addr.is_v4() && target_addr.is_v4()) ||
            (bind_addr.is_v6() && target_addr.is_v6())) {
            if (endpoints.empty()) {
                host_name = entry.host_name();
                service_name = entry.service_name();
            }
            endpoints.push_back(entry.endpoint());
        }
    }
    return asio::ip::tcp::resolver::results_type::create(
        endpoints.begin(), endpoints.end(), host_name, service_name);
}

bool bind_socket_to_virtual_interface(asio::ip::tcp::socket& socket,
                                      const asio::ip::address& bind_addr,
                                      std::shared_ptr<logging::Logger> logger,
                                      const std::string& log_prefix) {
    asio::error_code open_ec;
    asio::error_code bind_ec;
    const auto protocol = bind_addr.is_v4() ? asio::ip::tcp::v4() : asio::ip::tcp::v6();

    if (socket.is_open()) {
        asio::error_code close_ec;
        socket.close(close_ec);
    }

    socket.open(protocol, open_ec);
    if (open_ec) {
        if (logger) {
            logger->warn(log_prefix + " failed to open VIP-bound socket for " + bind_addr.to_string() + ": " + open_ec.message());
        }
        return false;
    }

    socket.bind(asio::ip::tcp::endpoint(bind_addr, 0), bind_ec);
    if (bind_ec) {
        if (logger) {
            logger->warn(log_prefix + " failed to bind to VIP " + bind_addr.to_string() + ": " + bind_ec.message());
        }
        asio::error_code close_ec;
        socket.close(close_ec);
        return false;
    }

    return true;
}

} // namespace clink::core::network
