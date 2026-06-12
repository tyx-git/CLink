#include <catch2/catch_test_macros.hpp>

#include "src/server/core/network/vip_bind.hpp"

#include <asio.hpp>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

namespace {
class ScopedEnvVar {
public:
    ScopedEnvVar(const char* name, const char* value) : name_(name) {
#if defined(_WIN32)
        const char* existing = std::getenv(name);
        if (existing) old_value_ = existing;
        env_buf_ = name_ + "=" + value;
        _putenv(env_buf_->c_str());
#else
        if (const char* existing = std::getenv(name)) old_value_ = existing;
        setenv(name, value, 1);
#endif
    }

    ~ScopedEnvVar() {
#if defined(_WIN32)
        env_buf_ = old_value_ ? (name_ + "=" + *old_value_) : (name_ + "=");
        _putenv(env_buf_->c_str());
#else
        if (old_value_) setenv(name_.c_str(), old_value_->c_str(), 1);
        else unsetenv(name_.c_str());
#endif
    }

private:
    std::string name_;
    std::optional<std::string> old_value_;
    std::optional<std::string> env_buf_;
};
}

TEST_CASE("VIP bind is disabled by environment", "[network][vip]") {
    ScopedEnvVar env("CLINK_DISABLE_VIF", "1");
    CHECK_FALSE(clink::core::network::should_bind_to_virtual_interface("10.8.0.1"));
}

TEST_CASE("VIP bind requires a non-empty address", "[network][vip]") {
    ScopedEnvVar env("CLINK_DISABLE_VIF", "0");
    CHECK_FALSE(clink::core::network::should_bind_to_virtual_interface(""));
    CHECK(clink::core::network::should_bind_to_virtual_interface("10.8.0.1"));
}

TEST_CASE("VIP endpoint filtering keeps only matching address family", "[network][vip]") {
    std::vector<asio::ip::tcp::endpoint> endpoints{
        asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), 80),
        asio::ip::tcp::endpoint(asio::ip::address_v6::loopback(), 80),
    };
    const auto mixed = asio::ip::tcp::resolver::results_type::create(
        endpoints.begin(), endpoints.end(), "localhost", "80");

    auto ipv4_only = clink::core::network::filter_results_for_bind_address(mixed, asio::ip::address_v4::loopback());
    REQUIRE_FALSE(ipv4_only.empty());
    for (const auto& entry : ipv4_only) {
        CHECK(entry.endpoint().address().is_v4());
    }

    auto ipv6_only = clink::core::network::filter_results_for_bind_address(mixed, asio::ip::address_v6::loopback());
    REQUIRE_FALSE(ipv6_only.empty());
    for (const auto& entry : ipv6_only) {
        CHECK(entry.endpoint().address().is_v6());
    }
}
