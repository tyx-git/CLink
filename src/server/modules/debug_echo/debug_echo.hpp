#pragma once
// Debug Echo Module (v1.3.0)
// Simple TCP echo server for tunnel data path validation.
// Clients send data through the SOCKS proxy + tunnel to the server's echo port.

#include <asio.hpp>
#include <memory>
#include <atomic>
#include <vector>
#include <string>

namespace clink::debug {

// Hardcoded test messages for debug communication validation
inline constexpr const char* kClientA_Id = "DEBUG_CLIENT_A";
inline constexpr const char* kClientB_Id = "DEBUG_CLIENT_B";

inline const char* get_test_message(int index) {
    static const char* msgs[] = {
        "CLINK_DEBUG_PING_001: Hello from ",
        "CLINK_DEBUG_PING_002: Hello from ",
        "CLINK_DEBUG_DATA_001: Test payload 64 bytes ................................",
        "CLINK_DEBUG_DATA_002: Test payload 128 bytes ................................................................................",
        "CLINK_DEBUG_PONG_001: Ack from ",
        "CLINK_DEBUG_PONG_002: Ack from ",
    };
    return (index >= 0 && index < 6) ? msgs[index] : msgs[0];
}

// TCP echo server that echoes back received data with a version tag.
class DebugEchoServer : public std::enable_shared_from_this<DebugEchoServer> {
public:
    explicit DebugEchoServer(asio::io_context& io, uint16_t port = 9999);
    ~DebugEchoServer();
    void start();
    void stop();
    [[nodiscard]] bool running() const noexcept { return running_.load(); }
    [[nodiscard]] uint16_t port() const noexcept { return port_; }
private:
    void do_accept();
    void handle_session(std::shared_ptr<asio::ip::tcp::socket> sock);
    asio::io_context& io_;
    asio::ip::tcp::acceptor acceptor_;
    uint16_t port_;
    std::atomic<bool> running_{false};
};

} // namespace clink::debug
