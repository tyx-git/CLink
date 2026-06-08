#include <catch2/catch_test_macros.hpp>

#include "src/share/core/ipc/ipc.hpp"

#include <asio.hpp>
#include <filesystem>
#include <string>

TEST_CASE("async linux ipc server starts when owned through factory unique_ptr", "[ipc]") {
#ifndef _WIN32
    asio::io_context io;
    const auto socket_path = std::filesystem::temp_directory_path() / "clink-async-ipc-start-test.sock";
    std::filesystem::remove(socket_path);

    auto server = clink::core::ipc::create_server(io, nullptr);

    REQUIRE_NOTHROW(server->start(socket_path.string()));
    server->stop();

    {
        auto server = clink::core::ipc::create_server(io, nullptr);
        REQUIRE_NOTHROW(server->start(socket_path.string()));
    }

    std::filesystem::remove(socket_path);
#else
    SUCCEED("Linux async IPC server test is not applicable on Windows");
#endif
}
