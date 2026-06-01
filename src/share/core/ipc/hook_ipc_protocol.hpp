#pragma once

#include <cstdint>

namespace clink::hook::ipc {

    constexpr const char* PIPE_NAME = "\\\\.\\pipe\\clink-process-ipc";
    constexpr uint32_t IPC_MAGIC = 0x434C4E4B; // CLNK

    enum class PacketType : uint8_t {
        Connect = 1,
        Disconnect = 2,
        DataSend = 3,
        DataRecv = 4,
        Log = 5
    };

    enum class LogLevel : uint8_t {
        Debug = 0,
        Info = 1,
        Warn = 2,
        Error = 3
    };

    constexpr uint32_t kMaxPacketBody = 4 * 1024 * 1024; // 4MB hard limit

    #pragma pack(push, 1)
    struct PacketHeader {
        uint32_t magic = IPC_MAGIC;
        PacketType type;
        uint64_t socket_id;
        uint32_t length;
    };
    #pragma pack(pop)

} // namespace clink::hook::ipc
