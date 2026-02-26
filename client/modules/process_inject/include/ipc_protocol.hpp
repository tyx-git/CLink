#pragma once

#include <cstdint>

namespace clink::hook::ipc {

    constexpr const char* PIPE_NAME = "\\\\.\\pipe\\clink-process-ipc";
    constexpr uint32_t IPC_MAGIC = 0x434C4E4B; // CLNK

    enum class PacketType : uint8_t {
        Connect = 1,
        Disconnect = 2,
        DataSend = 3,
        DataRecv = 4
    };

    #pragma pack(push, 1)
    struct PacketHeader {
        uint32_t magic = IPC_MAGIC;
        PacketType type;
        uint64_t socket_id;
        uint32_t length;
    };
    #pragma pack(pop)

} // namespace clink::hook::ipc
