#pragma once

#include <cstdint>

// 进程注入数据管道协议：Hook DLL ↔ ProcessManager 之间的二进制帧协议
// 与控制面 IPC（clink-ipc）不同，这条管道传的是原始 Winsock 流量
namespace clink::hook::ipc {

    constexpr const char* PIPE_NAME = "\\\\.\\pipe\\clink-process-ipc"; // 管道名
    constexpr uint32_t IPC_MAGIC = 0x434C4E4B; // CLNK 魔数，用于帧校验

    // 数据包类型
    enum class PacketType : uint8_t {
        Connect = 1,    // 目标进程调用了 connect()
        Disconnect = 2, // 目标进程调用了 closesocket()
        DataSend = 3,   // 目标进程调用了 send()（上行数据）
        DataRecv = 4,   // PM 转发回包（下行数据）
        Log = 5         // 日志消息
    };

    enum class LogLevel : uint8_t {
        Debug = 0,
        Info = 1,
        Warn = 2,
        Error = 3
    };

    constexpr uint32_t kMaxPacketBody = 4 * 1024 * 1024; // 单包 body 上限 4MB（安全防护）

    // PacketHeader：17 字节固定长度，二进制紧凑打包
    #pragma pack(push, 1)
    struct PacketHeader {
        uint32_t magic = IPC_MAGIC;   // 魔数 0x434C4E4B
        PacketType type;               // 包类型
        uint64_t socket_id;            // 原始 SOCKET 句柄值（用作会话标识）
        uint32_t length;               // body 长度（0 表示无 body）
    };
    #pragma pack(pop)

} // namespace clink::hook::ipc
