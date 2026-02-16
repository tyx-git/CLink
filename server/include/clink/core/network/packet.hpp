#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <chrono>
#include <cstring>

namespace clink::core::network {

/**
 * @brief 数据包类型
 */
enum class PacketType : uint8_t {
    Data = 0x01,      // 业务数据包
    Ack = 0x02,       // 确认包
    Heartbeat = 0x03, // 心跳包
    Control = 0x04,   // 控制信令
    Sack = 0x05       // 选择性确认包
};

/**
 * @brief 数据包头部结构 (小端对齐)
 * 总计 16 字节
 */
#pragma pack(push, 1)
struct PacketHeader {
    uint8_t type;          // PacketType
    uint8_t flags;         // 标志位 (如是否加密、是否压缩)
    uint16_t payload_size; // 载荷大小
    uint32_t seq_num;      // 序列号
    uint32_t ack_num;      // 确认号
    uint32_t checksum;     // 头部校验和 (可选)
};
#pragma pack(pop)

/**
 * @brief 完整数据包对象
 */
struct Packet {
    PacketHeader header{}; // Zero-initialize header
    std::vector<uint8_t> payload;

    Packet() {
        std::memset(&header, 0, sizeof(header));
    }

    // 辅助方法：序列化
    std::vector<uint8_t> serialize() const;
    
    // 辅助方法：反序列化
    static std::unique_ptr<Packet> deserialize(const uint8_t* data, size_t size);
};

/**
 * @brief 重传条目，用于跟踪未确认的数据包
 */
struct RetransmissionEntry {
    std::unique_ptr<Packet> packet;
    std::chrono::steady_clock::time_point last_send_time;
    int retry_count{0};
    std::chrono::milliseconds current_timeout;
    bool sent{false}; // 是否已经进行过初始发送
    uint32_t sack_count{0}; // 被后续包 SACK 的次数，用于触发早期丢包检测
};

} // namespace clink::core::network
