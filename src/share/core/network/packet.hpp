#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <chrono>
#include <cstring>
#include <atomic>
#include <limits>
#include "src/server/core/memory/buffer_pool.hpp"
#include <asio/buffer.hpp>

namespace clink::core::network {

enum class PacketType : uint8_t {
    Data = 0x01,
    Ack = 0x02,
    Heartbeat = 0x03,
    Control = 0x04,
    Sack = 0x05
};

struct PacketCopyStats {
    std::atomic<uint64_t> packets_deserialize_raw{0};
    std::atomic<uint64_t> packets_deserialize_block{0};
    std::atomic<uint64_t> bytes_copied_raw{0};
    std::atomic<uint64_t> bytes_copied_block{0};
    std::atomic<uint64_t> packets_corrupted{0};
    std::atomic<uint64_t> packets_incomplete{0};
};

const PacketCopyStats& packet_copy_stats() noexcept;
void reset_packet_copy_stats() noexcept;

#pragma pack(push, 1)
struct PacketHeader {
    uint8_t type;
    uint8_t flags;
    uint16_t payload_size;
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t checksum;
};
#pragma pack(pop)

constexpr std::size_t kMaxPayloadSize = std::numeric_limits<uint16_t>::max();

struct Packet {
    PacketHeader header{};
    std::shared_ptr<clink::core::memory::Block> block;
    size_t offset = 0;

    Packet() {
        std::memset(&header, 0, sizeof(header));
    }

    explicit Packet(std::shared_ptr<clink::core::memory::Block> b, size_t off = 0)
        : block(std::move(b)), offset(off) {
        std::memset(&header, 0, sizeof(header));
        if (block) {
            const size_t available = (block->size() > offset) ? (block->size() - offset) : 0;
            const size_t capped = std::min<size_t>(available, kMaxPayloadSize);
            header.payload_size = static_cast<uint16_t>(capped);
        }
    }

    void finalize();
    std::vector<uint8_t> serialize() const;
    std::vector<asio::const_buffer> serialize_to_buffers() const;
    static std::unique_ptr<Packet> deserialize(const uint8_t* data, size_t size, bool* out_corrupted = nullptr);
    static std::unique_ptr<Packet> deserialize(std::shared_ptr<clink::core::memory::Block> block, bool* out_corrupted = nullptr);

    uint8_t* payload_data() { return block ? block->begin() + offset : nullptr; }
    const uint8_t* payload_data() const { return block ? block->begin() + offset : nullptr; }
    size_t payload_size() const { return header.payload_size; }
};

struct RetransmissionEntry {
    std::unique_ptr<Packet> packet;
    std::chrono::steady_clock::time_point last_send_time;
    int retry_count{0};
    std::chrono::milliseconds current_timeout;
    bool sent{false};
    uint32_t sack_count{0};
};

} // namespace clink::core::network
