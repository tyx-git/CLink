#include "src/share/core/network/packet.hpp"
#include <cstring>
#include <algorithm>
#include <bit>
#include <asio.hpp>

namespace clink::core::network {

namespace {
    PacketCopyStats g_packet_copy_stats;

    void parse_header_view(const uint8_t* data, PacketHeader& out) {
        out.type = data[0];
        out.flags = data[1];
        out.payload_size = static_cast<uint16_t>(static_cast<uint16_t>(data[2]) | (static_cast<uint16_t>(data[3]) << 8));
        out.seq_num = static_cast<uint32_t>(data[4]) |
                      (static_cast<uint32_t>(data[5]) << 8) |
                      (static_cast<uint32_t>(data[6]) << 16) |
                      (static_cast<uint32_t>(data[7]) << 24);
        out.ack_num = static_cast<uint32_t>(data[8]) |
                      (static_cast<uint32_t>(data[9]) << 8) |
                      (static_cast<uint32_t>(data[10]) << 16) |
                      (static_cast<uint32_t>(data[11]) << 24);
        out.checksum = static_cast<uint32_t>(data[12]) |
                       (static_cast<uint32_t>(data[13]) << 8) |
                       (static_cast<uint32_t>(data[14]) << 16) |
                       (static_cast<uint32_t>(data[15]) << 24);
    }

    uint32_t calculate_crc32(const uint8_t* data, size_t length, uint32_t previous_crc = 0) {
        uint32_t crc = ~previous_crc;
        for (size_t i = 0; i < length; ++i) {
            crc ^= data[i];
            for (int j = 0; j < 8; ++j) {
                if (crc & 1)
                    crc = (crc >> 1) ^ 0xEDB88320;
                else
                    crc = crc >> 1;
            }
        }
        return ~crc;
    }
}

const PacketCopyStats& packet_copy_stats() noexcept {
    return g_packet_copy_stats;
}

void reset_packet_copy_stats() noexcept {
    g_packet_copy_stats.packets_deserialize_raw.store(0, std::memory_order_relaxed);
    g_packet_copy_stats.packets_deserialize_block.store(0, std::memory_order_relaxed);
    g_packet_copy_stats.bytes_copied_raw.store(0, std::memory_order_relaxed);
    g_packet_copy_stats.bytes_copied_block.store(0, std::memory_order_relaxed);
    g_packet_copy_stats.packets_corrupted.store(0, std::memory_order_relaxed);
    g_packet_copy_stats.packets_incomplete.store(0, std::memory_order_relaxed);
}

void Packet::finalize() {
    header.checksum = 0;
    uint32_t crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&header), sizeof(PacketHeader));
    if (block && header.payload_size > 0) {
        crc = calculate_crc32(block->begin() + offset, header.payload_size, crc);
    }
    header.checksum = crc;
}

std::vector<uint8_t> Packet::serialize() const {
    std::vector<uint8_t> result;
    size_t p_size = header.payload_size;
    result.resize(sizeof(PacketHeader) + p_size);

    PacketHeader* hdr = reinterpret_cast<PacketHeader*>(result.data());
    *hdr = header;
    hdr->payload_size = static_cast<uint16_t>(p_size);
    hdr->checksum = 0;

    if (p_size > 0 && block) {
        std::memcpy(result.data() + sizeof(PacketHeader), block->begin() + offset, p_size);
    }

    hdr->checksum = calculate_crc32(result.data(), result.size());
    return result;
}

std::vector<asio::const_buffer> Packet::serialize_to_buffers() const {
    std::vector<asio::const_buffer> buffers;
    buffers.reserve(2);
    buffers.push_back(asio::buffer(&header, sizeof(PacketHeader)));

    if (block && header.payload_size > 0) {
        buffers.push_back(asio::buffer(block->begin() + offset, header.payload_size));
    }
    return buffers;
}

std::unique_ptr<Packet> Packet::deserialize(const uint8_t* data, size_t size, bool* out_corrupted) {
    if (out_corrupted) *out_corrupted = false;
    if (size < sizeof(PacketHeader)) {
        g_packet_copy_stats.packets_incomplete.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    g_packet_copy_stats.packets_deserialize_raw.fetch_add(1, std::memory_order_relaxed);

    auto packet = std::make_unique<Packet>();
    parse_header_view(data, packet->header);

    if (packet->header.payload_size > kMaxPayloadSize) {
        g_packet_copy_stats.packets_corrupted.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    if (packet->header.payload_size > size - sizeof(PacketHeader)) {
        g_packet_copy_stats.packets_incomplete.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    uint32_t received_checksum = packet->header.checksum;
    packet->header.checksum = 0;
    uint32_t crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&packet->header), sizeof(PacketHeader));
    if (packet->header.payload_size > 0) {
        crc = calculate_crc32(data + sizeof(PacketHeader), packet->header.payload_size, crc);
    }
    if (crc != received_checksum) {
        if (out_corrupted) *out_corrupted = true;
        g_packet_copy_stats.packets_corrupted.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    packet->header.checksum = received_checksum;
    if (packet->header.payload_size > 0) {
        packet->block = clink::core::memory::BufferPool::instance()->acquire(packet->header.payload_size);
        packet->block->append(data + sizeof(PacketHeader), packet->header.payload_size);
        g_packet_copy_stats.bytes_copied_raw.fetch_add(packet->header.payload_size, std::memory_order_relaxed);
    }
    return packet;
}

std::unique_ptr<Packet> Packet::deserialize(std::shared_ptr<clink::core::memory::Block> block, bool* out_corrupted) {
    if (out_corrupted) *out_corrupted = false;
    if (!block || block->size() < sizeof(PacketHeader)) {
        g_packet_copy_stats.packets_incomplete.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    g_packet_copy_stats.packets_deserialize_block.fetch_add(1, std::memory_order_relaxed);

    auto packet = std::make_unique<Packet>();
    parse_header_view(block->begin(), packet->header);

    if (packet->header.payload_size > kMaxPayloadSize) {
        g_packet_copy_stats.packets_corrupted.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }
    if (packet->header.payload_size > block->size() - sizeof(PacketHeader)) {
        g_packet_copy_stats.packets_incomplete.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    uint32_t received_checksum = packet->header.checksum;
    packet->header.checksum = 0;
    uint32_t crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&packet->header), sizeof(PacketHeader));
    if (packet->header.payload_size > 0) {
        crc = calculate_crc32(block->begin() + sizeof(PacketHeader), packet->header.payload_size, crc);
    }
    if (crc != received_checksum) {
        if (out_corrupted) *out_corrupted = true;
        g_packet_copy_stats.packets_corrupted.fetch_add(1, std::memory_order_relaxed);
        return nullptr;
    }

    packet->header.checksum = received_checksum;
    if (packet->header.payload_size > 0) {
        packet->block = block;
        packet->offset = sizeof(PacketHeader);
    }
    return packet;
}

} // namespace clink::core::network
