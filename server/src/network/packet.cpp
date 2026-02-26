#include "server/include/clink/core/network/packet.hpp"
#include <cstring>
#include <algorithm>
#include <asio.hpp>

namespace clink::core::network {

namespace {
    // Simple CRC32 implementation
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

void Packet::finalize() {
    // Reset checksum to 0 for calculation
    header.checksum = 0;
    
    // Calculate checksum over header
    uint32_t crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&header), sizeof(PacketHeader));
    
    // Calculate checksum over payload if present
    if (block && header.payload_size > 0) {
        // Use the incremental CRC calculation
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
    hdr->checksum = 0; // Reset checksum for calculation

    if (p_size > 0 && block) {
        std::memcpy(result.data() + sizeof(PacketHeader), block->begin() + offset, p_size);
    }
    
    // Calculate checksum over the entire packet (header + payload)
    // Note: header.checksum is 0 during calculation
    hdr->checksum = calculate_crc32(result.data(), result.size());
    
    return result;
}

std::vector<asio::const_buffer> Packet::serialize_to_buffers() const {
    // Zero-copy serialization
    // WARNING: finalize() MUST be called before this if you want a valid checksum!
    
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
    if (size < sizeof(PacketHeader)) return nullptr;
    
    auto packet = std::make_unique<Packet>();
    std::memcpy(&packet->header, data, sizeof(PacketHeader));
    
    if (packet->header.payload_size > size - sizeof(PacketHeader)) {
        // Incomplete
        return nullptr;
    }

    // Verify Checksum
    uint32_t received_checksum = packet->header.checksum;
    packet->header.checksum = 0; // Clear for calculation
    
    // Calculate expected
    // Header
    uint32_t crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&packet->header), sizeof(PacketHeader));
    // Payload
    if (packet->header.payload_size > 0) {
        crc = ~crc;
        const uint8_t* p = data + sizeof(PacketHeader);
        size_t len = packet->header.payload_size;
        for (size_t i = 0; i < len; ++i) {
            crc ^= p[i];
            for (int j = 0; j < 8; ++j) {
                if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
                else crc = crc >> 1;
            }
        }
        crc = ~crc;
    }
    
    if (crc != received_checksum) {
        if (out_corrupted) *out_corrupted = true;
        return nullptr;
    }
    
    // Restore checksum (optional)
    packet->header.checksum = received_checksum;
    
    if (packet->header.payload_size > 0) {
        packet->block = clink::core::memory::BufferPool::instance()->acquire(packet->header.payload_size);
        packet->block->append(data + sizeof(PacketHeader), packet->header.payload_size);
    }
    
    return packet;
}

std::unique_ptr<Packet> Packet::deserialize(std::shared_ptr<clink::core::memory::Block> block, bool* out_corrupted) {
    if (out_corrupted) *out_corrupted = false;
    if (!block || block->size() < sizeof(PacketHeader)) return nullptr;

    auto packet = std::make_unique<Packet>();
    // Assume header is at block->begin()
    std::memcpy(&packet->header, block->begin(), sizeof(PacketHeader));
    
    // Validate payload size
    if (packet->header.payload_size > block->size() - sizeof(PacketHeader)) {
        // Incomplete packet in block
        return nullptr;
    }
    
    // Verify Checksum
    uint32_t received_checksum = packet->header.checksum;
    packet->header.checksum = 0;
    
    uint32_t crc = calculate_crc32(reinterpret_cast<const uint8_t*>(&packet->header), sizeof(PacketHeader));
    if (packet->header.payload_size > 0) {
        crc = ~crc;
        const uint8_t* p = block->begin() + sizeof(PacketHeader);
        size_t len = packet->header.payload_size;
        for (size_t i = 0; i < len; ++i) {
            crc ^= p[i];
            for (int j = 0; j < 8; ++j) {
                if (crc & 1) crc = (crc >> 1) ^ 0xEDB88320;
                else crc = crc >> 1;
            }
        }
        crc = ~crc;
    }
    
    if (crc != received_checksum) {
        if (out_corrupted) *out_corrupted = true;
        return nullptr;
    }
    
    packet->header.checksum = received_checksum;

    // Assign block and offset
    if (packet->header.payload_size > 0) {
        packet->block = block;
        packet->offset = sizeof(PacketHeader); // Payload starts after header
    }
    
    return packet;
}

} // namespace clink::core::network
