#include "clink/core/network/packet.hpp"
#include <cstring>
#include <algorithm>
#include <asio.hpp>

namespace clink::core::network {

std::vector<uint8_t> Packet::serialize() const {
    std::vector<uint8_t> result;
    size_t p_size = header.payload_size;
    result.resize(sizeof(PacketHeader) + p_size);
    
    PacketHeader* hdr = reinterpret_cast<PacketHeader*>(result.data());
    *hdr = header;
    hdr->payload_size = static_cast<uint16_t>(p_size);
    
    if (p_size > 0 && block) {
        std::memcpy(result.data() + sizeof(PacketHeader), block->begin() + offset, p_size);
    }
    
    return result;
}

std::vector<asio::const_buffer> Packet::serialize_to_buffers() const {
    std::vector<asio::const_buffer> buffers;
    // Note: This points to the member header, which must remain valid until write completes.
    buffers.push_back(asio::buffer(&header, sizeof(PacketHeader)));
    
    if (block && header.payload_size > 0) {
        buffers.push_back(asio::buffer(block->begin() + offset, header.payload_size));
    }
    return buffers;
}

std::unique_ptr<Packet> Packet::deserialize(const uint8_t* data, size_t size) {
    if (size < sizeof(PacketHeader)) return nullptr;
    
    auto packet = std::make_unique<Packet>();
    std::memcpy(&packet->header, data, sizeof(PacketHeader));
    
    if (packet->header.payload_size > size - sizeof(PacketHeader)) {
        // 数据包不完整
        return nullptr;
    }
    
    if (packet->header.payload_size > 0) {
        packet->block = clink::core::memory::BufferPool::instance()->acquire(packet->header.payload_size);
        packet->block->append(data + sizeof(PacketHeader), packet->header.payload_size);
    }
    
    return packet;
}

std::unique_ptr<Packet> Packet::deserialize(std::shared_ptr<clink::core::memory::Block> block) {
    if (!block || block->size() < sizeof(PacketHeader)) return nullptr;

    auto packet = std::make_unique<Packet>();
    // Assume header is at block->begin()
    std::memcpy(&packet->header, block->begin(), sizeof(PacketHeader));
    
    // Validate payload size
    if (packet->header.payload_size > block->size() - sizeof(PacketHeader)) {
        // Incomplete packet in block
        return nullptr;
    }
    
    // Assign block and offset
    if (packet->header.payload_size > 0) {
        packet->block = block;
        packet->offset = sizeof(PacketHeader); // Payload starts after header
    }
    
    return packet;
}

} // namespace clink::core::network
