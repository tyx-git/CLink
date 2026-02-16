#include "clink/core/network/packet.hpp"
#include <cstring>
#include <algorithm>

namespace clink::core::network {

std::vector<uint8_t> Packet::serialize() const {
    std::vector<uint8_t> result;
    result.resize(sizeof(PacketHeader) + payload.size());
    
    PacketHeader* hdr = reinterpret_cast<PacketHeader*>(result.data());
    *hdr = header;
    hdr->payload_size = static_cast<uint16_t>(payload.size());
    
    if (!payload.empty()) {
        std::memcpy(result.data() + sizeof(PacketHeader), payload.data(), payload.size());
    }
    
    return result;
}

std::unique_ptr<Packet> Packet::deserialize(const uint8_t* data, size_t size) {
    if (size < sizeof(PacketHeader)) return nullptr;
    
    auto packet = std::make_unique<Packet>();
    std::memcpy(&packet->header, data, sizeof(PacketHeader));
    
    if (packet->header.payload_size > size - sizeof(PacketHeader)) {
        // 数据包不完整
        return nullptr;
    }
    
    packet->payload.resize(packet->header.payload_size);
    if (packet->header.payload_size > 0) {
        std::memcpy(packet->payload.data(), data + sizeof(PacketHeader), packet->header.payload_size);
    }
    
    return packet;
}

} // namespace clink::core::network
