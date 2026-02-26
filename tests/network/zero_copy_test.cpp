#include <catch2/catch_test_macros.hpp>
#include "clink/core/network/session_manager_impl.hpp"
#include "clink/core/network/transport_adapter.hpp"
#include "clink/core/logging/logger.hpp"
#include "clink/core/memory/buffer_pool.hpp"
#include <iostream>
#include <cstring>

using namespace clink::core::network;

// Instrumented Mock Virtual Interface
class InstrumentedVirtualInterface : public VirtualInterface {
public:
    using VirtualInterface::write_packet;
    std::error_code open(const std::string&, const std::string&, const std::string&) override { return {}; }
    void close() override {}
    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return "instrumented0"; }

    void async_read_packet(std::shared_ptr<clink::core::memory::Block> buffer, std::function<void(std::error_code, size_t)> callback) override {
        read_callback_ = callback;
        current_read_buffer_ = buffer;
    }

    std::error_code write_packet(const uint8_t* data, size_t size) override {
        last_written_data_ptr_ = data;
        last_written_size_ = size;
        return {};
    }

    // Helper to simulate read completion with a specific block
    void complete_read(size_t bytes_transferred) {
        if (read_callback_) {
            read_callback_({}, bytes_transferred);
        }
    }

    std::shared_ptr<clink::core::memory::Block> current_read_buffer_;
    std::function<void(std::error_code, size_t)> read_callback_;
    const uint8_t* last_written_data_ptr_{nullptr};
    size_t last_written_size_{0};
};

// Instrumented Mock Transport Adapter
class InstrumentedTransportAdapter : public TransportAdapter {
public:
    std::string_view type() const noexcept override { return "instrumented"; }
    std::error_code start(const std::string&) override { return {}; }
    void stop() override { running_ = false; }
    bool is_connected() const noexcept override { return running_; }
    std::string_view remote_endpoint() const noexcept override { return "mock-remote"; }

    std::error_code send(const uint8_t*, size_t) override { return {}; }
    
    std::error_code send(const Packet& packet) override {
        last_sent_packet_block_ = packet.block;
        return {};
    }

    void on_receive(ReceiveCallback) override {}
    void on_receive(ZeroCopyReceiveCallback callback) override {
        zero_copy_callback_ = callback;
    }

    void simulate_receive(std::shared_ptr<clink::core::memory::Block> block) {
        if (zero_copy_callback_) {
            zero_copy_callback_(block);
        }
    }

    bool running_{true};
    std::shared_ptr<clink::core::memory::Block> last_sent_packet_block_;
    ZeroCopyReceiveCallback zero_copy_callback_;
};

// Test Session Manager that exposes internal components
class TestZeroCopySessionManager : public DefaultSessionManager {
public:
    using DefaultSessionManager::DefaultSessionManager;
    
    // Raw pointer to verify state, ownership is held by unique_ptr inside SessionManager
    InstrumentedVirtualInterface* vif_raw_{nullptr};

protected:
    VirtualInterfacePtr create_interface() override {
        auto ptr = std::make_unique<InstrumentedVirtualInterface>();
        vif_raw_ = ptr.get();
        return ptr;
    }
};

TEST_CASE("Zero Copy Data Path Verification", "[network][zerocopy]") {
    asio::io_context io_context;
    auto logger = std::make_shared<clink::core::logging::Logger>("ZeroCopyTest");
    auto session_manager = std::make_shared<TestZeroCopySessionManager>(io_context, logger);
    
    REQUIRE(session_manager->initialize().value() == 0);
    
    auto adapter = std::make_shared<InstrumentedTransportAdapter>();
    session_manager->create_session(adapter);

    SECTION("TUN Read -> Network Send (Zero Copy)") {
        // 1. SessionManager calls async_read_packet, providing a buffer.
        // We need to wait for start_tun_read to be called. initialize() calls it.
        
        REQUIRE(session_manager->vif_raw_ != nullptr);
        // It might take an event loop cycle? No, async_read_packet is called synchronously in start_tun_read
        REQUIRE(session_manager->vif_raw_->current_read_buffer_ != nullptr);
        
        auto buffer = session_manager->vif_raw_->current_read_buffer_;
        
        // 2. Simulate data arriving in TUN
        // We write some data into the buffer directly (simulating kernel write)
        const char* test_data = "ZeroCopyPayload";
        size_t len = strlen(test_data);
        buffer->append(reinterpret_cast<const uint8_t*>(test_data), len);
        
        // 3. Complete the read
        session_manager->vif_raw_->complete_read(len);
        
        // 4. Verify TransportAdapter received the SAME buffer instance
        REQUIRE(adapter->last_sent_packet_block_ != nullptr);
        CHECK(adapter->last_sent_packet_block_.get() == buffer.get());
        CHECK(adapter->last_sent_packet_block_->size() == len);
        CHECK(memcmp(adapter->last_sent_packet_block_->begin(), test_data, len) == 0);
    }

    SECTION("Network Receive -> TUN Write (Zero Copy View)") {
        // 1. Create a block in TransportAdapter (simulating network receive)
        auto block = clink::core::memory::BufferPool::instance()->acquire(1024);
        
        // Prepare Packet with Checksum
        Packet p;
        p.header.type = static_cast<uint8_t>(PacketType::Data);
        p.header.seq_num = 100;
        p.header.ack_num = 0;
        
        const char* payload = "NetworkData";
        size_t payload_len = strlen(payload);
        
        // Setup payload block for serialize
        auto p_block = clink::core::memory::BufferPool::instance()->acquire(payload_len);
        memcpy(p_block->write_ptr(), payload, payload_len);
        p_block->commit(payload_len);
        p.block = p_block;
        p.header.payload_size = static_cast<uint16_t>(payload_len);
        p.offset = 0;
        
        std::vector<uint8_t> serialized = p.serialize();
        
        // Copy serialized data (header + payload with checksum) into receive block
        memcpy(block->write_ptr(), serialized.data(), serialized.size());
        block->commit(serialized.size());
        
        // 2. Pass block to SessionManager
        adapter->simulate_receive(block);
        
        // 3. Verify VirtualInterface received a pointer INSIDE this block
        REQUIRE(session_manager->vif_raw_->last_written_data_ptr_ != nullptr);
        
        // Calculate expected pointer address
        const uint8_t* expected_ptr = block->begin() + sizeof(PacketHeader);
        CHECK(session_manager->vif_raw_->last_written_data_ptr_ == expected_ptr);
        CHECK(session_manager->vif_raw_->last_written_size_ == p.header.payload_size);
    }

    session_manager->shutdown();
}
