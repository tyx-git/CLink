#include <catch2/catch_all.hpp>
#include "clink/core/network/session_manager_impl.hpp"
#include "clink/core/network/transport_adapter.hpp"
#include "clink/core/logging/logger.hpp"
#include <deque>

using namespace clink::core::network;

class MockVirtualInterface : public VirtualInterface {
public:
    std::error_code open(const std::string& name, const std::string& address, const std::string& netmask) override {
        return {};
    }
    void close() override {}
    void async_read_packet(std::vector<uint8_t>& buffer, std::function<void(std::error_code, size_t)> callback) override {
        read_callback_ = callback;
        buffer_ptr_ = &buffer;
    }
    std::error_code write_packet(const uint8_t* data, size_t size) override {
        written_packets_.emplace_back(data, data + size);
        return {};
    }
    uint32_t mtu() const noexcept override { return 1500; }
    std::string name() const override { return "mock0"; }

    void simulate_packet(const std::vector<uint8_t>& data) {
        if (read_callback_ && buffer_ptr_) {
            *buffer_ptr_ = data;
            read_callback_({}, data.size());
        }
    }

    std::function<void(std::error_code, size_t)> read_callback_;
    std::vector<uint8_t>* buffer_ptr_{nullptr};
    std::deque<std::vector<uint8_t>> written_packets_;
};

class MockTransportAdapter : public TransportAdapter {
public:
    std::string_view type() const noexcept override { return "mock"; }
    std::error_code start(const std::string& endpoint) override { return {}; }
    void stop() override { running_ = false; }
    std::error_code send(const uint8_t* data, size_t size) override {
        sent_data_.emplace_back(data, data + size);
        return {};
    }
    void on_receive(ReceiveCallback callback) override {
        receive_callback_ = callback;
    }
    bool is_connected() const noexcept override { return running_; }
    std::string_view remote_endpoint() const noexcept override { return "mock-remote"; }

    void simulate_receive(const std::vector<uint8_t>& data) {
        if (receive_callback_) {
            receive_callback_(data.data(), data.size());
        }
    }

    bool running_{true};
    ReceiveCallback receive_callback_;
    std::deque<std::vector<uint8_t>> sent_data_;
};

class TestSessionManager : public DefaultSessionManager {
public:
    using DefaultSessionManager::DefaultSessionManager;
    
    std::shared_ptr<MockVirtualInterface> mock_vif_;

protected:
    VirtualInterfacePtr create_interface() override {
        mock_vif_ = std::make_unique<MockVirtualInterface>();
        // We need to keep a shared_ptr to it to access it in test, 
        // but return unique_ptr to base. 
        // Wait, make_unique returns unique_ptr.
        // We can't share ownership if unique_ptr is returned.
        // So we keep a raw pointer or weak_ptr? 
        // MockVirtualInterface is owned by SessionManager.
        // We can use a side channel to access it.
        // Or just return the unique_ptr and keep a raw pointer in mock_vif_ptr member.
        auto vif = std::make_unique<MockVirtualInterface>();
        mock_vif_raw_ = vif.get();
        return vif;
    }

public:
    MockVirtualInterface* mock_vif_raw_{nullptr};
};

TEST_CASE("SessionManager Integration Test", "[network][session]") {
    asio::io_context io_context;
    auto logger = std::make_shared<clink::core::logging::Logger>("TestSessionLogger");
    
    // Create shared_ptr for shared_from_this to work
    auto session_manager = std::make_shared<TestSessionManager>(io_context, logger);
    
    REQUIRE(session_manager->initialize().value() == 0);
    REQUIRE(session_manager->mock_vif_raw_ != nullptr);

    auto adapter = std::make_shared<MockTransportAdapter>();
    session_manager->create_session(adapter);

    // Verify session created
    auto sessions = session_manager->get_active_sessions();
    REQUIRE(sessions.size() == 1);
    std::string session_id = sessions[0].session_id;

    SECTION("Receive data from network -> route to TUN") {
        // Construct a valid Packet
        Packet packet;
        packet.header.type = static_cast<uint8_t>(PacketType::Data);
        packet.header.seq_num = 1;
        packet.header.ack_num = 0;
        packet.payload = {0x01, 0x02, 0x03, 0x04};
        packet.header.payload_size = 4;
        
        auto raw = packet.serialize();
        adapter->simulate_receive(raw);

        // Check if data reached VirtualInterface
        // Since processing might be async (queued in io_context), run io_context
        // But here adapter->on_receive is called directly, which calls session_manager callback directly.
        // The callback logic might lock mutexes etc.
        
        // Wait, route_packet is called inside the callback.
        // So mock_vif should have data.
        REQUIRE(session_manager->mock_vif_raw_->written_packets_.size() == 1);
        CHECK(session_manager->mock_vif_raw_->written_packets_[0] == packet.payload);
        
        // Also verify ACK sent back
        REQUIRE(adapter->sent_data_.size() == 1); // ACK
        auto ack_raw = adapter->sent_data_[0];
        auto ack_packet = Packet::deserialize(ack_raw.data(), ack_raw.size());
        REQUIRE(ack_packet != nullptr);
        CHECK(static_cast<PacketType>(ack_packet->header.type) == PacketType::Ack);
        CHECK(ack_packet->header.ack_num == 1);
    }

    SECTION("Receive data from TUN -> route to network") {
        std::vector<uint8_t> tun_data = {0xAA, 0xBB, 0xCC, 0xDD};
        
        // Simulate TUN read
        // start_tun_read calls async_read_packet.
        // mock_vif has stored callback.
        session_manager->mock_vif_raw_->simulate_packet(tun_data);
        
        // Check if data sent via adapter
        REQUIRE(adapter->sent_data_.size() == 1);
        auto sent_raw = adapter->sent_data_[0];
        auto sent_packet = Packet::deserialize(sent_raw.data(), sent_raw.size());
        REQUIRE(sent_packet != nullptr);
        CHECK(static_cast<PacketType>(sent_packet->header.type) == PacketType::Data);
        CHECK(sent_packet->payload == tun_data);
    }

    session_manager->shutdown();
}
