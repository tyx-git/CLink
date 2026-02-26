#include <catch2/catch_test_macros.hpp>
#include "clink/core/network/reliability_engine.hpp"
#include "clink/core/network/packet.hpp"
#include "clink/core/memory/buffer_pool.hpp"
#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>

using namespace clink::core::network;

std::shared_ptr<clink::core::memory::Block> make_block(const std::vector<uint8_t>& data) {
    auto block = clink::core::memory::BufferPool::instance()->acquire(data.size());
    if (!data.empty()) {
        block->append(data.data(), data.size());
    }
    return block;
}

struct TestContext {
    asio::io_context io_context;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard;
    std::thread io_thread;

    TestContext() : work_guard(asio::make_work_guard(io_context)) {}

    void start_io() {
         io_thread = std::thread([this]() {
             io_context.run();
         });
    }

    ~TestContext() {
        work_guard.reset();
        if (io_thread.joinable()) {
            io_thread.join();
        }
    }
};

TEST_CASE("ReliabilityEngine SACK and Congestion Control", "[network][reliability]") {
    TestContext ctx;
    auto& io_context = ctx.io_context;

    // Workaround for Asio steady_timer initialization crash on MinGW/Windows
    // Creating a dummy timer ensures necessary static initialization happens before ReliabilityEngine creation
    { asio::steady_timer dummy(io_context); }

    std::mutex sent_mutex;
    std::vector<std::vector<uint8_t>> sent_packets;
    auto send_fn = [&](const Packet& packet) {
        std::lock_guard<std::mutex> lock(sent_mutex);
        sent_packets.push_back(packet.serialize());
    };

    auto engine = std::make_shared<ReliabilityEngine>(io_context, nullptr, send_fn);
    
    ctx.start_io();
    engine->start();


    SECTION("Out-of-order packets generate SACK blocks") {
        // 模拟收到乱序包: 1, 3, 4, 6
        engine->set_last_received_seq(1);
        engine->set_last_received_seq(3);
        engine->set_last_received_seq(4);
        engine->set_last_received_seq(6);

        auto blocks = engine->get_sack_blocks();
        
        // 应该有两个块: [3, 4] 和 [6, 6]
        REQUIRE(blocks.size() == 2);
        CHECK(blocks[0].first == 3);
        CHECK(blocks[0].second == 4);
        CHECK(blocks[1].first == 6);
        CHECK(blocks[1].second == 6);

        // 收到缺失的包 2
        engine->set_last_received_seq(2);
        blocks = engine->get_sack_blocks();
        
        // 现在 1, 2, 3, 4 是连续的，last_received_seq 应该是 4
        // 剩下的乱序块只有 [6, 6]
        REQUIRE(blocks.size() == 1);
        CHECK(blocks[0].first == 6);
        CHECK(blocks[0].second == 6);
    }

    SECTION("Timeout triggers retransmission and increments counter") {
        engine->send_reliable(PacketType::Data, make_block({10, 11, 12})); // seq 1
        
        // Initial stats
        auto stats = engine->get_stats();
        REQUIRE(stats.retransmission_count == 0);
        
        // Clear sent packets to track new sends
        {
            std::lock_guard<std::mutex> lock(sent_mutex);
            sent_packets.clear();
        }

        // Wait for RTO (default 200ms) + buffer
        // Note: Timer resolution is 50ms, RTO is 200ms. 
        // We wait 400ms to be safe and allow multiple timer ticks.
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        
        // Should have retransmitted
        stats = engine->get_stats();
        CHECK(stats.retransmission_count >= 1);
        
        {
            std::lock_guard<std::mutex> lock(sent_mutex);
            CHECK(sent_packets.size() >= 1);
        }
    }


    SECTION("SACK blocks trigger removal from unacked queue") {
        engine->send_reliable(PacketType::Data, make_block({1, 2, 3})); // seq 1
        engine->send_reliable(PacketType::Data, make_block({4, 5, 6})); // seq 2
        engine->send_reliable(PacketType::Data, make_block({7, 8, 9})); // seq 3

        // Give some time for async operations if needed (though send_reliable is synchronous in adding to queue)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        auto stats = engine->get_stats();
        auto initial_acked = stats.total_acked;

        // 模拟收到 SACK，确认了 seq 1 和 2
        // Note: process_sack expects a vector of pairs
        std::vector<std::pair<uint32_t, uint32_t>> sack_blocks = {{1, 2}};
        engine->process_sack(sack_blocks);

        stats = engine->get_stats();
        // total_acked 应该增加 2
        CHECK(stats.total_acked == initial_acked + 2);
    }
    SECTION("Congestion Control: Slow Start") {
        auto stats = engine->get_stats();
        uint32_t initial_cwnd = stats.cwnd;
        CHECK(initial_cwnd == 10);
        
        // Send packets to populate unacked_packets_
        // seq 1 to 5
        for (int i = 0; i < 5; ++i) {
             engine->send_reliable(PacketType::Data, make_block({uint8_t(i)}));
        }
        
        // ACK seq 1
        // This should increase cwnd by 1 (Slow Start)
        engine->process_ack(1);
        
        stats = engine->get_stats();
        CHECK(stats.cwnd == initial_cwnd + 1);
        
        // ACK seq 2
        engine->process_ack(2);
        stats = engine->get_stats();
        CHECK(stats.cwnd == initial_cwnd + 2);
    }

    SECTION("Fast Retransmit and Fast Recovery") {
        // Send packets seq 1, 2, 3, 4, 5
        for (int i = 0; i < 5; ++i) {
             engine->send_reliable(PacketType::Data, make_block({uint8_t(i)}));
        }
        
        // ACK seq 1 (normal)
        engine->process_ack(1);
        
        // Receive duplicate ACKs for seq 1 (implying seq 2 is lost)
        // dup ack 1
        engine->process_ack(1);
        // dup ack 2
        engine->process_ack(1);
        // dup ack 3 -> Should trigger Fast Retransmit
        engine->process_ack(1);
        
        auto stats = engine->get_stats();
        CHECK(stats.retransmission_count >= 1);
        
        // Initial cwnd is 10.
        // After ack(1), cwnd becomes 11.
        // Fast retransmit: ssthresh = max(2, 11/2) = 5.
        // cwnd = ssthresh + 3 = 8.
        CHECK(stats.ssthresh == 5);
        CHECK(stats.cwnd == 8);
    }

    SECTION("SACK-based Early Loss Detection") {
        // Send packets 1, 2, 3, 4, 5
        for (int i = 0; i < 5; ++i) {
             engine->send_reliable(PacketType::Data, make_block({uint8_t(i)}));
        }
        
        // Suppose packet 1 is lost.
        // We receive SACK for [2, 2], [3, 3], [4, 4].
        // Each SACK block that is > 1 will increment sack_count for packet 1.
        
        // SACK [2, 2]
        engine->process_sack({{2, 2}});
        // Packet 1 sack_count becomes 1.
        
        // SACK [3, 3]
        engine->process_sack({{3, 3}});
        // Packet 1 sack_count becomes 2.
        
        // SACK [4, 4]
        engine->process_sack({{4, 4}});
        // Packet 1 sack_count becomes 3 -> Trigger Fast Retransmit
        
        auto stats = engine->get_stats();
        CHECK(stats.retransmission_count >= 1);
    }

    engine->stop();
}
