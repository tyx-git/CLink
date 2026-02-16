#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <filesystem>

#include "clink/core/logging/logger.hpp"
#include "clink/core/logging/config.hpp"

// 简单的性能计时器
class Timer {
public:
    Timer() : start_(std::chrono::high_resolution_clock::now()) {}

    void reset() {
        start_ = std::chrono::high_resolution_clock::now();
    }

    double elapsed_ms() const {
        auto end = std::chrono::high_resolution_clock::now();
        return std::chrono::duration<double, std::milli>(end - start_).count();
    }

    double elapsed_seconds() const {
        return elapsed_ms() / 1000.0;
    }

private:
    std::chrono::time_point<std::chrono::high_resolution_clock> start_;
};

// 测试配置
struct PerformanceTestConfig {
    int num_messages = 10000;
    int num_threads = 4;
    std::string log_level = "info";
    bool async = true;
    size_t queue_size = 8192;
    std::chrono::seconds flush_interval = std::chrono::seconds(3);
};

// 生成测试消息
std::vector<std::string> generate_test_messages(int count) {
    std::vector<std::string> messages;
    messages.reserve(count);
    for (int i = 0; i < count; ++i) {
        messages.push_back("Test log message #" + std::to_string(i) +
                          " with some additional data for testing performance " +
                          "timestamp: " + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()));
    }
    return messages;
}

// 结果收集结构
struct PerformanceResult {
    std::string test_name;
    int num_messages;
    int num_threads;
    double elapsed_ms;
    double throughput_msg_per_sec;
    double avg_latency_ms;
    size_t queue_size;
    bool async;

    std::string to_csv() const {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2);
        oss << test_name << ","
            << num_messages << ","
            << num_threads << ","
            << elapsed_ms << ","
            << throughput_msg_per_sec << ","
            << avg_latency_ms << ","
            << queue_size << ","
            << (async ? "async" : "sync");
        return oss.str();
    }

    static std::string csv_header() {
        return "test_name,num_messages,num_threads,elapsed_ms,throughput_msg_per_sec,avg_latency_ms,queue_size,mode";
    }
};

// 全局结果收集
std::vector<PerformanceResult> g_performance_results;

// 单线程同步日志性能测试
TEST_CASE("Synchronous logging performance", "[performance][logging][sync]") {
    PerformanceTestConfig config;
    config.num_messages = 10000;
    config.async = false;

    // 创建同步日志配置
    auto log_config = clink::core::logging::LogConfig::default_config();
    log_config.async = false;
    log_config.sinks.clear();

    // 添加控制台sink
    clink::core::logging::SinkConfig console_sink;
    console_sink.type = clink::core::logging::SinkType::Console;
    console_sink.enabled = true;
    console_sink.level = clink::core::logging::Level::info;
    log_config.sinks.push_back(console_sink);

    // 初始化日志系统
    clink::core::logging::initialize_logging(log_config);

    // 创建logger
    auto logger = clink::core::logging::create_logger("perf-test-sync", log_config);

    // 生成测试消息
    auto messages = generate_test_messages(config.num_messages);

    // 预热（避免冷启动影响）
    for (int i = 0; i < 100; ++i) {
        logger->info("Warmup message " + std::to_string(i));
    }

    // 性能测试
    Timer timer;

    for (const auto& msg : messages) {
        logger->info(msg);
    }

    double elapsed_ms = timer.elapsed_ms();
    double messages_per_second = (config.num_messages / elapsed_ms) * 1000.0;
    double avg_latency_ms = elapsed_ms / config.num_messages;

    std::cout << "\n=== Synchronous Logging Performance ===" << std::endl;
    std::cout << "Messages: " << config.num_messages << std::endl;
    std::cout << "Time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput: " << messages_per_second << " msg/sec" << std::endl;
    std::cout << "Average latency: " << avg_latency_ms << " ms/msg" << std::endl;

    // 保存结果
    PerformanceResult result;
    result.test_name = "single_thread_sync";
    result.num_messages = config.num_messages;
    result.num_threads = 1;
    result.elapsed_ms = elapsed_ms;
    result.throughput_msg_per_sec = messages_per_second;
    result.avg_latency_ms = avg_latency_ms;
    result.queue_size = 0; // 同步模式无队列
    result.async = false;
    g_performance_results.push_back(result);
}

// 单线程异步日志性能测试
TEST_CASE("Asynchronous logging performance", "[performance][logging][async]") {
    PerformanceTestConfig config;
    config.num_messages = 10000;
    config.async = true;
    config.queue_size = 8192;

    // 创建异步日志配置
    auto log_config = clink::core::logging::LogConfig::default_config();
    log_config.async = true;
    log_config.queue_size = config.queue_size;
    log_config.flush_interval = std::chrono::seconds(1);
    log_config.sinks.clear();

    clink::core::logging::SinkConfig console_sink;
    console_sink.type = clink::core::logging::SinkType::Console;
    console_sink.enabled = true;
    console_sink.level = clink::core::logging::Level::info;
    log_config.sinks.push_back(console_sink);

    // 初始化日志系统
    clink::core::logging::initialize_logging(log_config);

    // 创建logger
    auto logger = clink::core::logging::create_logger("perf-test-async", log_config);

    // 生成测试消息
    auto messages = generate_test_messages(config.num_messages);

    // 预热
    for (int i = 0; i < 100; ++i) {
        logger->info("Warmup message " + std::to_string(i));
    }

    // 性能测试
    Timer timer;

    for (const auto& msg : messages) {
        logger->info(msg);
    }

    // 等待所有消息被处理（异步队列清空）
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    double elapsed_ms = timer.elapsed_ms();
    double messages_per_second = (config.num_messages / elapsed_ms) * 1000.0;
    double avg_latency_ms = elapsed_ms / config.num_messages;

    std::cout << "\n=== Asynchronous Logging Performance ===" << std::endl;
    std::cout << "Messages: " << config.num_messages << std::endl;
    std::cout << "Queue size: " << config.queue_size << std::endl;
    std::cout << "Time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput: " << messages_per_second << " msg/sec" << std::endl;
    std::cout << "Average latency: " << avg_latency_ms << " ms/msg" << std::endl;

    // 保存结果
    PerformanceResult result;
    result.test_name = "single_thread_async";
    result.num_messages = config.num_messages;
    result.num_threads = 1;
    result.elapsed_ms = elapsed_ms;
    result.throughput_msg_per_sec = messages_per_second;
    result.avg_latency_ms = avg_latency_ms;
    result.queue_size = config.queue_size;
    result.async = true;
    g_performance_results.push_back(result);
}

// 多线程同步日志性能测试
TEST_CASE("Multi-threaded synchronous logging", "[performance][logging][sync][threading]") {
    PerformanceTestConfig config;
    config.num_messages = 5000;  // 每个线程的消息数
    config.num_threads = 4;
    config.async = false;

    auto log_config = clink::core::logging::LogConfig::default_config();
    log_config.async = false;
    log_config.sinks.clear();

    clink::core::logging::SinkConfig console_sink;
    console_sink.type = clink::core::logging::SinkType::Console;
    console_sink.enabled = true;
    console_sink.level = clink::core::logging::Level::info;
    log_config.sinks.push_back(console_sink);

    clink::core::logging::initialize_logging(log_config);

    auto messages = generate_test_messages(config.num_messages);

    std::vector<std::thread> threads;
    std::atomic<int> total_messages{0};

    Timer timer;

    for (int t = 0; t < config.num_threads; ++t) {
        threads.emplace_back([&, t]() {
            auto logger = clink::core::logging::create_logger("thread-sync-" + std::to_string(t), log_config);
            for (const auto& msg : messages) {
                logger->info(msg + " from thread " + std::to_string(t));
                total_messages.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    double elapsed_ms = timer.elapsed_ms();
    int actual_total = total_messages.load();
    double messages_per_second = (actual_total / elapsed_ms) * 1000.0;
    double avg_latency_ms = elapsed_ms / actual_total;

    std::cout << "\n=== Multi-threaded Synchronous Logging ===" << std::endl;
    std::cout << "Threads: " << config.num_threads << std::endl;
    std::cout << "Messages per thread: " << config.num_messages << std::endl;
    std::cout << "Total messages: " << actual_total << std::endl;
    std::cout << "Time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput: " << messages_per_second << " msg/sec" << std::endl;
    std::cout << "Average latency: " << avg_latency_ms << " ms/msg" << std::endl;

    PerformanceResult result;
    result.test_name = "multi_thread_sync";
    result.num_messages = actual_total;
    result.num_threads = config.num_threads;
    result.elapsed_ms = elapsed_ms;
    result.throughput_msg_per_sec = messages_per_second;
    result.avg_latency_ms = avg_latency_ms;
    result.queue_size = 0;
    result.async = false;
    g_performance_results.push_back(result);
}

// 多线程异步日志性能测试
TEST_CASE("Multi-threaded asynchronous logging", "[performance][logging][async][threading]") {
    PerformanceTestConfig config;
    config.num_messages = 5000;  // 每个线程的消息数
    config.num_threads = 4;
    config.async = true;
    config.queue_size = 16384;  // 更大的队列处理高并发

    auto log_config = clink::core::logging::LogConfig::default_config();
    log_config.async = true;
    log_config.queue_size = config.queue_size;
    log_config.sinks.clear();

    clink::core::logging::SinkConfig console_sink;
    console_sink.type = clink::core::logging::SinkType::Console;
    console_sink.enabled = true;
    console_sink.level = clink::core::logging::Level::info;
    log_config.sinks.push_back(console_sink);

    clink::core::logging::initialize_logging(log_config);

    auto messages = generate_test_messages(config.num_messages);

    std::vector<std::thread> threads;
    std::atomic<int> total_messages{0};

    Timer timer;

    for (int t = 0; t < config.num_threads; ++t) {
        threads.emplace_back([&, t]() {
            auto logger = clink::core::logging::create_logger("thread-async-" + std::to_string(t), log_config);
            for (const auto& msg : messages) {
                logger->info(msg + " from async thread " + std::to_string(t));
                total_messages.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // 等待异步队列清空
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    double elapsed_ms = timer.elapsed_ms();
    int actual_total = total_messages.load();
    double messages_per_second = (actual_total / elapsed_ms) * 1000.0;
    double avg_latency_ms = elapsed_ms / actual_total;

    std::cout << "\n=== Multi-threaded Asynchronous Logging ===" << std::endl;
    std::cout << "Threads: " << config.num_threads << std::endl;
    std::cout << "Messages per thread: " << config.num_messages << std::endl;
    std::cout << "Total messages: " << actual_total << std::endl;
    std::cout << "Queue size: " << config.queue_size << std::endl;
    std::cout << "Time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput: " << messages_per_second << " msg/sec" << std::endl;
    std::cout << "Average latency: " << avg_latency_ms << " ms/msg" << std::endl;

    PerformanceResult result;
    result.test_name = "multi_thread_async";
    result.num_messages = actual_total;
    result.num_threads = config.num_threads;
    result.elapsed_ms = elapsed_ms;
    result.throughput_msg_per_sec = messages_per_second;
    result.avg_latency_ms = avg_latency_ms;
    result.queue_size = config.queue_size;
    result.async = true;
    g_performance_results.push_back(result);
}

// 高负载队列处理测试
TEST_CASE("High load queue processing", "[performance][logging][queue]") {
    PerformanceTestConfig config;
    config.num_messages = 50000;  // 高负载
    config.async = true;
    config.queue_size = 8192;

    auto log_config = clink::core::logging::LogConfig::default_config();
    log_config.async = true;
    log_config.queue_size = config.queue_size;
    log_config.sinks.clear();

    clink::core::logging::SinkConfig console_sink;
    console_sink.type = clink::core::logging::SinkType::Console;
    console_sink.enabled = true;
    console_sink.level = clink::core::logging::Level::info;
    log_config.sinks.push_back(console_sink);

    clink::core::logging::initialize_logging(log_config);

    auto logger = clink::core::logging::create_logger("high-load-test", log_config);

    // 高负载测试：快速发送大量消息
    auto messages = generate_test_messages(config.num_messages);

    Timer timer;

    for (const auto& msg : messages) {
        logger->info(msg);
    }

    // 等待队列处理
    std::this_thread::sleep_for(std::chrono::seconds(1));

    double elapsed_ms = timer.elapsed_ms();
    double messages_per_second = (config.num_messages / elapsed_ms) * 1000.0;
    double avg_latency_ms = elapsed_ms / config.num_messages;

    std::cout << "\n=== High Load Queue Processing ===" << std::endl;
    std::cout << "Messages: " << config.num_messages << std::endl;
    std::cout << "Queue size: " << config.queue_size << std::endl;
    std::cout << "Processing time: " << elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput: " << messages_per_second << " msg/sec" << std::endl;
    std::cout << "Average latency: " << avg_latency_ms << " ms/msg" << std::endl;

    // 测试队列溢出情况（发送超过队列容量的消息）
    std::cout << "\n=== Queue Overflow Test ===" << std::endl;

    // 发送超过队列容量的消息
    const int overflow_test_size = config.queue_size * 2;
    Timer overflow_timer;

    for (int i = 0; i < overflow_test_size; ++i) {
        logger->info("Overflow test message #" + std::to_string(i));
    }

    // 等待所有消息被处理
    std::this_thread::sleep_for(std::chrono::seconds(2));

    double overflow_elapsed_ms = overflow_timer.elapsed_ms();
    double overflow_throughput = (overflow_test_size / overflow_elapsed_ms) * 1000.0;

    std::cout << "Messages sent: " << overflow_test_size << " (2x queue capacity)" << std::endl;
    std::cout << "Queue capacity: " << config.queue_size << std::endl;
    std::cout << "Total time: " << overflow_elapsed_ms << " ms" << std::endl;
    std::cout << "Throughput under overflow: " << overflow_throughput << " msg/sec" << std::endl;
    std::cout << "Note: Messages beyond queue capacity will block until space available" << std::endl;

    PerformanceResult result;
    result.test_name = "high_load_async";
    result.num_messages = config.num_messages;
    result.num_threads = 1;
    result.elapsed_ms = elapsed_ms;
    result.throughput_msg_per_sec = messages_per_second;
    result.avg_latency_ms = avg_latency_ms;
    result.queue_size = config.queue_size;
    result.async = true;
    g_performance_results.push_back(result);
}

// 内存使用估算
TEST_CASE("Memory usage estimation", "[performance][logging][memory]") {
    std::cout << "\n=== Memory Usage Estimation ===" << std::endl;

    // 估算不同队列大小的内存使用
    std::vector<std::pair<size_t, std::string>> queue_configs = {
        {1024, "Small queue (1K)"},
        {4096, "Medium queue (4K)"},
        {8192, "Default queue (8K)"},
        {16384, "Large queue (16K)"},
        {32768, "Extra large queue (32K)"}
    };

    // 假设每条消息平均200字节（包含元数据）
    const size_t avg_message_size = 200;

    std::cout << "Queue memory usage estimation (assuming " << avg_message_size << " bytes per message):" << std::endl;
    for (const auto& [queue_size, description] : queue_configs) {
        size_t estimated_memory = queue_size * avg_message_size;
        double memory_mb = estimated_memory / (1024.0 * 1024.0);

        std::cout << "  " << description << " (" << queue_size << " messages): "
                  << estimated_memory << " bytes ("
                  << std::fixed << std::setprecision(2) << memory_mb << " MB)" << std::endl;
    }
}

// 测试结束后保存结果到文件
TEST_CASE("Save performance results", "[performance][logging][report]") {
    // 这个测试应该在最后运行，保存所有结果
    std::cout << "\n=== Saving Performance Results ===" << std::endl;

    // 创建报告目录
    std::filesystem::path report_dir = "docs/log";
    std::filesystem::create_directories(report_dir);

    // 保存CSV结果
    std::ofstream csv_file(report_dir / "performance_results.csv");
    if (csv_file.is_open()) {
        csv_file << PerformanceResult::csv_header() << "\n";
        for (const auto& result : g_performance_results) {
            csv_file << result.to_csv() << "\n";
        }
        csv_file.close();
        std::cout << "Results saved to: " << (report_dir / "performance_results.csv") << std::endl;
    } else {
        std::cerr << "Failed to open results file for writing" << std::endl;
    }

    // 生成汇总报告
    std::ofstream report_file(report_dir / "performance_summary.txt");
    if (report_file.is_open()) {
        report_file << "SPDLog Performance Test Report\n";
        report_file << "================================\n";
        report_file << "Generated: " << __DATE__ << " " << __TIME__ << "\n\n";

        report_file << "Test Configuration:\n";
        report_file << "- Message size: ~200 bytes (estimated)\n";
        report_file << "- Warmup: 100 messages\n";
        report_file << "- Default queue size: 8192\n\n";

        report_file << "Performance Results:\n";
        report_file << "====================\n\n";

        for (const auto& result : g_performance_results) {
            report_file << "Test: " << result.test_name << "\n";
            report_file << "  Messages: " << result.num_messages << "\n";
            report_file << "  Threads: " << result.num_threads << "\n";
            report_file << "  Mode: " << (result.async ? "Asynchronous" : "Synchronous") << "\n";
            if (result.async) {
                report_file << "  Queue size: " << result.queue_size << "\n";
            }
            report_file << "  Time: " << std::fixed << std::setprecision(2) << result.elapsed_ms << " ms\n";
            report_file << "  Throughput: " << result.throughput_msg_per_sec << " msg/sec\n";
            report_file << "  Avg latency: " << result.avg_latency_ms << " ms/msg\n";
            report_file << "\n";
        }

        // 计算同步vs异步性能提升
        double sync_throughput = 0, async_throughput = 0;
        int sync_count = 0, async_count = 0;

        for (const auto& result : g_performance_results) {
            if (result.test_name == "single_thread_sync" || result.test_name == "multi_thread_sync") {
                sync_throughput += result.throughput_msg_per_sec;
                sync_count++;
            } else if (result.test_name == "single_thread_async" || result.test_name == "multi_thread_async") {
                async_throughput += result.throughput_msg_per_sec;
                async_count++;
            }
        }

        if (sync_count > 0 && async_count > 0) {
            double avg_sync = sync_throughput / sync_count;
            double avg_async = async_throughput / async_count;
            double improvement = ((avg_async - avg_sync) / avg_sync) * 100.0;

            report_file << "Performance Comparison:\n";
            report_file << "=======================\n";
            report_file << "Average synchronous throughput: " << avg_sync << " msg/sec\n";
            report_file << "Average asynchronous throughput: " << avg_async << " msg/sec\n";
            report_file << "Performance improvement: " << std::fixed << std::setprecision(1) << improvement << "%\n";
        }

        report_file.close();
        std::cout << "Summary saved to: " << (report_dir / "performance_summary.txt") << std::endl;
    } else {
        std::cerr << "Failed to open report file for writing" << std::endl;
    }

    REQUIRE(g_performance_results.size() > 0);
}