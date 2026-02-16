#include "clink/core/application.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <csignal>
#include <atomic>

namespace {

std::atomic<clink::core::Application*> g_app_ptr{nullptr};

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        std::cout << "\nReceived shutdown signal, stopping..." << std::endl;
        if (auto* app = g_app_ptr.load()) {
            // 使用默认的 5 秒超时
            app->shutdown(std::chrono::seconds(5));
        }
    }
}

clink::core::logging::Level parse_log_level(std::string_view value) {
    std::string lowered{value};
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lowered == "trace") return clink::core::logging::Level::trace;
    if (lowered == "debug") return clink::core::logging::Level::debug;
    if (lowered == "info") return clink::core::logging::Level::info;
    if (lowered == "warn") return clink::core::logging::Level::warn;
    if (lowered == "error") return clink::core::logging::Level::error;
    if (lowered == "critical") return clink::core::logging::Level::critical;
    return clink::core::logging::Level::info;
}

std::filesystem::path parse_config_path(int argc, char** argv, std::filesystem::path default_path) {
    std::filesystem::path path = std::move(default_path);
    if (const char* env = std::getenv("CLINK_CONFIG_PATH")) {
        path = env;
    }
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            path = argv[++i];
        }
    }
    return path;
}

void parse_extra_flags(int argc, char** argv, clink::core::ApplicationOptions& options) {
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if ((arg == "--log-level" || arg == "-l") && i + 1 < argc) {
            options.log_level = parse_log_level(argv[++i]);
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    clink::core::ApplicationOptions options;
    options.identity = "clink";
    options.role = "service";
    options.heartbeat_interval = std::chrono::seconds(1);
    options.config_path = parse_config_path(argc, argv, options.config_path);
    options.auto_reload_config = true; // 默认开启自动重载
    parse_extra_flags(argc, argv, options);

    clink::core::Application app{options};
    g_app_ptr.store(&app);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        app.initialize();
        app.start_ipc_server("\\\\.\\pipe\\clink-ipc");
        app.run();
        app.shutdown();
    } catch (const std::exception& ex) {
        std::cerr << "Service failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
