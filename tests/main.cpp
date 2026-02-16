#include "clink/core/application.hpp"

#include <chrono>
#include <iostream>
#include <thread>

int main() {
    clink::core::ApplicationOptions options;
    options.identity = "clink-test";
    options.role = "test";
    options.heartbeat_interval = std::chrono::milliseconds(10);

    clink::core::Application app{options};
    app.initialize();
    const auto& configuration = app.configuration();
    std::cout << "Loaded config entries: " << configuration.size() << std::endl;
    
    // Run application in a separate thread
    std::thread app_thread([&app]() {
        app.run();
    });

    // Let it run for a short while
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    app.shutdown();
    if (app_thread.joinable()) {
        app_thread.join();
    }

    std::cout << "Smoke test completed" << std::endl;
    return 0;
}
