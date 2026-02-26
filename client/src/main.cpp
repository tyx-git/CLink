#include "client/include/clink/core/application.hpp"
#include "client/include/clink/core/utils/terminal.hpp"
#include "server/include/clink/core/security/dpapi_helper.hpp"
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
using namespace clink::core::utils;
using json = nlohmann::json;
namespace {
constexpr const char* kIpcPipe = "\\\\.\\pipe\\clink-ipc";
struct IpcEnvelope {
    bool ok{false};
    std::string command;
    json data;
    std::string error;
    std::string raw;
};
std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit = 0;
    double count = static_cast<double>(bytes);
    while (count >= 1024 && unit < 4) {
        count /= 1024;
        unit++;
    }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << count << " " << units[unit];
    return ss.str();
}
void print_usage() {
    Terminal::println("CLINK CLI", Color::BrightCyan);
    Terminal::println("Usage: clink-cli [options] <command>");
    Terminal::println("\nOptions:");
    Terminal::println("  -c, --config <path>  Path to configuration file");
    Terminal::println("\nCommands:");
    Terminal::print("  connect     ", Color::Green);
    Terminal::println("Bring up a session");
    Terminal::print("  disconnect  ", Color::Red);
    Terminal::println("Tear down session");
    Terminal::print("  status      ", Color::Yellow);
    Terminal::println("Show current daemon status");
    Terminal::print("  reload      ", Color::Magenta);
    Terminal::println("Reload daemon configuration");
    Terminal::print("  diag        ", Color::Cyan);
    Terminal::println("Dump troubleshooting data");
    Terminal::print("  monitor     ", Color::BrightMagenta);
    Terminal::println("Real-time session monitor");
    Terminal::print("  logs        ", Color::BrightYellow);
    Terminal::println("Tail daemon logs (--tail)");
    Terminal::print("  encrypt     ", Color::Blue);
    Terminal::println("Encrypt a secret using DPAPI");
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
std::string_view find_first_command(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg.rfind("-", 0) == 0) {
            if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
                ++i;
            }
            continue;
        }
        return arg;
    }
    return {};
}
template <typename T>
T jget(const json& j, const char* key, T def = T{}) {
    try {
        if (!j.contains(key) || j.at(key).is_null()) return def;
        return j.at(key).get<T>();
    }catch (...) {
        return def;
    }
}
IpcEnvelope parse_response_envelope(const std::string& payload) {
    IpcEnvelope out;
    out.raw = payload;
    try {
        const auto root = json::parse(payload);
        out.ok = jget<bool>(root, "ok", false);
        out.command = jget<std::string>(root, "command", "");
        out.error = jget<std::string>(root, "error", "");
        out.data = root.contains("data") ? root["data"] : json::object();
    }catch (const std::exception& e) {
        out.ok = false;
        out.error = std::string("invalid json payload: ") + e.what();
        out.data = json::object();
    }
    return out;
}
void print_status_table(const json& payload) {
    Terminal::println("--- CLINK DAEMON STATUS ---", Color::BrightCyan);
    const std::string status = jget<std::string>(payload, "status", "disconnected");
    const std::string session_id = jget<std::string>(payload, "session_id", "");
    const auto active_sessions = jget<int>(payload, "active_sessions", 0);
    Terminal::print("Service Status: ", Color::White);
    if (status == "connected") Terminal::println("CONNECTED", Color::BrightGreen);
    else if (status == "connecting") Terminal::println("CONNECTING", Color::Yellow);
    else if (status == "disconnecting") Terminal::println("DISCONNECTING", Color::Yellow);
    else Terminal::println("DISCONNECTED", Color::Red);
    if (!session_id.empty() && session_id != "null" && session_id != "none") {
        Terminal::print("Session ID:     ", Color::White);
        Terminal::println(session_id, Color::Cyan);
    }
    Terminal::print("Active Clients: ", Color::White);
    Terminal::println(std::to_string(active_sessions), Color::BrightWhite);
    if (!payload.contains("sessions") || !payload.at("sessions").is_array()) {
        return;
    }
    Terminal::println("\nActive Sessions:", Color::BrightWhite);
    Terminal::println(std::string(80, '-'), Color::White);
    std::cout << std::left << std::setw(15) << "Session ID"
              << std::setw(12) << "Sent"
              << std::setw(12) << "Received"
              << std::setw(8) << "RTT"
              << std::setw(8) << "Loss" << std::endl;
    for (const auto& s : payload.at("sessions")) {
        const std::string id = jget<std::string>(s, "id", "");
        const uint64_t sent = jget<uint64_t>(s, "bytes_sent", 0);
        const uint64_t recv = jget<uint64_t>(s, "bytes_received", 0);
        const auto rtt = jget<int64_t>(s, "rtt_ms", 0);
        const uint64_t corrupted = jget<uint64_t>(s, "corrupted_packets", 0);
        const uint64_t retrans = jget<uint64_t>(s, "retrans_count", 0);
        std::cout << std::left
                  << std::setw(15) << (id.size() > 12 ? id.substr(0, 12) + ".." : id)
                  << std::setw(12) << format_bytes(sent)
                  << std::setw(12) << format_bytes(recv)
                  << std::setw(8) << (std::to_string(rtt) + "ms")
                  << std::setw(8) << retrans << std::endl;
        Terminal::print("    Quality: ", Color::Cyan);
        if (corrupted > 0) {
            Terminal::print("Corrupted: " + std::to_string(corrupted) + " | ", Color::Red);
        }else {
            Terminal::print("Integrity: OK | ", Color::Green);
        }
        const json lat = s.contains("latency_distribution") ? s.at("latency_distribution") : json::object();
        std::cout << "Lat: "
                  << "<10:" << jget<uint64_t>(lat, "<10ms", 0) << " "
                  << "<50:" << jget<uint64_t>(lat, "10-50ms", 0) << " "
                  << "<100:" << jget<uint64_t>(lat, "50-100ms", 0) << " "
                  << "<200:" << jget<uint64_t>(lat, "100-200ms", 0) << " "
                  << "<500:" << jget<uint64_t>(lat, "200-500ms", 0) << " "
                  << "<1s:" << jget<uint64_t>(lat, "500ms-1s", 0) << " "
                  << ">1s:" << jget<uint64_t>(lat, ">1s", 0) << std::endl;
        Terminal::println(std::string(80, '-'), Color::White);
    }
}
bool send_command_and_print(clink::core::ipc::IpcClient& client, const std::string& command) {
    auto response = client.send_request({clink::core::ipc::MessageType::Request, command, ""});
    const auto envelope = parse_response_envelope(response.payload);
    Terminal::print("Response: ", Color::BrightWhite);
    if (envelope.ok) {
        Terminal::println(envelope.raw, Color::Green);
        return true;
    }
    Terminal::println(envelope.raw, Color::Yellow);
    return false;
}
int handle_status(clink::core::Application& app) {
    auto& client = app.ipc_client();
    client.connect(kIpcPipe);
    auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
    const auto envelope = parse_response_envelope(response.payload);
    if (!envelope.ok) {
        Terminal::println("Failed to get status: " + envelope.error, Color::Red);
        return 1;
    }
    print_status_table(envelope.data);
    return 0;
}
int handle_monitor(clink::core::Application& app) {
    auto& client = app.ipc_client();
    client.connect(kIpcPipe);
    Terminal::println("Starting real-time monitor (Ctrl+C to exit)...", Color::Cyan);
    while (true) {
        auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
        const auto envelope = parse_response_envelope(response.payload);
        Terminal::clear_screen();
        Terminal::println("=== CLINK MONITOR (Ctrl+C to exit) ===", Color::BrightMagenta);
        if (!envelope.ok) {
            Terminal::println("Connection error: " + envelope.error, Color::Red);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        print_status_table(envelope.data);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
int handle_diag(clink::core::Application& app, const clink::core::ApplicationOptions& options) {
    Terminal::println("=== CLINK DIAGNOSTIC TOOL ===", Color::BrightCyan);
    Terminal::print("[1/4] Checking configuration... ", Color::White);
    try {
        if (std::filesystem::exists(options.config_path)) {
            auto cfg = clink::core::config::Configuration::load_from_file(options.config_path);
            (void)cfg;
            Terminal::println("OK", Color::Green);
            Terminal::println("      Path: " + options.config_path.string(), Color::White);
        }else {
            Terminal::println("MISSING", Color::Yellow);
            Terminal::println("      Using default values.", Color::White);
        }
    }catch (const std::exception& e) {
        Terminal::println("ERROR", Color::Red);
        Terminal::println("      " + std::string(e.what()), Color::Red);
    }
    Terminal::print("[2/4] Checking daemon connectivity... ", Color::White);
    auto& client = app.ipc_client();
    try {
        client.connect(kIpcPipe);
        auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
        const auto env = parse_response_envelope(response.payload);
        if (env.ok) {
            Terminal::println("OK", Color::Green);
            Terminal::println("      Daemon is responding.", Color::White);
        }else {
            Terminal::println("FAILED", Color::Red);
            Terminal::println("      " + (env.error.empty() ? "Daemon returned error" : env.error), Color::Yellow);
        }
    }catch (...) {
        Terminal::println("FAILED", Color::Red);
        Terminal::println("      Daemon might not be running or pipe is inaccessible.", Color::Yellow);
    }
    Terminal::print("[3/4] Checking internet access... ", Color::White);
#ifdef _WIN32
    const int res = std::system("ping -n 1 8.8.8.8 > nul");
    Terminal::println(res == 0 ? "OK" : "FAILED", res == 0 ? Color::Green : Color::Red);
#else
    Terminal::println("SKIPPED (non-windows)", Color::Yellow);
#endif
    Terminal::print("[4/4] Checking log files... ", Color::White);
    std::filesystem::path log_path = "logs/clink-daemon.log";
    if (std::filesystem::exists(log_path)) {
        auto size = std::filesystem::file_size(log_path);
        Terminal::println("OK", Color::Green);
        Terminal::println("      Path: " + log_path.string() + " (" + format_bytes(size) + ")", Color::White);
    }else {
        Terminal::println("NOT FOUND", Color::Yellow);
        Terminal::println("      Logs may not have been generated yet.", Color::White);
    }
    Terminal::println("\nDiagnostic complete.", Color::BrightCyan);
    return 0;
}
int handle_logs(clink::core::Application& app, int argc, char** argv) {
    bool tail = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--tail") {
            tail = true;
            break;
        }
    }
    Terminal::println("Fetching daemon logs...", Color::Cyan);
    auto& client = app.ipc_client();
    try {
        client.connect(kIpcPipe);
        std::string last_content;
        do {
            auto response = client.send_request({clink::core::ipc::MessageType::Request, "logs", ""});
            const auto env = parse_response_envelope(response.payload);
            if (!env.ok) {
                Terminal::println(env.raw, Color::Red);
                break;
            }
            const std::string content = jget<std::string>(env.data, "content", "");
            if (content != last_content) {
                std::stringstream ss(content);
                std::string line;
                while (std::getline(ss, line)) {
                    if (line.find("[info]") != std::string::npos) Terminal::println(line, Color::Green);
                    else if (line.find("[warn]") != std::string::npos) Terminal::println(line, Color::Yellow);
                    else if (line.find("[error]") != std::string::npos) Terminal::println(line, Color::Red);
                    else if (line.find("[debug]") != std::string::npos) Terminal::println(line, Color::Blue);
                    else if (line.find("[trace]") != std::string::npos) Terminal::println(line, Color::White);
                    else Terminal::println(line);
                }
                last_content = content;
            }
            if (tail) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }while (tail);
        return 0;
    }catch (const std::exception& e) {
        Terminal::println("Failed to fetch logs from daemon: " + std::string(e.what()), Color::Red);
        return 1;
    }
}
int handle_encrypt(int argc, char** argv) {
    std::string secret;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "encrypt" && i + 1 < argc) {
            secret = argv[i + 1];
            break;
        }
    }
    if (secret.empty()) {
        std::cout << "Usage: clink-cli encrypt <secret>" << std::endl;
        return 1;
    }
    try {
        auto encrypted = clink::core::security::DpapiHelper::encrypt(secret);
        auto base64 = clink::core::security::DpapiHelper::to_base64(encrypted);
        std::cout << "Encrypted secret (Base64): " << base64 << std::endl;
        std::cout << "Copy this into your config file." << std::endl;
        return 0;
    }catch (const std::exception& e) {
        std::cerr << "Encryption failed: " << e.what() << std::endl;
        return 1;
    }
}
}// namespace
int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }
    const std::string_view command = find_first_command(argc, argv);
    if (command.empty()) {
        print_usage();
        return 1;
    }
    clink::core::ApplicationOptions options;
    options.identity = "clink-cli";
    options.role = "cli";
    options.heartbeat_interval = std::chrono::milliseconds(250);
    options.config_path = parse_config_path(argc, argv, options.config_path);
    clink::core::Application app{options};
    try {
        app.initialize();
        int rc = 0;
        if (command == "status") {
            rc = handle_status(app);
        }else if (command == "monitor") {
            rc = handle_monitor(app);
        }else if (command == "diag") {
            rc = handle_diag(app, options);
        }else if (command == "logs") {
            rc = handle_logs(app, argc, argv);
        }else if (command == "encrypt") {
            rc = handle_encrypt(argc, argv);
        }else if (command == "connect" || command == "disconnect" || command == "reload") {
            Terminal::print("Sending ", Color::Cyan);
            Terminal::print(std::string(command), Color::BrightCyan);
            Terminal::println(" request to daemon...", Color::Cyan);
            auto& client = app.ipc_client();
            client.connect(kIpcPipe);
            send_command_and_print(client, std::string(command));
        }else {
            std::cerr << "Unknown command: " << command << "\n";
            print_usage();
            rc = 2;
        }
        app.shutdown();
        return rc;
    }catch (const std::exception& e) {
        std::cerr << "CLI error: " << e.what() << std::endl;
        return 1;
    }
}
