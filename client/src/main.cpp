#include "clink/core/application.hpp"
#include "clink/core/security/dpapi_helper.hpp"
#include "clink/core/utils/terminal.hpp"

#include <chrono>
#include <thread>
#include <iostream>
#include <fstream>
#include <string_view>
#include <filesystem>
#include <cstdlib>
#include <iomanip>
#include <sstream>

using namespace clink::core::utils;

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

namespace {

void print_usage() {
    Terminal::println("CLINK CLI", Color::BrightCyan);
    Terminal::println("Usage: clink-cli [options] <command>");
    Terminal::println("\nOptions:");
    Terminal::println("  -c, --config <path>  Path to configuration file");
    Terminal::println("\nCommands:");
    Terminal::print("  connect     ", Color::Green); Terminal::println("Bring up a session");
    Terminal::print("  disconnect  ", Color::Red); Terminal::println("Tear down session");
    Terminal::print("  status      ", Color::Yellow); Terminal::println("Show current daemon status");
    Terminal::print("  reload      ", Color::Magenta); Terminal::println("Reload daemon configuration");
    Terminal::print("  diag        ", Color::Cyan); Terminal::println("Dump troubleshooting data");
    Terminal::print("  monitor     ", Color::BrightMagenta); Terminal::println("Real-time session monitor");
    Terminal::print("  logs        ", Color::BrightYellow); Terminal::println("Tail daemon logs");
    Terminal::print("  encrypt     ", Color::Blue); Terminal::println("Encrypt a secret using DPAPI");
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

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string_view command;
    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg.starts_with("-")) {
            if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
                i++; // skip next
            }
            continue;
        }
        command = arg;
        break;
    }

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

        if (command == "status") {
            auto& client = app.ipc_client();
            try {
                client.connect("\\\\.\\pipe\\clink-ipc");
                auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
                
                std::string payload = response.payload;
                Terminal::println("--- CLINK DAEMON STATUS ---", Color::BrightCyan);
                
                auto get_val = [&](const std::string& key) {
                    size_t k_pos = payload.find("\"" + key + "\": ");
                    if (k_pos == std::string::npos) return std::string("");
                    size_t v_start = k_pos + key.length() + 4;
                    size_t v_end = payload.find_first_of(",}", v_start);
                    std::string v = payload.substr(v_start, v_end - v_start);
                    if (v.starts_with("\"")) v = v.substr(1, v.length() - 2);
                    return v;
                };

                std::string status = get_val("status");
                std::string session_id = get_val("session_id");
                std::string active_sessions = get_val("active_sessions");

                Terminal::print("Service Status: ", Color::White);
                if (status == "connected") Terminal::println("CONNECTED", Color::BrightGreen);
                else if (status == "connecting") Terminal::println("CONNECTING", Color::Yellow);
                else if (status == "disconnecting") Terminal::println("DISCONNECTING", Color::Yellow);
                else Terminal::println("DISCONNECTED", Color::Red);

                if (!session_id.empty() && session_id != "null") {
                    Terminal::print("Session ID:     ", Color::White);
                    Terminal::println(session_id, Color::Cyan);
                }

                Terminal::print("Active Clients: ", Color::White);
                Terminal::println(active_sessions, Color::BrightWhite);

                if (payload.find("\"sessions\": [") != std::string::npos) {
                    Terminal::println("\nActive Sessions:", Color::BrightWhite);
                    Terminal::println(std::string(60, '-'), Color::White);
                    std::cout << std::left 
                              << std::setw(15) << "Session ID" 
                              << std::setw(15) << "Sent" 
                              << std::setw(15) << "Received" 
                              << std::setw(10) << "RTT" << std::endl;
                    
                    size_t start_pos = payload.find("\"sessions\": [");
                    size_t end_pos = payload.find("]", start_pos);
                    std::string sessions_list = payload.substr(start_pos, end_pos - start_pos);
                    
                    size_t session_pos = 0;
                    while ((session_pos = sessions_list.find("{", session_pos)) != std::string::npos) {
                        size_t session_end = sessions_list.find("}", session_pos);
                        std::string s_data = sessions_list.substr(session_pos, session_end - session_pos);
                        
                        auto get_session_val = [&](const std::string& key) {
                            size_t k_pos = s_data.find("\"" + key + "\": ");
                            if (k_pos == std::string::npos) return std::string("");
                            size_t v_start = k_pos + key.length() + 4;
                            size_t v_end = s_data.find_first_of(",}", v_start);
                            std::string v = s_data.substr(v_start, v_end - v_start);
                            if (v.starts_with("\"")) v = v.substr(1, v.length() - 2);
                            return v;
                        };

                        std::string id = get_session_val("id");
                        std::string sent_str = get_session_val("bytes_sent");
                        std::string recv_str = get_session_val("bytes_received");
                        std::string rtt = get_session_val("rtt_ms");

                        uint64_t sent = sent_str.empty() ? 0 : std::stoull(sent_str);
                        uint64_t recv = recv_str.empty() ? 0 : std::stoull(recv_str);

                        std::cout << std::left 
                                  << std::setw(15) << (id.length() > 12 ? id.substr(0, 12) + ".." : id)
                                  << std::setw(15) << format_bytes(sent)
                                  << std::setw(15) << format_bytes(recv)
                                  << std::setw(10) << (rtt + "ms") << std::endl;
                        
                        session_pos = session_end;
                    }
                }
            } catch (const std::exception& e) {
                Terminal::println("Failed to get status: " + std::string(e.what()), Color::Red);
            }
        } else if (command == "connect" || command == "disconnect" || command == "reload") {
            Terminal::print("Sending ", Color::Cyan);
            Terminal::print(std::string(command), Color::BrightCyan);
            Terminal::println(" request to daemon...", Color::Cyan);
            auto& client = app.ipc_client();
            try {
                client.connect("\\\\.\\pipe\\clink-ipc");
                auto response = client.send_request({clink::core::ipc::MessageType::Request, std::string(command), ""});
                Terminal::print("Response: ", Color::BrightWhite);
                if (response.payload.find("\"ok\"") != std::string::npos || response.payload.find("\"connecting\"") != std::string::npos || response.payload.find("\"disconnecting\"") != std::string::npos) {
                    Terminal::println(response.payload, Color::Green);
                } else {
                    Terminal::println(response.payload, Color::Yellow);
                }
            } catch (const std::exception& e) {
                Terminal::println("Failed to connect to daemon: " + std::string(e.what()), Color::Red);
            }
        } else if (command == "diag") {
            Terminal::println("=== CLINK DIAGNOSTIC TOOL ===", Color::BrightCyan);
            
            // 1. Check Config
            Terminal::print("[1/4] Checking configuration... ", Color::White);
            try {
                if (std::filesystem::exists(options.config_path)) {
                    auto cfg = clink::core::config::Configuration::load_from_file(options.config_path);
                    Terminal::println("OK", Color::Green);
                    Terminal::println("      Path: " + options.config_path.string(), Color::White);
                } else {
                    Terminal::println("MISSING", Color::Yellow);
                    Terminal::println("      Using default values.", Color::White);
                }
            } catch (const std::exception& e) {
                Terminal::println("ERROR", Color::Red);
                Terminal::println("      " + std::string(e.what()), Color::Red);
            }

            // 2. Check IPC
            Terminal::print("[2/4] Checking daemon connectivity... ", Color::White);
            auto& client = app.ipc_client();
            try {
                client.connect("\\\\.\\pipe\\clink-ipc");
                auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
                Terminal::println("OK", Color::Green);
                Terminal::println("      Daemon is responding.", Color::White);
            } catch (...) {
                Terminal::println("FAILED", Color::Red);
                Terminal::println("      Daemon might not be running or pipe is inaccessible.", Color::Yellow);
            }

            // 3. Check Network (simple ping-like check to a common DNS)
            Terminal::print("[3/4] Checking internet access... ", Color::White);
#ifdef _WIN32
            int res = std::system("ping -n 1 8.8.8.8 > nul");
            if (res == 0) {
                Terminal::println("OK", Color::Green);
            } else {
                Terminal::println("FAILED", Color::Red);
            }
#else
            Terminal::println("SKIPPED (non-windows)", Color::Yellow);
#endif

            // 4. Check Logs
            Terminal::print("[4/4] Checking log files... ", Color::White);
            std::filesystem::path log_path = "logs/clink-daemon.log";
            if (std::filesystem::exists(log_path)) {
                auto size = std::filesystem::file_size(log_path);
                Terminal::println("OK", Color::Green);
                Terminal::println("      Path: " + log_path.string() + " (" + format_bytes(size) + ")", Color::White);
            } else {
                Terminal::println("NOT FOUND", Color::Yellow);
                Terminal::println("      Logs may not have been generated yet.", Color::White);
            }

            Terminal::println("\nDiagnostic complete.", Color::BrightCyan);
        } else if (command == "monitor") {
            Terminal::println("Starting real-time monitor (Ctrl+C to exit)...", Color::Cyan);
            auto& client = app.ipc_client();
            try {
                client.connect("\\\\.\\pipe\\clink-ipc");
                
                while (true) {
                    auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
                    std::string payload = response.payload;
                    
                    Terminal::clear_screen();
                    Terminal::println("CLINK REAL-TIME MONITOR", Color::BrightCyan);
                    Terminal::println(std::string(40, '='), Color::White);
                    
                    // Status summary
                    Terminal::print("Daemon Status: ", Color::White);
                    if (payload.find("\"connected\"") != std::string::npos) Terminal::println("CONNECTED", Color::BrightGreen);
                    else if (payload.find("\"connecting\"") != std::string::npos) Terminal::println("CONNECTING", Color::Yellow);
                    else Terminal::println("DISCONNECTED", Color::Red);
                    
                    // Detailed sessions
                    if (payload.find("\"sessions\": [") != std::string::npos) {
                        Terminal::println("\nActive Sessions:", Color::BrightWhite);
                        Terminal::println(std::string(75, '-'), Color::White);
                        std::cout << std::left 
                                  << std::setw(12) << "ID" 
                                  << std::setw(12) << "User" 
                                  << std::setw(15) << "Sent" 
                                  << std::setw(15) << "Received" 
                                  << std::setw(10) << "RTT/RTO" 
                                  << std::setw(15) << "Endpoint" << std::endl;
                        
                        uint64_t total_sent = 0;
                        uint64_t total_recv = 0;

                        size_t start_pos = payload.find("\"sessions\": [");
                        size_t end_pos = payload.find("]", start_pos);
                        std::string sessions_list = payload.substr(start_pos, end_pos - start_pos);
                        
                        size_t session_pos = 0;
                        while ((session_pos = sessions_list.find("{", session_pos)) != std::string::npos) {
                            size_t session_end = sessions_list.find("}", session_pos);
                            std::string s_data = sessions_list.substr(session_pos, session_end - session_pos);
                            
                            auto get_val = [&](const std::string& key) {
                                size_t k_pos = s_data.find("\"" + key + "\": ");
                                if (k_pos == std::string::npos) return std::string("");
                                size_t v_start = k_pos + key.length() + 4;
                                size_t v_end = s_data.find_first_of(",}", v_start);
                                std::string v = s_data.substr(v_start, v_end - v_start);
                                if (v.starts_with("\"")) v = v.substr(1, v.length() - 2);
                                return v;
                            };

                            std::string id = get_val("id");
                            std::string user = get_val("user_id");
                            std::string endpoint = get_val("remote_endpoint");
                            std::string sent_str = get_val("bytes_sent");
                            std::string recv_str = get_val("bytes_received");
                            std::string rtt = get_val("rtt_ms");
                            std::string rto = get_val("rto_ms");

                            uint64_t sent = sent_str.empty() ? 0 : std::stoull(sent_str);
                            uint64_t recv = recv_str.empty() ? 0 : std::stoull(recv_str);
                            total_sent += sent;
                            total_recv += recv;

                            std::cout << std::left 
                                      << std::setw(12) << (id.length() > 8 ? id.substr(0, 8) + ".." : id)
                                      << std::setw(12) << (user.empty() ? "N/A" : (user.length() > 8 ? user.substr(0, 8) + ".." : user))
                                      << std::setw(15) << format_bytes(sent)
                                      << std::setw(15) << format_bytes(recv)
                                      << std::setw(10) << (rtt + "/" + rto + "ms")
                                      << std::setw(15) << (endpoint.length() > 14 ? endpoint.substr(0, 14) : endpoint) << std::endl;
                            
                            session_pos = session_end;
                        }

                        Terminal::println(std::string(75, '-'), Color::White);
                        std::cout << std::left 
                                  << std::setw(12) << "TOTAL" 
                                  << std::setw(12) << "" 
                                  << std::setw(15) << format_bytes(total_sent)
                                  << std::setw(15) << format_bytes(total_recv)
                                  << std::endl;
                    } else {
                        Terminal::println("\nNo active sessions.", Color::Yellow);
                    }
                    
                    Terminal::println("\n" + std::string(40, '='), Color::White);
                    Terminal::println("Press Ctrl+C to stop", Color::White);
                    
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            } catch (const std::exception& e) {
                Terminal::println("Monitor error: " + std::string(e.what()), Color::Red);
            }
        } else if (command == "logs") {
            bool tail = false;
            for (int i = 1; i < argc; ++i) {
                if (std::string(argv[i]) == "--tail") {
                    tail = true;
                    break;
                }
            }

            Terminal::println("Fetching daemon logs...", Color::Cyan);
            auto& client = app.ipc_client();
            try {
                client.connect("\\\\.\\pipe\\clink-ipc");
                
                std::string last_content;
                do {
                    auto response = client.send_request({clink::core::ipc::MessageType::Request, "logs", ""});
                    if (response.payload.find("{\"error\":") == 0) {
                        Terminal::println(response.payload, Color::Red);
                        break;
                    }

                    if (response.payload != last_content) {
                        // 找出新增的内容
                        if (last_content.empty() || response.payload.find(last_content) == std::string::npos) {
                            // 打印带颜色的内容
                            std::stringstream ss(response.payload);
                            std::string line;
                            while (std::getline(ss, line)) {
                                if (line.find("[info]") != std::string::npos) Terminal::println(line, Color::Green);
                                else if (line.find("[warn]") != std::string::npos) Terminal::println(line, Color::Yellow);
                                else if (line.find("[error]") != std::string::npos) Terminal::println(line, Color::Red);
                                else if (line.find("[debug]") != std::string::npos) Terminal::println(line, Color::Blue);
                                else if (line.find("[trace]") != std::string::npos) Terminal::println(line, Color::White);
                                else Terminal::println(line);
                            }
                        } else {
                            std::string added = response.payload.substr(last_content.length());
                            std::stringstream ss(added);
                            std::string line;
                            while (std::getline(ss, line)) {
                                if (line.find("[info]") != std::string::npos) Terminal::println(line, Color::Green);
                                else if (line.find("[warn]") != std::string::npos) Terminal::println(line, Color::Yellow);
                                else if (line.find("[error]") != std::string::npos) Terminal::println(line, Color::Red);
                                else if (line.find("[debug]") != std::string::npos) Terminal::println(line, Color::Blue);
                                else if (line.find("[trace]") != std::string::npos) Terminal::println(line, Color::White);
                                else Terminal::println(line);
                            }
                        }
                        last_content = response.payload;
                    }

                    if (tail) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    }
                } while (tail);
            } catch (const std::exception& e) {
                Terminal::println("Failed to fetch logs from daemon: " + std::string(e.what()), Color::Red);
                Terminal::println("Attempting to read local log file...", Color::Yellow);
                
                std::filesystem::path log_path = "logs/clink-daemon.log";
                if (!std::filesystem::exists(log_path)) {
                    Terminal::println("Log file not found: " + log_path.string(), Color::Red);
                    return 1;
                }

                Terminal::println("Tailing " + log_path.string() + " (Ctrl+C to stop)...", Color::Cyan);
                std::ifstream file(log_path);
                if (!file.is_open()) {
                    Terminal::println("Failed to open log file", Color::Red);
                    return 1;
                }

                file.seekg(0, std::ios::end);
                std::string line;
                while (true) {
                    if (std::getline(file, line)) {
                        if (line.find("[info]") != std::string::npos) Terminal::println(line, Color::Green);
                        else if (line.find("[warn]") != std::string::npos) Terminal::println(line, Color::Yellow);
                        else if (line.find("[error]") != std::string::npos) Terminal::println(line, Color::Red);
                        else if (line.find("[debug]") != std::string::npos) Terminal::println(line, Color::Blue);
                        else if (line.find("[trace]") != std::string::npos) Terminal::println(line, Color::White);
                        else Terminal::println(line);
                    } else {
                        if (file.eof()) {
                            file.clear();
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        } else break;
                    }
                }
            }
        } else if (command == "encrypt") {
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
            } catch (const std::exception& e) {
                std::cerr << "Encryption failed: " << e.what() << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Unknown command: " << command << "\n";
            print_usage();
            return 2;
        }

        app.shutdown();
    } catch (const std::exception& e) {
        std::cerr << "CLI error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
