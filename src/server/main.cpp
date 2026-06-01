#include "src/server/core/application/application.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <string>
#include <string_view>

#ifdef _WIN32
#include <shellapi.h>
#include <windows.h>
#endif

namespace {

std::atomic<clink::core::Application*> g_app_ptr{nullptr};
std::atomic<int> g_last_signal{0};
constexpr std::string_view kServerVersion{"1.3.5"};

bool has_flag(int argc, char** argv, std::string_view flag) {
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == flag) {
            return true;
        }
    }
    return false;
}

bool has_any_flag(int argc, char** argv, std::initializer_list<std::string_view> flags) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        for (const std::string_view flag : flags) {
            if (arg == flag) {
                return true;
            }
        }
    }
    return false;
}

void print_usage() {
    std::cout << "CLINK Server\n";
    std::cout << "Usage: clink-server [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config <path>      Path to configuration file\n";
    std::cout << "  -l, --log-level <level>  trace|debug|info|warn|error|critical\n";
    std::cout << "      --no-elevate         Skip Windows auto-elevation\n";
    std::cout << "  -h, --help               Show this help message\n";
    std::cout << "      --version            Show version information\n\n";
    std::cout << "Notes:\n";
    std::cout << "  - On Windows, the server auto-elevates when VIF setup requires it.\n";
    std::cout << "  - For non-admin diagnostics, combine --no-elevate with CLINK_DISABLE_VIF=1.\n";
}

void print_version() {
    std::cout << "clink-server " << kServerVersion << std::endl;
}

#ifdef _WIN32
std::string get_flag_value(int argc, char** argv, std::string_view flag) {
    for (int i = 1; i < argc - 1; ++i) {
        if (std::string_view(argv[i]) == flag) {
            return argv[i + 1];
        }
    }
    return {};
}

std::string read_ipc_address_from_config(int argc, char** argv) {
    std::string config_path = get_flag_value(argc, argv, "-c");
    if (config_path.empty()) {
        config_path = get_flag_value(argc, argv, "--config");
    }
    if (config_path.empty()) {
        config_path = "config/clink.init.toml";
    }

    std::ifstream f(config_path);
    if (!f.is_open()) return {};

    std::string line;
    while (std::getline(f, line)) {
        // Simple TOML parser: look for ipc.address = "..."
        auto pos = line.find("ipc.address");
        if (pos == std::string::npos) continue;
        pos = line.find('=', pos + 11);
        if (pos == std::string::npos) continue;
        auto q1 = line.find('"', pos + 1);
        if (q1 == std::string::npos) continue;
        auto q2 = line.find('"', q1 + 1);
        if (q2 == std::string::npos) continue;
        return line.substr(q1 + 1, q2 - q1 - 1);
    }
    return {};
}

std::string quote_arg(std::string_view arg) {
    const bool need_quote = arg.find_first_of(" \t\"") != std::string_view::npos;
    if (!need_quote) {
        return std::string(arg);
    }

    std::string out;
    out.reserve(arg.size() + 2);
    out.push_back('"');
    for (const char ch : arg) {
        if (ch == '"') {
            out += "\\\"";
        } else {
            out.push_back(ch);
        }
    }
    out.push_back('"');
    return out;
}

bool is_running_as_admin() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

bool relaunch_as_admin_if_needed(int argc, char** argv) {
    if (is_running_as_admin()) {
        return false;
    }
    if (has_flag(argc, argv, "--elevated")) {
        return false;
    }
    if (has_flag(argc, argv, "--no-elevate")) {
        std::cout << "Skipping auto-elevation because --no-elevate was provided." << std::endl;
        return false;
    }
    if (has_any_flag(argc, argv, {"-h", "--help", "--version"})) {
        return false;
    }

    if (const char* env_disable_vif = std::getenv("CLINK_DISABLE_VIF")) {
        if (std::string_view(env_disable_vif) == "1") {
            std::cout << "VIF disabled by CLINK_DISABLE_VIF=1, skip elevation." << std::endl;
            return false;
        }
    }

    std::string params;
    for (int i = 1; i < argc; ++i) {
        if (!params.empty()) {
            params.push_back(' ');
        }
        params += quote_arg(argv[i]);
    }
    if (!params.empty()) {
        params.push_back(' ');
    }
    params += "--elevated";

    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = argv[0];
    sei.lpParameters = params.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&sei)) {
        const DWORD err = GetLastError();
        std::cerr << "Elevation request failed err=" << err << std::endl;
        std::cerr << "Please run this program as Administrator to enable VIF auto-create." << std::endl;
        return false;
    }

    std::cout << "Elevation requested. Waiting for elevated instance IPC pipe..." << std::endl;
    if (sei.hProcess) {
        // Poll the IPC pipe to detect when the elevated process is ready.
        // WaitForInputIdle is unreliable for console apps (no message pump).
        std::string pipe_path = read_ipc_address_from_config(argc, argv);
        if (pipe_path.empty()) {
            pipe_path = "\\\\.\\pipe\\clink-ipc";
        }
        constexpr int kMaxAttempts = 50; // 50 * 200ms = 10s timeout
        bool pipe_ready = false;

        for (int i = 0; i < kMaxAttempts; ++i) {
            // Check if elevated process exited prematurely
            DWORD exit_code = 0;
            if (GetExitCodeProcess(sei.hProcess, &exit_code) && exit_code != STILL_ACTIVE) {
                std::cerr << "Elevated process exited early, exit_code=" << exit_code << std::endl;
                break;
            }

            HANDLE hTest = CreateFileA(pipe_path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hTest != INVALID_HANDLE_VALUE) {
                CloseHandle(hTest);
                pipe_ready = true;
                break;
            }

            DWORD err = GetLastError();
            if (err != ERROR_PIPE_BUSY && err != ERROR_FILE_NOT_FOUND) {
                // Non-transient error, stop polling
                break;
            }

            Sleep(200);
        }

        if (pipe_ready) {
            std::cout << "Elevated process IPC pipe is ready." << std::endl;
        } else {
            std::cout << "Elevated process started (IPC pipe not detected within timeout)." << std::endl;
        }

        CloseHandle(sei.hProcess);
    }
    return true;
}
#endif

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_last_signal.store(signal);
        std::cout << "\nReceived shutdown signal, stopping..." << std::endl;
        if (auto* app = g_app_ptr.load()) {
            app->request_stop();
        }
    }
}

clink::core::logging::Level parse_log_level(std::string_view value) {
    std::string lowered{value};
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });

    if (lowered == "trace") {
        return clink::core::logging::Level::trace;
    }
    if (lowered == "debug") {
        return clink::core::logging::Level::debug;
    }
    if (lowered == "info") {
        return clink::core::logging::Level::info;
    }
    if (lowered == "warn") {
        return clink::core::logging::Level::warn;
    }
    if (lowered == "error") {
        return clink::core::logging::Level::error;
    }
    if (lowered == "critical") {
        return clink::core::logging::Level::critical;
    }
    return clink::core::logging::Level::info;
}

std::filesystem::path parse_config_path(int argc, char** argv, std::filesystem::path default_path) {
    std::filesystem::path path = std::move(default_path);
    if (const char* env = std::getenv("CLINK_CONFIG_PATH")) {
        path = env;
    }

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            path = argv[++i];
        }
    }
    return path;
}

void parse_extra_flags(int argc, char** argv, clink::core::ApplicationOptions& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg{argv[i]};
        if ((arg == "--log-level" || arg == "-l") && i + 1 < argc) {
            options.log_level = parse_log_level(argv[++i]);
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (has_any_flag(argc, argv, {"-h", "--help"})) {
        print_usage();
        return 0;
    }
    if (has_flag(argc, argv, "--version")) {
        print_version();
        return 0;
    }

#ifdef _WIN32
    if (relaunch_as_admin_if_needed(argc, argv)) {
        return 0;
    }
#endif

    clink::core::ApplicationOptions options;
#ifdef _WIN32
    options.identity = "clink-server: windows";
#else
    options.identity = "clink-server: linux";
#endif
    options.role = "service";
    options.heartbeat_interval = std::chrono::seconds(1);
    options.config_path = parse_config_path(argc, argv, options.config_path);
    options.auto_reload_config = true;
    parse_extra_flags(argc, argv, options);

    clink::core::Application app{options};
    g_app_ptr.store(&app);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        app.initialize();
        app.run();

        const int signal = g_last_signal.load();
        if (signal == SIGINT) {
            std::cout << "Shutdown reason: signal=SIGINT" << std::endl;
        } else if (signal == SIGTERM) {
            std::cout << "Shutdown reason: signal=SIGTERM" << std::endl;
        } else {
            std::cout << "Shutdown reason: normal_exit_or_external_stop" << std::endl;
        }

        app.Application::shutdown(std::chrono::seconds(5));
    } catch (const std::exception& ex) {
        std::cerr << "Service failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
