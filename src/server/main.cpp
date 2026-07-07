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

// ===== 全局状态 =====
// g_app_ptr：指向 Application 实例的原子指针，供信号处理器安全访问
// g_last_signal：记录收到的最后一个信号编号
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
    std::cout << "CLINK Daemon\n";
    std::cout << "Usage: clinkd [options]\n\n";
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
    std::cout << "clinkd " << kServerVersion << std::endl;
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
    std::filesystem::path config_path = get_flag_value(argc, argv, "-c");
    if (config_path.empty()) {
        config_path = get_flag_value(argc, argv, "--config");
    }
    if (config_path.empty()) {
        config_path = "config/clink.init.toml";
    }

    try {
        const auto configuration = clink::core::config::Configuration::load_from_file(config_path);
        return configuration.get_string("ipc.address", "");
    } catch (...) {
        return {};
    }
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

    // Use GetModuleFileNameA to obtain the full executable path instead of
    // relying on argv[0] which may be a relative path.  This ensures the
    // elevated process can always find the correct binary.
    char exe_path[MAX_PATH];
    const DWORD exe_len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
    if (exe_len == 0 || exe_len >= MAX_PATH) {
        std::cerr << "Failed to obtain executable path for elevation (err="
                  << GetLastError() << ")." << std::endl;
        std::cerr << "Please run this program as Administrator manually to enable VIF." << std::endl;
        return false;
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

    // Preserve the current working directory so the elevated instance can
    // locate relative-path resources (config, certs, logs, etc.).  Without
    // this the elevated process defaults to %WINDIR%\System32.
    char cwd[MAX_PATH];
    const DWORD cwd_len = GetCurrentDirectoryA(MAX_PATH, cwd);

    SHELLEXECUTEINFOA sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = exe_path;
    sei.lpParameters = params.c_str();
    sei.lpDirectory = (cwd_len > 0 && cwd_len < MAX_PATH) ? cwd : nullptr;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&sei)) {
        const DWORD err = GetLastError();
        std::cerr << "Elevation request failed err=" << err << std::endl;
        if (err == ERROR_CANCELLED) {
            std::cerr << "UAC prompt was denied by the user." << std::endl;
            std::cerr << "VIF virtual-interface features will NOT be available." << std::endl;
        }
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

// 信号处理器：SIGINT/SIGTERM → 仅调用 request_stop() 让主循环退出
// 不直接在信号处理器中做清理操作（避免重入 / 死锁风险）
void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_last_signal.store(signal);
        std::cout << "\nReceived shutdown signal, stopping..." << std::endl;
        if (auto* app = g_app_ptr.load()) {
            app->request_stop();  // 仅置 running_=false，实际清理在 shutdown() 中
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

// ===== 入口 =====
// 三步启动：解析参数 → initialize（创建子系统）→ run（事件循环）
// shutdown 由信号触发，主循环退出后自动调用
int main(int argc, char** argv) {
    // --help 和 --version 立即返回，不触发提权
    if (has_any_flag(argc, argv, {"-h", "--help"})) {
        print_usage();
        return 0;
    }
    if (has_flag(argc, argv, "--version")) {
        print_version();
        return 0;
    }

#ifdef _WIN32
    // 自动提权：发现不是管理员且有 VIF 需求时，通过 ShellExecuteEx runas 重启自身
    // 提权后由 elevated 子进程执行后续逻辑，原进程退出
    if (relaunch_as_admin_if_needed(argc, argv)) {
        return 0;
    }
#endif

    clink::core::ApplicationOptions options;
#ifdef _WIN32
    options.identity = "clinkd: windows";
#else
    options.identity = "clinkd: linux";
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
        app.initialize();  // 第一步：装载配置、创建子系统、启动 IPC 和 PM
        app.run();         // 第二步：启动模块、进入事件循环，阻塞直到 request_stop()

        const int signal = g_last_signal.load();
        if (signal == SIGINT) {
            std::cout << "Shutdown reason: signal=SIGINT" << std::endl;
        } else if (signal == SIGTERM) {
            std::cout << "Shutdown reason: signal=SIGTERM" << std::endl;
        } else {
            std::cout << "Shutdown reason: normal_exit_or_external_stop" << std::endl;
        }

        app.Application::shutdown(std::chrono::seconds(5));  // 第三步：逆序关停所有子系统（5秒超时）
    } catch (const std::exception& ex) {
        std::cerr << "Service failed: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
