#include "src/client/core/application/application.hpp"
#include "src/client/core/utils/terminal.hpp"
#include "src/share/core/config/log_path_utils.hpp"
#include "src/share/core/security/base64.hpp"
#include "src/share/include/clink/protocol/control_plane.hpp"
#include "src/server/core/security/dpapi_helper.hpp"
#include <nlohmann/json.hpp>
#include <chrono>
#include <cctype>
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
namespace control_plane = clink::protocol::control_plane;

#ifdef _WIN32
constexpr const char* kDefaultIpcPipe = "\\\\.\\pipe\\clink-ipc";
#else
constexpr const char* kDefaultIpcPipe = "/tmp/clink-ipc.sock";
#endif

// File-scope IPC pipe resolved once in main() before any handler runs
static std::string g_resolved_ipc_pipe;

// Resolve IPC address from command line (--ipc), env, or config
void resolve_ipc_pipe(int argc, char** argv,
                      const clink::core::config::Configuration& config) {
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--ipc" && i + 1 < argc) {
            g_resolved_ipc_pipe = argv[i + 1];
            return;
        }
    }
    std::string cfg_addr = config.get_string("ipc.address", "");
    g_resolved_ipc_pipe = cfg_addr.empty() ? kDefaultIpcPipe : cfg_addr;
}

// Overload for handlers that don't have argc/argv — reads from config
std::string get_ipc_pipe(const clink::core::config::Configuration& config) {
    if (!g_resolved_ipc_pipe.empty()) return g_resolved_ipc_pipe;
    return config.get_string("ipc.address", kDefaultIpcPipe);
}

struct IpcEnvelope {
    bool ok{false};
    std::string command;
    json data;
    std::string error;
    std::string raw;
};

struct CommandOutcome {
    bool ok{false};
    bool accepted{false};
    bool restart_required{false};
};

struct ConnectAttemptOutcome {
    bool envelope_ok{false};
    bool accepted{false};
    bool fallback_recommended{false};
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
    Terminal::println("Usage: clink [options] <command>");
    Terminal::println("\nOptions:");
    Terminal::println("  -c, --config <path>      Path to configuration file");
    Terminal::println("      --ip <address>       Override remote server address for connect");
    Terminal::println("      --port <port>        Override remote server port for connect");
    Terminal::println("      --transport <type>   tcp|tls (connect only, default: tls)");
    Terminal::println("      --timeout <ms>       Connect timeout hint (connect only)");
    Terminal::println("      --no-self-check      Allow self-connect check bypass (debug)");
    Terminal::println("      --allow-all          Auto fallback/retry without confirmation");
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
    Terminal::println("Show daemon logs; --tail also shows status alerts");
    Terminal::print("  encrypt     ", Color::Blue);
    Terminal::println("Encrypt a secret using DPAPI");
    Terminal::println("\nExit codes:");
    Terminal::println("  0  success");
    Terminal::println("  1  failed or rejected");
    Terminal::println("  2  success, but restart required");
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
            if ((arg == "--config" || arg == "-c" || arg == "--ip" || arg == "--port" || arg == "--transport" || arg == "--timeout" || arg == "--ipc") && i + 1 < argc) {
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
        if (root.is_object() && root.contains(control_plane::kEnvelopeOk)) {
            out.ok = jget<bool>(root, control_plane::kEnvelopeOk, false);
            out.command = jget<std::string>(root, control_plane::kEnvelopeCommand, "");
            out.error = jget<std::string>(root, control_plane::kEnvelopeError, "");
            out.data = root.contains(control_plane::kEnvelopeData) ? root[control_plane::kEnvelopeData] : json::object();
        } else if (root.is_object() && root.contains(control_plane::kEnvelopeError) &&
                   !root.contains(control_plane::kFieldStatus)) {
            out.ok = false;
            out.command = jget<std::string>(root, control_plane::kEnvelopeCommand, "");
            out.error = jget<std::string>(root, control_plane::kEnvelopeError, "unknown error");
            out.data = root;
        } else {
            out.ok = true;
            out.command = jget<std::string>(root, control_plane::kEnvelopeCommand, "");
            out.error.clear();
            out.data = root;
        }
    }catch (const std::exception& e) {
        out.ok = false;
        out.error = std::string("invalid json payload: ") + e.what();
        out.data = json::object();
    }

    if (out.error.empty() && out.data.is_object()) {
        const std::string message = jget<std::string>(out.data, control_plane::kFieldMessage, "");
        const std::string reason = jget<std::string>(out.data, control_plane::kFieldReason, "");
        if (!message.empty()) {
            out.error = message;
        } else if (!reason.empty() && !out.ok) {
            out.error = reason;
        }
    }

    return out;
}

bool payload_accepted(const json& payload, bool default_value = true) {
    if (!payload.is_object()) {
        return default_value;
    }

    if (payload.contains(control_plane::kFieldAccepted) && payload.at(control_plane::kFieldAccepted).is_boolean()) {
        return payload.at(control_plane::kFieldAccepted).get<bool>();
    }

    const std::string status = jget<std::string>(payload, control_plane::kFieldStatus, "");
    if (status == control_plane::kStatusFailed || status == control_plane::kStatusRejected ||
        status == control_plane::kStatusError || status == control_plane::kStatusTimeout) {
        return false;
    }

    if (status == control_plane::kStatusOk || status == control_plane::kStatusPending ||
        status == control_plane::kStatusConnected || status == control_plane::kStatusDisconnecting ||
        status == control_plane::kStatusDisconnected) {
        return true;
    }

    return default_value;
}

std::string envelope_error_text(const IpcEnvelope& envelope) {
    if (!envelope.error.empty()) {
        return envelope.error;
    }

    if (envelope.data.is_object()) {
        const std::string message = jget<std::string>(envelope.data, control_plane::kFieldMessage, "");
        if (!message.empty()) {
            return message;
        }

        const std::string reason = jget<std::string>(envelope.data, control_plane::kFieldReason, "");
        if (!reason.empty()) {
            return reason;
        }
    }

    return envelope.raw.empty() ? std::string("unknown error") : envelope.raw;
}

void print_restart_notice(const json& payload) {
    if (!jget<bool>(payload, control_plane::kFieldRestartRequired, false)) {
        return;
    }

    Terminal::print("Restart Required: ", Color::White);
    Terminal::println("YES", Color::Yellow);
    if (payload.contains(control_plane::kFieldRestartReasons) &&
        payload.at(control_plane::kFieldRestartReasons).is_array() &&
        !payload.at(control_plane::kFieldRestartReasons).empty()) {
        std::string reasons;
        for (const auto& item : payload.at(control_plane::kFieldRestartReasons)) {
            const std::string reason = item.is_string() ? item.get<std::string>() : item.dump();
            if (!reasons.empty()) {
                reasons += ", ";
            }
            reasons += reason;
        }
        Terminal::println("  reasons: " + reasons, Color::Yellow);
    }
    Terminal::println("  hint: restart the running process to fully apply deferred configuration changes.", Color::Yellow);

    const std::string effective_ipc = jget<std::string>(payload, control_plane::kFieldEffectiveIpcAddress, "");
    const std::string configured_ipc = jget<std::string>(payload, control_plane::kFieldConfiguredIpcAddress, "");
    if (!effective_ipc.empty() || !configured_ipc.empty()) {
        Terminal::println("  ipc: effective=" + effective_ipc + " configured=" + configured_ipc, Color::Yellow);
    }
    if (payload.contains(control_plane::kFieldConfigReloadSupported) &&
        !jget<bool>(payload, control_plane::kFieldConfigReloadSupported, true)) {
        Terminal::println("  note: live config reload is not supported for this process; restart is the only way to apply drifted config.", Color::Yellow);
    }
}
bool payload_requires_restart(const json& payload) {
    return payload.is_object() && jget<bool>(payload, control_plane::kFieldRestartRequired, false);
}

std::string resolve_expected_log_path(const clink::core::config::Configuration& configuration) {
    return clink::core::config::resolve_log_file_path(configuration, "logs/clink.log");
}

void add_unique_line(std::vector<std::string>& lines, std::string line) {
    if (line.empty()) {
        return;
    }
    if (std::find(lines.begin(), lines.end(), line) == lines.end()) {
        lines.push_back(std::move(line));
    }
}

std::vector<std::string> build_restart_hints(const json& payload) {
    std::vector<std::string> hints;
    if (!payload_requires_restart(payload)) {
        return hints;
    }

    if (payload.contains(control_plane::kFieldRestartReasons) && payload.at(control_plane::kFieldRestartReasons).is_array()) {
        for (const auto& item : payload.at(control_plane::kFieldRestartReasons)) {
            const std::string reason = item.is_string() ? item.get<std::string>() : item.dump();
            if (reason == control_plane::kConfigDomainIpcAddress) {
                add_unique_line(hints, "Restart the process to bind the new IPC address.");
            } else if (reason == control_plane::kConfigDomainProcessManagerRuntime) {
                add_unique_line(hints, "Restart the daemon to apply process-manager / SOCKS / injection configuration changes.");
            } else if (reason == control_plane::kConfigDomainLogging) {
                add_unique_line(hints, "Restart the process to propagate logging changes to already-constructed components.");
            } else if (reason == control_plane::kConfigDomainTransportRuntime) {
                add_unique_line(hints, "Restart the client to apply transport / TLS configuration changes.");
            } else {
                add_unique_line(hints, "Restart the process to apply deferred configuration changes: " + reason);
            }
        }
    }

    if (payload.contains(control_plane::kFieldConfigReloadSupported) &&
        !jget<bool>(payload, control_plane::kFieldConfigReloadSupported, true)) {
        add_unique_line(hints, "Live config reload is not supported for this process; restart is required for convergence.");
    }

    return hints;
}

std::vector<std::string> build_status_alerts(const json& payload) {
    std::vector<std::string> alerts;

    const std::string health = jget<std::string>(payload, control_plane::kFieldHealth, "");
    if (health == control_plane::kHealthRed) {
        add_unique_line(alerts, "Daemon health is RED.");
    } else if (health == control_plane::kHealthYellow) {
        add_unique_line(alerts, "Daemon health is DEGRADED.");
    }

    if (payload.contains(control_plane::kFieldProcessManager) && payload.at(control_plane::kFieldProcessManager).is_object()) {
        const auto& pm = payload.at(control_plane::kFieldProcessManager);
        const std::string pm_state = jget<std::string>(pm, control_plane::kFieldState, "");
        const std::string pm_reason = jget<std::string>(pm, control_plane::kFieldReason, "");
        if (pm_state == control_plane::kStatusFailed) {
            add_unique_line(alerts, "Process manager failed: " + pm_reason);
        } else if (pm_state == control_plane::kStateDegraded) {
            add_unique_line(alerts, "Process manager is degraded: " + pm_reason);
        }
    }

    const std::string config_status = jget<std::string>(payload, control_plane::kFieldConfigStatus, "");
    if (!config_status.empty()) {
        add_unique_line(alerts, "Config status: " + config_status);
    }

    const std::string connect_phase = jget<std::string>(payload, control_plane::kFieldConnectPhase, "");
    const std::string connect_reason = jget<std::string>(payload, control_plane::kFieldConnectReason, "");
    const std::string connect_message = jget<std::string>(payload, control_plane::kFieldConnectMessage, "");
    if ((connect_phase == control_plane::kStatusFailed || connect_phase == control_plane::kStatusRejected) &&
        !connect_reason.empty() && connect_reason != control_plane::kValueNone) {
        add_unique_line(alerts, "Last connect issue: " + connect_reason + (connect_message.empty() ? std::string{} : " - " + connect_message));
    }

    const auto restart_hints = build_restart_hints(payload);
    for (const auto& hint : restart_hints) {
        add_unique_line(alerts, hint);
    }

    return alerts;
}

void print_monitor_alert_banner(const json& payload) {
    const auto alerts = build_status_alerts(payload);
    if (alerts.empty()) {
        return;
    }

    Terminal::println("Alerts:", Color::BrightYellow);
    for (const auto& alert : alerts) {
        Terminal::println("  - " + alert, Color::Yellow);
    }
    Terminal::println(std::string(80, '='), Color::Yellow);
}

bool should_offer_tcp_fallback(const IpcEnvelope& envelope) {
    if (!envelope.ok) {
        return false;
    }

    if (payload_accepted(envelope.data, false)) {
        return false;
    }

    const std::string status = jget<std::string>(envelope.data, control_plane::kFieldStatus, "");
    const std::string reason = jget<std::string>(envelope.data, control_plane::kFieldReason, "");

    if (reason == control_plane::kReasonTransportStartFailed || reason == control_plane::kReasonTransportMismatch) {
        return true;
    }

    return status == control_plane::kStatusFailed && reason.empty();
}
void print_status_table(const json& payload, bool show_restart_details = true) {
    Terminal::println("--- CLINK DAEMON STATUS ---", Color::BrightCyan);
    const std::string status = jget<std::string>(payload, control_plane::kFieldStatus, control_plane::kStatusDisconnected);
    const std::string session_id = jget<std::string>(payload, control_plane::kFieldSessionId, "");
    const auto active_sessions = jget<int>(payload, control_plane::kFieldActiveSessions, 0);
    const auto tracked_sessions = jget<int>(payload, control_plane::kFieldTrackedSessions, active_sessions);
    const std::string connect_phase = jget<std::string>(payload, control_plane::kFieldConnectPhase, "");
    const std::string connect_reason = jget<std::string>(payload, control_plane::kFieldConnectReason, "");
    const std::string connect_message = jget<std::string>(payload, control_plane::kFieldConnectMessage, "");
    const std::string health = jget<std::string>(payload, control_plane::kFieldHealth, "");
    Terminal::print("Service Status: ", Color::White);
    if (status == control_plane::kStatusConnected) Terminal::println("CONNECTED", Color::BrightGreen);
    else if (status == control_plane::kStatusConnecting) Terminal::println("CONNECTING", Color::Yellow);
    else if (status == control_plane::kStatusDisconnecting) Terminal::println("DISCONNECTING", Color::Yellow);
    else Terminal::println("DISCONNECTED", Color::Red);
    if (!session_id.empty() && session_id != "null" && session_id != control_plane::kValueNone) {
        Terminal::print("Session ID:     ", Color::White);
        Terminal::println(session_id, Color::Cyan);
    }
    Terminal::print("Active Sessions:", Color::White);
    Terminal::println(std::to_string(active_sessions), Color::BrightWhite);
    if (tracked_sessions != active_sessions) {
        Terminal::print("Tracked Sessions: ", Color::White);
        Terminal::println(std::to_string(tracked_sessions), Color::BrightWhite);
    }
    if (!health.empty()) {
        Terminal::print("Health:         ", Color::White);
        if (health == control_plane::kHealthGreen) Terminal::println("GREEN", Color::BrightGreen);
        else if (health == control_plane::kHealthYellow) Terminal::println("YELLOW", Color::Yellow);
        else Terminal::println("RED", Color::Red);
    }
    if (!connect_phase.empty() && connect_phase != control_plane::kStatusIdle) {
        Terminal::print("Connect Phase:  ", Color::White);
        Terminal::println(connect_phase, Color::Cyan);
    }
    if (!connect_reason.empty() && connect_reason != control_plane::kValueNone) {
        Terminal::print("Connect Reason: ", Color::White);
        Terminal::println(connect_reason, Color::Yellow);
    }
    if (!connect_message.empty()) {
        Terminal::print("Connect Msg:    ", Color::White);
        Terminal::println(connect_message, Color::Yellow);
    }
    const std::string config_status = jget<std::string>(payload, control_plane::kFieldConfigStatus, "");
    if (!config_status.empty()) {
        Terminal::print("Config Status:  ", Color::White);
        Terminal::println(config_status, Color::Yellow);
    }
    if (payload.contains(control_plane::kFieldProcessManager) && payload.at(control_plane::kFieldProcessManager).is_object()) {
        const auto& pm = payload.at(control_plane::kFieldProcessManager);
        Terminal::print("ProcessMgr:     ", Color::White);
        Terminal::println(jget<std::string>(pm, control_plane::kFieldState, control_plane::kStatusUnknown) +
                          " backend=" + jget<std::string>(pm, control_plane::kFieldSocksBackend, control_plane::kValueNone) +
                          " reason=" + jget<std::string>(pm, control_plane::kFieldReason, control_plane::kValueNone),
                          jget<std::string>(pm, control_plane::kFieldState, "") == control_plane::kStatusFailed ? Color::Red : Color::Cyan);
    }
    if (payload.contains(control_plane::kFieldEffectiveIpcAddress) || payload.contains(control_plane::kFieldConfiguredIpcAddress)) {
        Terminal::print("IPC Address:    ", Color::White);
        Terminal::println(jget<std::string>(payload, control_plane::kFieldEffectiveIpcAddress, "") +
                          " (configured=" + jget<std::string>(payload, control_plane::kFieldConfiguredIpcAddress, "") + ")",
                          Color::White);
    }
    if (show_restart_details) {
        print_restart_notice(payload);
    }
    if (!payload.contains(control_plane::kFieldSessions) || !payload.at(control_plane::kFieldSessions).is_array()) {
        return;
    }
    Terminal::println(std::string("\n") + (tracked_sessions > active_sessions ? "Tracked Sessions:" : "Active Sessions:"), Color::BrightWhite);
    Terminal::println(std::string(80, '-'), Color::White);
    std::cout << std::left << std::setw(15) << "Session ID"
              << std::setw(14) << "Status"
              << std::setw(12) << "Sent"
              << std::setw(12) << "Received"
              << std::setw(8) << "RTT"
              << std::setw(8) << "Retrans" << std::endl;
    for (const auto& s : payload.at(control_plane::kFieldSessions)) {
        const std::string id = jget<std::string>(s, control_plane::kFieldId, "");
        const std::string session_status = jget<std::string>(s, control_plane::kFieldStatus, control_plane::kStatusUnknown);
        const uint64_t sent = jget<uint64_t>(s, "bytes_sent", 0);
        const uint64_t recv = jget<uint64_t>(s, "bytes_received", 0);
        const auto rtt = jget<int64_t>(s, "rtt_ms", 0);
        const uint64_t corrupted = jget<uint64_t>(s, "corrupted_packets", 0);
        const uint64_t retrans = jget<uint64_t>(s, "retrans_count", 0);
        std::cout << std::left
                  << std::setw(15) << (id.size() > 12 ? id.substr(0, 12) + ".." : id)
                  << std::setw(14) << session_status
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
CommandOutcome send_command_and_print(clink::core::ipc::IpcClient& client, const std::string& command, const std::string& payload = "") {
    auto response = client.send_request({clink::core::ipc::MessageType::Request, command, payload});
    const auto envelope = parse_response_envelope(response.payload);
    CommandOutcome outcome;
    outcome.ok = envelope.ok;
    outcome.accepted = false;
    outcome.restart_required = payload_requires_restart(envelope.data);

    if (command == "connect" && envelope.ok) {
        const bool accepted = payload_accepted(envelope.data, true);
        const std::string status = jget<std::string>(envelope.data, control_plane::kFieldStatus, control_plane::kStatusUnknown);
        const std::string reason = jget<std::string>(envelope.data, control_plane::kFieldReason, "");
        const std::string message = jget<std::string>(envelope.data, control_plane::kFieldMessage, "");
        const std::string endpoint = jget<std::string>(envelope.data, "endpoint", "");

        Terminal::print("Connect result: ", Color::BrightWhite);
        if (accepted) {
            Terminal::println(status, Color::Green);
        } else {
            Terminal::println(status, Color::Yellow);
            if (!reason.empty()) {
                Terminal::println("  reason: " + reason, Color::Yellow);
            }
            if (!message.empty()) {
                Terminal::println("  message: " + message, Color::Yellow);
            }
            if (!endpoint.empty()) {
                Terminal::println("  endpoint: " + endpoint, Color::Yellow);
            }
        }

        Terminal::print("Response: ", Color::BrightWhite);
        Terminal::println(envelope.raw, accepted ? Color::Green : Color::Yellow);
        outcome.accepted = accepted;
        return outcome;
    }

    Terminal::print("Response: ", Color::BrightWhite);
    if (envelope.ok) {
        const bool accepted = payload_accepted(envelope.data, true);
        const std::string reason = jget<std::string>(envelope.data, "reason", "");
        const std::string message = jget<std::string>(envelope.data, "message", "");
        Terminal::println(envelope.raw, accepted ? Color::Green : Color::Yellow);
        if (!accepted) {
            if (!reason.empty()) {
                Terminal::println("  reason: " + reason, Color::Yellow);
            }
            if (!message.empty()) {
                Terminal::println("  message: " + message, Color::Yellow);
            }
        }
        if ((command == "reload" || command == "disconnect") && envelope.data.is_object()) {
            print_status_table(envelope.data);
        }
        outcome.accepted = accepted;
        return outcome;
    }
    Terminal::println(envelope_error_text(envelope), Color::Yellow);
    return outcome;
}
int handle_status(clink::core::Application& app) {
    auto& client = app.ipc_client();
    client.connect(get_ipc_pipe(app.configuration()));
    auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
    const auto envelope = parse_response_envelope(response.payload);
    if (!envelope.ok) {
        Terminal::println("Failed to get status: " + envelope_error_text(envelope), Color::Red);
        return 1;
    }
    print_status_table(envelope.data);
    return payload_requires_restart(envelope.data) ? 2 : 0;
}
int handle_monitor(clink::core::Application& app) {
    auto& client = app.ipc_client();
    client.connect(get_ipc_pipe(app.configuration()));
    Terminal::println("Starting real-time monitor (Ctrl+C to exit)...", Color::Cyan);
    while (true) {
        auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
        const auto envelope = parse_response_envelope(response.payload);
        Terminal::clear_screen();
        Terminal::println("=== CLINK MONITOR (Ctrl+C to exit) ===", Color::BrightMagenta);
        if (!envelope.ok) {
            Terminal::println("Connection error: " + envelope_error_text(envelope), Color::Red);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        print_monitor_alert_banner(envelope.data);
        print_status_table(envelope.data, false);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
int handle_diag(clink::core::Application& app, const clink::core::ApplicationOptions& options) {
    int exit_code = 0;
    std::vector<std::string> suggestions;
    std::string expected_log_path = "logs/clink.log";
    auto mark_warning = [&]() {
        if (exit_code == 0) {
            exit_code = 2;
        }
    };
    auto mark_failure = [&]() {
        exit_code = 1;
    };

    Terminal::println("=== CLINK DIAGNOSTIC TOOL ===", Color::BrightCyan);
    Terminal::print("[1/4] Checking configuration... ", Color::White);
    try {
        if (std::filesystem::exists(options.config_path)) {
            auto cfg = clink::core::config::Configuration::load_from_file(options.config_path);
            expected_log_path = resolve_expected_log_path(cfg);
            (void)cfg;
            Terminal::println("OK", Color::Green);
            Terminal::println("      Path: " + options.config_path.string(), Color::White);
        }else {
            Terminal::println("MISSING", Color::Yellow);
            Terminal::println("      Using default values.", Color::White);
            mark_warning();
            add_unique_line(suggestions, "Create the config file or pass --config to avoid relying on implicit defaults.");
        }
    }catch (const std::exception& e) {
        Terminal::println("ERROR", Color::Red);
        Terminal::println("      " + std::string(e.what()), Color::Red);
        mark_failure();
        add_unique_line(suggestions, "Fix the configuration file syntax/path before retrying diag.");
    }
    Terminal::print("[2/4] Checking daemon connectivity... ", Color::White);
    auto& client = app.ipc_client();
    try {
        client.connect(get_ipc_pipe(app.configuration()));
        auto response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
        const auto env = parse_response_envelope(response.payload);
        if (env.ok) {
            Terminal::println("OK", Color::Green);
            Terminal::println("      Daemon is responding.", Color::White);
            if (payload_requires_restart(env.data)) {
                mark_warning();
                Terminal::println("      Restart required to fully apply current configuration.", Color::Yellow);
                for (const auto& hint : build_restart_hints(env.data)) {
                    add_unique_line(suggestions, hint);
                }
            }
            const std::string health = jget<std::string>(env.data, "health", "");
            if (health == control_plane::kHealthYellow) {
                mark_warning();
                Terminal::println("      Daemon health is degraded (yellow).", Color::Yellow);
                add_unique_line(suggestions, "Inspect daemon logs and process-manager state to understand degraded health.");
            } else if (health == control_plane::kHealthRed) {
                mark_warning();
                Terminal::println("      Daemon health reports red status.", Color::Yellow);
                add_unique_line(suggestions, "Check daemon logs immediately; a core subsystem is failed or unavailable.");
            }
            const std::string config_status = jget<std::string>(env.data, "config_status", "");
            if (!config_status.empty()) {
                mark_warning();
                Terminal::println("      Config status: " + config_status, Color::Yellow);
                add_unique_line(suggestions, "Repair the config file readability issue so runtime status can track config drift correctly.");
            }
            const std::string connect_reason = jget<std::string>(env.data, "connect_reason", "");
            const std::string connect_message = jget<std::string>(env.data, "connect_message", "");
            if (!connect_reason.empty() &&
                connect_reason != control_plane::kValueNone &&
                connect_reason != control_plane::kReasonDisconnectComplete) {
                add_unique_line(suggestions, "Review the last connect failure: " + connect_reason + (connect_message.empty() ? std::string{} : " - " + connect_message));
            }
        }else {
            Terminal::println("FAILED", Color::Red);
            Terminal::println("      " + envelope_error_text(env), Color::Yellow);
            mark_failure();
            add_unique_line(suggestions, "Start the daemon and confirm the local IPC endpoint is accessible before retrying.");
        }
    }catch (...) {
        Terminal::println("FAILED", Color::Red);
        Terminal::println("      Daemon might not be running or pipe is inaccessible.", Color::Yellow);
        mark_failure();
        add_unique_line(suggestions, "Verify the daemon is running and that the IPC endpoint/permissions are correct.");
    }
    Terminal::print("[3/4] Checking internet access... ", Color::White);
#ifdef _WIN32
    const int res = std::system("ping -n 1 8.8.8.8 > nul");
    Terminal::println(res == 0 ? "OK" : "FAILED", res == 0 ? Color::Green : Color::Red);
#else
    const int res = std::system("ping -c 1 8.8.8.8 > /dev/null 2>&1");
    Terminal::println(res == 0 ? "OK" : "FAILED", res == 0 ? Color::Green : Color::Red);
#endif
    if (res != 0) {
        mark_warning();
        Terminal::println("      External network reachability failed; this may be environmental.", Color::Yellow);
        add_unique_line(suggestions, "Check firewall, routing, DNS, or offline network conditions if remote connectivity is expected.");
    }
    Terminal::print("[4/4] Checking log files... ", Color::White);
    std::filesystem::path log_path = expected_log_path;
    if (std::filesystem::exists(log_path)) {
        auto size = std::filesystem::file_size(log_path);
        Terminal::println("OK", Color::Green);
        Terminal::println("      Path: " + log_path.string() + " (" + format_bytes(size) + ")", Color::White);
    }else {
        Terminal::println("NOT FOUND", Color::Yellow);
        Terminal::println("      Logs may not have been generated yet.", Color::White);
        mark_warning();
        add_unique_line(suggestions, "Confirm logging is enabled and the daemon has written at least one log file.");
    }
    Terminal::print("\nDiagnostic summary: ", Color::BrightCyan);
    if (exit_code == 0) {
        Terminal::println("OK", Color::Green);
    } else if (exit_code == 2) {
        Terminal::println("WARN", Color::Yellow);
    } else {
        Terminal::println("FAILED", Color::Red);
    }
    if (!suggestions.empty()) {
        Terminal::println("Suggestions:", Color::BrightYellow);
        for (const auto& suggestion : suggestions) {
            Terminal::println("  - " + suggestion, Color::Yellow);
        }
    }
    return exit_code;
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
        client.connect(get_ipc_pipe(app.configuration()));
        std::string last_content;
        std::string last_alert_signature;
        do {
            if (tail) {
                auto status_response = client.send_request({clink::core::ipc::MessageType::Request, "status", ""});
                const auto status_env = parse_response_envelope(status_response.payload);
                if (status_env.ok) {
                    const auto alerts = build_status_alerts(status_env.data);
                    const std::string alert_signature = json(alerts).dump();
                    if (alert_signature != last_alert_signature) {
                        if (!alerts.empty()) {
                            Terminal::println("=== STATUS ALERTS ===", Color::BrightYellow);
                            for (const auto& alert : alerts) {
                                Terminal::println("  - " + alert, Color::Yellow);
                            }
                            Terminal::println(std::string(80, '='), Color::Yellow);
                        } else if (!last_alert_signature.empty()) {
                            Terminal::println("=== STATUS ALERTS CLEARED ===", Color::Green);
                        }
                        last_alert_signature = alert_signature;
                    }
                }
            }

            auto response = client.send_request({clink::core::ipc::MessageType::Request, "logs", ""});
            const auto env = parse_response_envelope(response.payload);
            if (!env.ok) {
                Terminal::println(envelope_error_text(env), Color::Red);
                return 1;
            }
            const std::string content = jget<std::string>(env.data, "content", "");
            const std::string path = jget<std::string>(env.data, "path", "");
            if (!path.empty() && last_content.empty()) {
                Terminal::println("Log source: " + path, Color::Cyan);
            }
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
        std::cout << "Usage: clink encrypt <secret>" << std::endl;
        return 1;
    }
    try {
        auto encrypted = clink::core::security::DpapiHelper::encrypt(secret);
        auto base64 = clink::core::security::to_base64(encrypted);
        std::cout << "Encrypted secret (Base64): " << base64 << std::endl;
        std::cout << "Copy this into your config file." << std::endl;
        return 0;
    }catch (const std::exception& e) {
        std::cerr << "Encryption failed: " << e.what() << std::endl;
        return 1;
    }
}

struct ConnectCliOptions {
    std::string ip{"127.0.0.1"};
    std::string port{"4433"};
    std::string transport{"tls"};
    int timeout_ms{0};
    bool no_self_check{false};
    bool allow_all{false};
    bool transport_explicit{false};
    bool endpoint_override{false};

    bool has_daemon_payload() const noexcept {
        return endpoint_override || transport_explicit || timeout_ms > 0 || no_self_check;
    }
};

ConnectCliOptions parse_connect_cli_options(int argc, char** argv) {
    ConnectCliOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg{argv[i]};
        if (arg == "--ip" && i + 1 < argc) {
            opts.ip = argv[++i];
            opts.endpoint_override = true;
        } else if (arg == "--port" && i + 1 < argc) {
            opts.port = argv[++i];
            opts.endpoint_override = true;
        } else if (arg == "--transport" && i + 1 < argc) {
            opts.transport = argv[++i];
            opts.transport_explicit = true;
        } else if (arg == "--timeout" && i + 1 < argc) {
            try {
                opts.timeout_ms = std::stoi(argv[++i]);
                if (opts.timeout_ms < 0) opts.timeout_ms = 0;
            } catch (...) {
                opts.timeout_ms = 0;
            }
        } else if (arg == "--no-self-check") {
            opts.no_self_check = true;
        } else if (arg == "--allow-all") {
            opts.allow_all = true;
        } else if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            ++i;
        }
    }

    if (opts.transport != "tls" && opts.transport != "tcp") {
        opts.transport = "tls";
    }

    return opts;
}

std::string build_connect_payload(const ConnectCliOptions& opts, const std::string& transport_override = "") {
    std::string transport = transport_override.empty() ? opts.transport : transport_override;
    nlohmann::json payload;
    if (opts.endpoint_override) {
        payload["endpoint"] = transport + "://" + opts.ip + ":" + opts.port;
    }
    if (opts.transport_explicit || opts.endpoint_override) {
        payload["transport"] = transport;
    }
    if (opts.timeout_ms > 0) {
        payload["timeout_ms"] = opts.timeout_ms;
    }
    if (opts.no_self_check) {
        payload["no_self_check"] = true;
    }
    if (opts.allow_all) {
        payload["allow_all"] = true;
    }
    return payload.dump();
}

bool prompt_yes_no(const std::string& question, bool default_yes = false) {
    Terminal::print(question, Color::Yellow);
    Terminal::print(default_yes ? " [Y/n]: " : " [y/N]: ", Color::Yellow);
    std::string input;
    std::getline(std::cin, input);

    if (input.empty()) {
        return default_yes;
    }

    const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(input[0])));
    return c == 'y';
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
    options.identity = "clink";
    options.role = "cli";
    options.heartbeat_interval = std::chrono::milliseconds(250);
    options.config_path = parse_config_path(argc, argv, options.config_path);
    clink::core::Application app{options};
    try {
        app.initialize();
        resolve_ipc_pipe(argc, argv, app.configuration());
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
            client.connect(g_resolved_ipc_pipe);

            if (command == "connect") {
                const auto connect_opts = parse_connect_cli_options(argc, argv);

                auto try_connect_with_transport = [&](const std::string& transport, const std::string& label) -> ConnectAttemptOutcome {
                    const std::string payload = build_connect_payload(connect_opts, transport);
                    Terminal::println("Connect target: " + transport + "://" + connect_opts.ip + ":" + connect_opts.port, Color::Yellow);

                    auto response = client.send_request({clink::core::ipc::MessageType::Request, "connect", payload});
                    auto envelope = parse_response_envelope(response.payload);
                    ConnectAttemptOutcome outcome;
                    outcome.envelope_ok = envelope.ok;

                    if (!envelope.ok) {
                        Terminal::println(label + " connect failed at IPC/application layer.", Color::Yellow);
                        Terminal::println("  error: " + envelope_error_text(envelope), Color::Yellow);
                        return outcome;
                    }

                    const bool accepted = payload_accepted(envelope.data, false);
                    const std::string status = jget<std::string>(envelope.data,
                                                                  control_plane::kFieldStatus,
                                                                  control_plane::kStatusUnknown);
                    const std::string reason = jget<std::string>(envelope.data, control_plane::kFieldReason, "");
                    const std::string message = jget<std::string>(envelope.data, control_plane::kFieldMessage, "");

                    Terminal::print(label + " connect result: ", Color::BrightWhite);
                    Terminal::println(status, accepted ? Color::Green : Color::Yellow);
                    if (!reason.empty()) Terminal::println("  reason: " + reason, Color::Yellow);
                    if (!message.empty()) Terminal::println("  message: " + message, Color::Yellow);
                    if (reason == control_plane::kReasonSelfConnectBlocked) {
                        Terminal::println("  hint: target resolves to local listener. Use another host/IP or enable network.allow_self_connect=true for debug.", Color::Yellow);
                    }
                    Terminal::print("Response: ", Color::BrightWhite);
                    Terminal::println(envelope.raw, accepted ? Color::Green : Color::Yellow);
                    outcome.accepted = accepted;
                    outcome.fallback_recommended = should_offer_tcp_fallback(envelope);
                    return outcome;
                };

                if (!connect_opts.endpoint_override) {
                    Terminal::println("Connect target: daemon configuration (transport.server_endpoint/client.remote_endpoint)", Color::Yellow);
                    const auto payload = connect_opts.has_daemon_payload() ? build_connect_payload(connect_opts) : std::string{};
                    const auto outcome = send_command_and_print(client, "connect", payload);
                    rc = (outcome.ok && outcome.accepted) ? 0 : 1;
                } else if (connect_opts.transport_explicit) {
                    const auto outcome = try_connect_with_transport(connect_opts.transport, connect_opts.transport == "tls" ? "TLS" : "TCP");
                    rc = outcome.accepted ? 0 : 1;
                } else {
                    const auto tls_outcome = try_connect_with_transport("tls", "TLS");
                    if (tls_outcome.accepted) {
                        rc = 0;
                    } else if (!tls_outcome.fallback_recommended) {
                        Terminal::println("TCP fallback skipped because the rejection is not transport-related.", Color::Yellow);
                        rc = 1;
                    } else {
                        Terminal::println("TLS unavailable or rejected. TCP fallback is available.", Color::Yellow);

                        bool do_fallback = false;
                        if (connect_opts.allow_all) {
                            do_fallback = true;
                            Terminal::println("--allow-all enabled, retrying with tcp automatically...", Color::Yellow);
                        } else {
                            do_fallback = prompt_yes_no("Retry with tcp://" + connect_opts.ip + ":" + connect_opts.port + " ?", false);
                        }

                        if (do_fallback) {
                            const auto tcp_outcome = try_connect_with_transport("tcp", "TCP");
                            rc = tcp_outcome.accepted ? 0 : 1;
                        } else {
                            rc = 1;
                        }
                    }
                }
            } else {
                const auto outcome = send_command_and_print(client, std::string(command), "");
                if (!outcome.ok || !outcome.accepted) {
                    rc = 1;
                } else if (command == "reload" && outcome.restart_required) {
                    rc = 2;
                } else {
                    rc = 0;
                }
            }
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
