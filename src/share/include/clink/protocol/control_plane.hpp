#pragma once

namespace clink::protocol::control_plane {

inline constexpr char kEnvelopeOk[] = "ok";
inline constexpr char kEnvelopeCommand[] = "command";
inline constexpr char kEnvelopeData[] = "data";
inline constexpr char kEnvelopeError[] = "error";

inline constexpr char kFieldAccepted[] = "accepted";
inline constexpr char kFieldStatus[] = "status";
inline constexpr char kFieldReason[] = "reason";
inline constexpr char kFieldMessage[] = "message";
inline constexpr char kFieldValue[] = "value";
inline constexpr char kFieldSessionId[] = "session_id";
inline constexpr char kFieldConnectPhase[] = "connect_phase";
inline constexpr char kFieldConnectReason[] = "connect_reason";
inline constexpr char kFieldConnectMessage[] = "connect_message";
inline constexpr char kFieldActiveSessions[] = "active_sessions";
inline constexpr char kFieldTrackedSessions[] = "tracked_sessions";
inline constexpr char kFieldRestartRequired[] = "restart_required";
inline constexpr char kFieldRestartReasons[] = "restart_reasons";
inline constexpr char kFieldConfigReloadSupported[] = "config_reload_supported";
inline constexpr char kFieldConfigStatus[] = "config_status";
inline constexpr char kFieldHealth[] = "health";
inline constexpr char kFieldProcessManager[] = "process_manager";
inline constexpr char kFieldState[] = "state";
inline constexpr char kFieldSocksBackend[] = "socks_backend";
inline constexpr char kFieldSocksAvailable[] = "socks_available";
inline constexpr char kFieldEffectiveIpcAddress[] = "effective_ipc_address";
inline constexpr char kFieldConfiguredIpcAddress[] = "configured_ipc_address";
inline constexpr char kFieldSessions[] = "sessions";
inline constexpr char kFieldId[] = "id";
inline constexpr char kFieldContent[] = "content";
inline constexpr char kFieldPath[] = "path";

inline constexpr char kConfigDomainIpcAddress[] = "ipc.address";
inline constexpr char kConfigDomainProcessManagerRuntime[] = "process_manager.runtime";
inline constexpr char kConfigDomainTransportRuntime[] = "transport.runtime";
inline constexpr char kConfigDomainLogging[] = "logging";
inline constexpr char kValueNone[] = "none";

inline constexpr char kStatusOk[] = "ok";
inline constexpr char kStatusIdle[] = "idle";
inline constexpr char kStatusPending[] = "pending";
inline constexpr char kStatusConnected[] = "connected";
inline constexpr char kStatusConnecting[] = "connecting";
inline constexpr char kStatusDisconnecting[] = "disconnecting";
inline constexpr char kStatusDisconnected[] = "disconnected";
inline constexpr char kStatusRejected[] = "rejected";
inline constexpr char kStatusFailed[] = "failed";
inline constexpr char kStatusError[] = "error";
inline constexpr char kStatusTimeout[] = "timeout";
inline constexpr char kStatusUnknown[] = "unknown";
inline constexpr char kStatusStopped[] = "stopped";
inline constexpr char kStatusHandshaking[] = "handshaking";
inline constexpr char kStatusActive[] = "active";
inline constexpr char kStatusClosing[] = "closing";

inline constexpr char kStateReady[] = "ready";
inline constexpr char kStateDegraded[] = "degraded";
inline constexpr char kStateNotStarted[] = "not_started";
inline constexpr char kStateInvalidRef[] = "invalid_ref";

inline constexpr char kHealthGreen[] = "green";
inline constexpr char kHealthYellow[] = "yellow";
inline constexpr char kHealthRed[] = "red";

inline constexpr char kReasonNoHandler[] = "no_handler";
inline constexpr char kReasonHandlerException[] = "handler_exception";
inline constexpr char kReasonUnknownCommand[] = "unknown_command";
inline constexpr char kReasonServiceNotRunning[] = "service_not_running";
inline constexpr char kReasonServiceShuttingDown[] = "service_shutting_down";
inline constexpr char kReasonSessionNotActive[] = "session_not_active";
inline constexpr char kReasonSessionNotDisconnected[] = "session_not_disconnected";
inline constexpr char kReasonNoSessionManager[] = "no_session_manager";
inline constexpr char kReasonMissingEndpoint[] = "missing_endpoint";
inline constexpr char kReasonSelfConnectBlocked[] = "self_connect_blocked";
inline constexpr char kReasonTransportMismatch[] = "transport_mismatch";
inline constexpr char kReasonTransportStartFailed[] = "transport_start_failed";
inline constexpr char kReasonCreateSessionException[] = "create_session_exception";
inline constexpr char kReasonCreateSessionExceptionUnknown[] = "create_session_exception_unknown";
inline constexpr char kReasonDisconnectComplete[] = "disconnect_complete";
inline constexpr char kReasonHandshakeTimeout[] = "handshake_timeout";
inline constexpr char kReasonConnectionLost[] = "connection_lost";
inline constexpr char kReasonConnectionThreadException[] = "connection_thread_exception";
inline constexpr char kReasonThreadStartFailed[] = "thread_start_failed";
inline constexpr char kReasonShutdown[] = "shutdown";
inline constexpr char kReasonLogOpenFailed[] = "log_open_failed";
inline constexpr char kReasonPipeOpenFailed[] = "pipe_open_failed";
inline constexpr char kReasonPipeSetModeFailed[] = "pipe_set_mode_failed";
inline constexpr char kReasonPipeWriteFailed[] = "pipe_write_failed";
inline constexpr char kReasonPipeReadFailed[] = "pipe_read_failed";
inline constexpr char kReasonSocketCreateFailed[] = "socket_create_failed";
inline constexpr char kReasonSocketConnectFailed[] = "socket_connect_failed";
inline constexpr char kReasonRequestTooLarge[] = "request_too_large";
inline constexpr char kReasonRequestWriteFailed[] = "request_write_failed";
inline constexpr char kReasonResponseLengthReadFailed[] = "response_length_read_failed";
inline constexpr char kReasonResponseLengthInvalid[] = "response_length_invalid";
inline constexpr char kReasonResponseReadFailed[] = "response_read_failed";

}  // namespace clink::protocol::control_plane
