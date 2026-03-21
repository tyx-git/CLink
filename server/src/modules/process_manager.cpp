#include "server/include/clink/server/modules/process_manager.hpp"
#include "server/include/clink/server/modules/socks_server.hpp"
#include <iostream>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstring>
#include <utility>

#ifdef _WIN32
#include "server/modules/process_inject/include/process_injector.hpp"
#include "server/modules/process_inject/include/process_ipc_server.hpp"
#include "server/include/clink/server/modules/ipc_proxy_session.hpp"

namespace clink::server::modules {
    struct ProcessManagerImpl {
        std::mutex mutex;
        std::map<std::pair<void*, uint64_t>, std::shared_ptr<clink::server::modules::IpcProxySession>> sessions;
        std::atomic<uint64_t> packets_total{0};
        std::atomic<uint64_t> packets_connect{0};
        std::atomic<uint64_t> packets_send{0};
        std::atomic<uint64_t> packets_disconnect{0};
        std::atomic<uint64_t> unknown_packets{0};
        std::atomic<uint64_t> active_sessions_peak{0};
        std::atomic<uint64_t> dropped_send_no_session{0};
        std::atomic<uint64_t> invalid_connect_addr{0};
        std::atomic<uint64_t> connect_exceptions{0};
        std::atomic<uint64_t> last_log_ms{0};
    };
}
#endif

namespace clink::server::modules {

namespace {
#ifdef _WIN32
const char* inject_error_log_level(clink::hook::inject::InjectError ec) {
    switch (ec) {
        case clink::hook::inject::InjectError::None:
            return "info";
        case clink::hook::inject::InjectError::NotSupported:
            return "warn";
        case clink::hook::inject::InjectError::InvalidArgument:
            return "warn";
        case clink::hook::inject::InjectError::AccessDenied:
            return "error";
        case clink::hook::inject::InjectError::ProcessNotFound:
            return "warn";
        case clink::hook::inject::InjectError::BackendFailure:
            return "error";
        default:
            return "warn";
    }
}

void log_inject_result(std::shared_ptr<clink::core::logging::Logger> logger,
                       uint32_t pid,
                       const std::string& dll_path,
                       bool ok,
                       clink::hook::inject::InjectError ec,
                       const std::string& detail) {
    if (!logger) return;

    const std::string base = "Process inject pid=" + std::to_string(pid) +
                             " dll='" + dll_path + "'" +
                             " result=" + (ok ? "success" : "failed") +
                             " code=" + clink::hook::inject::InjectErrorToString(ec) +
                             (detail.empty() ? "" : (" detail='" + detail + "'"));

    const char* level = inject_error_log_level(ec);
    if (std::strcmp(level, "error") == 0) {
        logger->error(base);
    } else if (std::strcmp(level, "warn") == 0) {
        logger->warn(base);
    } else {
        logger->info(base);
    }
}
#endif
}

ProcessManager::ProcessManager(asio::io_context& io_context, std::shared_ptr<clink::core::logging::Logger> logger, std::shared_ptr<clink::core::network::SessionManager> session_manager)
    : io_context_(io_context), logger_(std::move(logger)), session_manager_(std::move(session_manager)) {
#ifdef _WIN32
    session_state_ = std::make_shared<ProcessManagerImpl>();
#endif
}

ProcessManager::~ProcessManager() {
    stop();
}

bool ProcessManager::start(const clink::core::config::Configuration& config) {
    std::lock_guard<std::mutex> guard(lifecycle_mutex_);
    if (running_) return true;

    socks_available_ = false;
    start_state_ = StartState::Failed;
    start_reason_ = "starting";
    socks_backend_ = "none";

    auto close_all_ipc_sessions = [this]() {
#ifdef _WIN32
        auto session_state = std::static_pointer_cast<ProcessManagerImpl>(session_state_);
        if (!session_state) {
            return;
        }

        std::vector<std::shared_ptr<clink::server::modules::IpcProxySession>> sessions_to_close;
        {
            std::lock_guard<std::mutex> lock(session_state->mutex);
            sessions_to_close.reserve(session_state->sessions.size());
            for (auto& kv : session_state->sessions) {
                sessions_to_close.push_back(kv.second);
            }
            session_state->sessions.clear();
        }

        for (auto& session : sessions_to_close) {
            if (session) {
                session->set_close_handler(nullptr);
                session->close();
            }
        }
#endif
    };

    auto cleanup_on_failure = [this, &close_all_ipc_sessions]() {
        if (socks_server_) {
            socks_server_->stop();
            socks_server_.reset();
        }
#ifdef _WIN32
        close_all_ipc_sessions();
        if (ipc_server_) {
            ipc_server_->stop();
            ipc_server_.reset();
        }
#endif
    };

    try {
        if (logger_) {
            logger_->info("[pm] stage=start.begin");
        }

        // 1. Start SOCKS5 Server
        uint16_t socks_port = 0;
        if (config.contains("socks.port")) {
            const int cfg_port = config.get_int("socks.port");
            if (cfg_port < 0 || cfg_port > 65535) {
                if (logger_) {
                    logger_->warn("[pm] invalid socks.port fallback_to_0", cfg_port);
                }
                socks_port = 0;
            } else {
                socks_port = static_cast<uint16_t>(cfg_port);
            }
        }

        if (logger_) {
            logger_->info("[pm] stage=socks.create.begin");
        }
        try {
            if (logger_) {
                logger_->info("[pm] stage=socks.create.alloc.begin");
            }
            socks_server_ = std::make_shared<SocksServer>(io_context_, logger_, session_manager_);
            if (logger_) {
                logger_->info("[pm] stage=socks.create.alloc.ok");
            }
        } catch (const std::exception& ex) {
            if (logger_) {
                logger_->error("[pm] stage=socks.create.alloc.exception", ex.what());
            }
            start_reason_ = "socks_create_exception";
            cleanup_on_failure();
            return false;
        } catch (...) {
            if (logger_) {
                logger_->error("[pm] stage=socks.create.alloc.exception: unknown");
            }
            start_reason_ = "socks_create_exception_unknown";
            cleanup_on_failure();
            return false;
        }
        if (!socks_server_) {
            if (logger_) {
                logger_->error("[pm] stage=socks.create.failed null_server");
            }
            start_reason_ = "socks_create_null";
            cleanup_on_failure();
            return false;
        }
        if (logger_) {
            logger_->info("[pm] stage=socks.create.ok configured_port", socks_port);
            logger_->info("[pm] stage=socks.start.begin");
        }
        std::string socks_backend = "auto";
        if (config.contains("socks.backend")) {
            socks_backend = config.get_string("socks.backend", "auto");
        }

        if (socks_server_->start(socks_port, socks_backend)) {
            socks_port = socks_server_->port();
            socks_available_ = true;
            if (socks_server_->backend() == SocksServer::Backend::Asio) {
                socks_backend_ = "asio";
            } else if (socks_server_->backend() == SocksServer::Backend::WinSock) {
                socks_backend_ = "winsock";
            } else {
                socks_backend_ = "unknown";
            }
            if (logger_) {
                logger_->info("[pm] stage=socks.start.ok bound_port backend", socks_port, socks_backend_);
            }
        } else {
            socks_available_ = false;
            start_reason_ = "socks_unavailable";
            if (logger_) {
                logger_->warn("[pm] stage=socks.start.failed");
            }
            // Continue in degraded mode: IPC may still be useful.
        }

#ifdef _WIN32
        if (logger_) {
            logger_->info("[pm] stage=injector.log_sink.begin");
        }
        clink::hook::inject::SetLogSink([logger = logger_](bool is_error, const std::string& message) {
            if (!logger) return;
            if (is_error) {
                logger->error("[injector]", message);
            } else {
                logger->info("[injector]", message);
            }
        });
        if (logger_) {
            logger_->info("[pm] stage=injector.log_sink.ok");
            logger_->info("[pm] stage=injector.backend", clink::hook::inject::BackendName(), clink::hook::inject::IsSupported() ? "yes" : "no");
        }

        if (config.contains("process.inject.target_pid") && config.contains("process.inject.dll")) {
            const int configured_pid = config.get_int("process.inject.target_pid");
            const std::string configured_dll = config.get_string("process.inject.dll");

            if (configured_pid <= 0 || configured_dll.empty()) {
                if (logger_) {
                    logger_->warn("Skip process inject: invalid config pid dll", configured_pid, configured_dll);
                }
            } else {
                clink::hook::inject::InjectError inject_ec = clink::hook::inject::InjectError::None;
                std::string inject_detail;
                const bool injected = clink::hook::inject::InjectLibrary(
                    static_cast<uint32_t>(configured_pid),
                    configured_dll,
                    &inject_detail,
                    &inject_ec);

                log_inject_result(logger_,
                                  static_cast<uint32_t>(configured_pid),
                                  configured_dll,
                                  injected,
                                  inject_ec,
                                  inject_detail);
            }
        }

        // 2. Start Process IPC Server
        if (logger_) {
            logger_->info("[pm] stage=ipc_server.create.begin");
        }
        ipc_server_ = std::make_shared<clink::hook::ProcessIPCServer>(io_context_);
        ipc_server_->set_log_sink([logger = logger_](bool is_error, const std::string& msg) {
            if (!logger) return;
            if (is_error) {
                logger->error("[ipc.server]", msg);
            } else {
                logger->debug("[ipc.server]", msg);
            }
        });
        if (logger_) {
            logger_->info("[pm] stage=ipc_server.create.ok");
        }

        // Register packet handler
        auto session_state = std::static_pointer_cast<ProcessManagerImpl>(session_state_);
        if (!session_state) {
            if (logger_) {
                logger_->error("[pm] stage=ipc_server.handlers.bind.failed no_session_state");
            }
            start_reason_ = "ipc_session_state_missing";
            cleanup_on_failure();
            return false;
        }
        if (logger_) {
            logger_->info("[pm] stage=ipc_server.handlers.bind.begin");
        }
        ipc_server_->set_packet_handler([this, session_state](
            std::shared_ptr<clink::hook::IPCConnection> conn,
            const clink::hook::ipc::PacketHeader& header,
            const std::vector<char>& body) {
            if (!conn) {
                if (logger_) {
                    logger_->warn("IPC packet drop: null connection");
                }
                return;
            }

            auto key = std::make_pair(static_cast<void*>(conn.get()), header.socket_id);

            if (header.length > clink::hook::ipc::kMaxPacketBody) {
                session_state->unknown_packets.fetch_add(1, std::memory_order_relaxed);
                if (logger_) {
                    logger_->warn("IPC packet drop: body too large", header.length);
                }
                return;
            }

            if (logger_) {
                logger_->debug("IPC packet received type socket body_len",
                               static_cast<int>(header.type),
                               header.socket_id,
                               body.size());
            }

            if (header.type == clink::hook::ipc::PacketType::DataSend) {
                session_state->packets_total.fetch_add(1, std::memory_order_relaxed);
                session_state->packets_send.fetch_add(1, std::memory_order_relaxed);

                std::shared_ptr<clink::server::modules::IpcProxySession> session;
                {
                    std::lock_guard<std::mutex> lock(session_state->mutex);
                    auto it = session_state->sessions.find(key);
                    if (it != session_state->sessions.end()) {
                        session = it->second;
                    }
                }
                if (session) {
                    if (logger_) {
                        logger_->debug("IPC DataSend dispatch sid len", header.socket_id, body.size());
                    }
                    session->send_data(body);
                } else {
                    session_state->dropped_send_no_session.fetch_add(1, std::memory_order_relaxed);
                    if (logger_) {
                        logger_->warn("IPC DataSend drop(no session) sid len", header.socket_id, body.size());
                    }
                }
            } else if (header.type == clink::hook::ipc::PacketType::Connect) {
                session_state->packets_total.fetch_add(1, std::memory_order_relaxed);
                session_state->packets_connect.fetch_add(1, std::memory_order_relaxed);

                std::string addr(body.begin(), body.end());
                if (logger_) {
                    logger_->info("IPC Connect addr socket", addr, header.socket_id);
                }

                std::string host;
                uint16_t port = 0;

                if (!addr.empty() && addr.front() == '[') {
                    // IPv6 bracket format: [addr]:port
                    const size_t rb = addr.find(']');
                    if (rb == std::string::npos || rb + 2 > addr.size() || addr[rb + 1] != ':') {
                        session_state->invalid_connect_addr.fetch_add(1, std::memory_order_relaxed);
                        if (logger_) {
                            logger_->warn("Invalid IPv6 connect address format from IPC", addr);
                        }
                        return;
                    }
                    host = addr.substr(1, rb - 1);
                    try {
                        const int parsed_port = std::stoi(addr.substr(rb + 2));
                        if (parsed_port <= 0 || parsed_port > 65535) {
                            session_state->invalid_connect_addr.fetch_add(1, std::memory_order_relaxed);
                            if (logger_) {
                                logger_->warn("Invalid connect port from IPC", parsed_port);
                            }
                            return;
                        }
                        port = static_cast<uint16_t>(parsed_port);
                    } catch (const std::exception& ex) {
                        session_state->invalid_connect_addr.fetch_add(1, std::memory_order_relaxed);
                        if (logger_) {
                            logger_->warn("Invalid connect address from IPC", addr, ex.what());
                        }
                        return;
                    }
                } else {
                    size_t colon_pos = addr.rfind(':');
                    if (colon_pos == std::string::npos) {
                        session_state->invalid_connect_addr.fetch_add(1, std::memory_order_relaxed);
                        if (logger_) {
                            logger_->warn("Invalid connect address format from IPC", addr);
                        }
                        return;
                    }

                    host = addr.substr(0, colon_pos);
                    try {
                        const int parsed_port = std::stoi(addr.substr(colon_pos + 1));
                        if (parsed_port <= 0 || parsed_port > 65535) {
                            session_state->invalid_connect_addr.fetch_add(1, std::memory_order_relaxed);
                            if (logger_) {
                                logger_->warn("Invalid connect port from IPC", parsed_port);
                            }
                            return;
                        }
                        port = static_cast<uint16_t>(parsed_port);
                    } catch (const std::exception& ex) {
                        session_state->invalid_connect_addr.fetch_add(1, std::memory_order_relaxed);
                        if (logger_) {
                            logger_->warn("Invalid connect address from IPC", addr, ex.what());
                        }
                        return;
                    }
                }

                auto session = std::make_shared<IpcProxySession>(io_context_, conn, header.socket_id, logger_, session_manager_);

                std::weak_ptr<ProcessManagerImpl> weak_state = session_state;
                std::weak_ptr<clink::hook::IPCConnection> weak_conn = conn;
                session->set_close_handler([weak_state, weak_conn](uint64_t sid) {
                    auto state = weak_state.lock();
                    auto conn_locked = weak_conn.lock();
                    if (!state || !conn_locked) {
                        return;
                    }

                    std::lock_guard<std::mutex> lock(state->mutex);
                    const auto erase_key = std::make_pair(static_cast<void*>(conn_locked.get()), sid);
                    state->sessions.erase(erase_key);
                });

                bool inserted = false;
                {
                    std::lock_guard<std::mutex> lock(session_state->mutex);
                    auto [it, did_insert] = session_state->sessions.emplace(key, session);
                    inserted = did_insert;
                    if (!did_insert) {
                        if (logger_) {
                            logger_->warn("IPC session already exists, closing previous", header.socket_id);
                        }
                        auto prev_session = it->second;
                        it->second = session;
                        if (prev_session) {
                            prev_session->set_close_handler(nullptr);
                            prev_session->close();
                        }
                    }

                    if (logger_) {
                        logger_->debug("IPC session created conn sid active",
                                       reinterpret_cast<uintptr_t>(conn.get()),
                                       header.socket_id,
                                       session_state->sessions.size());
                    }
                    const uint64_t active_now = static_cast<uint64_t>(session_state->sessions.size());
                    uint64_t peak = session_state->active_sessions_peak.load(std::memory_order_relaxed);
                    while (active_now > peak &&
                           !session_state->active_sessions_peak.compare_exchange_weak(peak, active_now, std::memory_order_relaxed)) {
                    }
                }

                session->start(host, port);
            } else if (header.type == clink::hook::ipc::PacketType::Disconnect) {
                session_state->packets_total.fetch_add(1, std::memory_order_relaxed);
                session_state->packets_disconnect.fetch_add(1, std::memory_order_relaxed);

                std::shared_ptr<clink::server::modules::IpcProxySession> session;
                {
                    std::lock_guard<std::mutex> lock(session_state->mutex);
                    auto it = session_state->sessions.find(key);
                    if (it != session_state->sessions.end()) {
                        session = it->second;
                        session_state->sessions.erase(it);
                    }
                }
                if (session) {
                    session->close();
                }
            } else if (header.type == clink::hook::ipc::PacketType::Log) {
                session_state->packets_total.fetch_add(1, std::memory_order_relaxed);

                if (body.empty()) {
                    if (logger_) {
                        logger_->warn("[hook.client] malformed log packet: empty body");
                    }
                    return;
                }
                const uint8_t level = static_cast<uint8_t>(body[0]);
                std::string logline(body.begin() + 1, body.end());
                if (logline.empty()) {
                    logline = "<empty message>";
                }
                if (logger_) {
                    if (level == 2 || level == 3) {
                        logger_->error("[hook.client]", logline);
                    } else if (level == 1) {
                        logger_->info("[hook.client]", logline);
                    } else {
                        logger_->debug("[hook.client]", logline);
                    }
                }
            } else {
                session_state->packets_total.fetch_add(1, std::memory_order_relaxed);
                session_state->unknown_packets.fetch_add(1, std::memory_order_relaxed);
                if (logger_) {
                    logger_->warn("Unknown IPC packet type socket", static_cast<int>(header.type), header.socket_id);
                }
            }
        });

        // Handle IPCConnection disconnect to cleanup sessions
        ipc_server_->set_disconnect_handler([this, session_state](std::shared_ptr<clink::hook::IPCConnection> conn) {
            if (!conn) {
                return;
            }

            std::vector<std::shared_ptr<clink::server::modules::IpcProxySession>> sessions_to_close;
            {
                std::lock_guard<std::mutex> lock(session_state->mutex);
                for (auto it = session_state->sessions.begin(); it != session_state->sessions.end();) {
                    if (it->first.first == static_cast<void*>(conn.get())) {
                        sessions_to_close.push_back(it->second);
                        it = session_state->sessions.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            // Close sessions outside the lock to avoid deadlock with close_handler
            for (auto& session : sessions_to_close) {
                if (session) {
                    session->set_close_handler(nullptr);
                    session->close();
                }
            }
        });

        if (logger_) {
            logger_->info("[pm] stage=ipc_server.handlers.bind.ok");
            logger_->info("[pm] stage=ipc_server.start.begin");
        }
        ipc_server_->start();
        if (logger_) {
            logger_->info("[pm] stage=ipc_server.start.ok");
        }

        if (socks_port > 0) {
            ipc_server_->set_socks_port(socks_port);
            if (logger_) {
                logger_->info("[pm] stage=ipc_server.socks_port.set value", socks_port);
            }
        }

        if (logger_) {
            logger_->info("[pm] stage=ipc_server.ready");
        }
#else
        if (logger_) {
            logger_->info("[pm] stage=injector.backend name=linux-not-implemented supported=no");
            logger_->info("[pm] stage=ipc_server.skip platform_unsupported");
        }
#endif

        running_ = true;
        start_state_ = socks_available_ ? StartState::Ready : StartState::Degraded;
        if (start_state_ == StartState::Ready) {
            start_reason_ = "ok";
        } else if (start_reason_ == "starting") {
            start_reason_ = "degraded";
        }
        if (logger_) {
            if (start_state_ == StartState::Ready) {
                logger_->info("[pm] stage=start.ok mode=ready");
            } else {
                logger_->warn("[pm] stage=start.ok mode=degraded reason=socks_unavailable");
            }
        }
        return true;
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->error(std::string("[pm] stage=start.exception error=") + e.what());
        }
        start_reason_ = "start_exception";
        cleanup_on_failure();
        return false;
    } catch (...) {
        if (logger_) {
            logger_->error("[pm] stage=start.exception error=unknown");
        }
        start_reason_ = "start_exception_unknown";
        cleanup_on_failure();
        return false;
    }
}

void ProcessManager::stop() {
    std::lock_guard<std::mutex> guard(lifecycle_mutex_);
    if (!running_ && !socks_server_
#ifdef _WIN32
        && !ipc_server_
#endif
    ) {
        return;
    }

    if (socks_server_) {
        socks_server_->stop();
        socks_server_.reset();
    }

#ifdef _WIN32
    auto session_state = std::static_pointer_cast<ProcessManagerImpl>(session_state_);
    std::vector<std::shared_ptr<clink::server::modules::IpcProxySession>> sessions_to_close;
    if (session_state) {
        std::lock_guard<std::mutex> lock(session_state->mutex);
        sessions_to_close.reserve(session_state->sessions.size());
        for (auto& kv : session_state->sessions) {
            sessions_to_close.push_back(kv.second);
        }
        session_state->sessions.clear();
    }

    for (auto& session : sessions_to_close) {
        if (session) {
            session->set_close_handler(nullptr);
            session->close();
        }
    }

    if (ipc_server_) {
        ipc_server_->stop();
        ipc_server_.reset();
    }
#endif

    running_ = false;
    socks_available_ = false;
    socks_backend_ = "none";
    start_state_ = StartState::Failed;
    start_reason_ = "stopped";
}

} // namespace clink::server::modules
