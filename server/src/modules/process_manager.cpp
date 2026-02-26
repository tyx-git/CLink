#include "server/include/clink/server/modules/process_manager.hpp"
#include "server/include/clink/server/modules/socks_server.hpp"
#include <iostream>
#include <map>
#include <mutex>
#include <atomic>
#include <chrono>

#ifdef _WIN32
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
void maybe_log_ipc_stats(const std::shared_ptr<clink::core::logging::Logger>& logger, const std::shared_ptr<ProcessManagerImpl>& state, size_t current_sessions) {
    using namespace std::chrono;
    const uint64_t now_ms = static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    const uint64_t prev_ms = state->last_log_ms.load();
    if ((now_ms - prev_ms) < 5000ULL) return;
    state->last_log_ms.store(now_ms);

    logger->info(
        "[process-ipc] packets_total={}connect={}send={}disconnect={}unknown={}dropped_send_no_session={}invalid_connect_addr={}connect_exceptions={}active_sessions={}active_sessions_peak={}",
        state->packets_total.load(),
        state->packets_connect.load(),
        state->packets_send.load(),
        state->packets_disconnect.load(),
        state->unknown_packets.load(),
        state->dropped_send_no_session.load(),
        state->invalid_connect_addr.load(),
        state->connect_exceptions.load(),
        current_sessions,
        state->active_sessions_peak.load()
    );
}
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
    if (running_) return true;
    
    try {
        // 1. Start SOCKS5 Server
        uint16_t socks_port = 0;
        if (config.contains("socks.port")) {
            socks_port = static_cast<uint16_t>(config.get_int("socks.port"));
        }
        
        socks_server_ = std::make_shared<SocksServer>(io_context_, logger_, session_manager_);
        if (socks_server_->start(socks_port)) {
            socks_port = socks_server_->port();
            logger_->info("SOCKS5 Server started on port " + std::to_string(socks_port));
        } else {
            logger_->warn("Failed to start SOCKS5 Server");
            // Should we continue? Yes, IPC might be useful without SOCKS.
        }

#ifdef _WIN32
        // 2. Start Process IPC Server
        ipc_server_ = std::make_shared<clink::hook::ProcessIPCServer>(io_context_);
        
        // Register packet handler
        auto session_state = std::static_pointer_cast<ProcessManagerImpl>(session_state_);
        ipc_server_->set_packet_handler([this, session_state](std::shared_ptr<clink::hook::IPCConnection> conn, const clink::hook::ipc::PacketHeader& header, const std::vector<char>& body) {
             std::lock_guard<std::mutex> lock(session_state->mutex);
             auto key = std::make_pair(static_cast<void*>(conn.get()), header.socket_id);
             
             if (header.type == clink::hook::ipc::PacketType::DataSend) {
                 if (session_state->sessions.count(key)) {
                     session_state->sessions[key]->send_data(body);
                 }
             } else if (header.type == clink::hook::ipc::PacketType::Connect) {
                  std::string addr(body.begin(), body.end());
                  logger_->info("IPC Connect: {} (socket {})", addr, header.socket_id);
                  
                  // Parse host:port
                  size_t colon_pos = addr.find(':');
                  if (colon_pos != std::string::npos) {
                      std::string host = addr.substr(0, colon_pos);
                      uint16_t port = static_cast<uint16_t>(std::stoi(addr.substr(colon_pos + 1)));
                      
                      auto session = std::make_shared<IpcProxySession>(io_context_, conn, header.socket_id, logger_, session_manager_);
                      
                      // Set close handler to remove from session map
                      std::weak_ptr<ProcessManagerImpl> weak_state = session_state;
                      void* conn_ptr = static_cast<void*>(conn.get());
                      
                      session->set_close_handler([weak_state, conn_ptr](uint64_t sid) {
                          if (auto state = weak_state.lock()) {
                              std::lock_guard<std::mutex> lock(state->mutex);
                              auto key = std::make_pair(conn_ptr, sid);
                              state->sessions.erase(key);
                          }
                      });

                      session->start(host, port);
                      session_state->sessions[key] = session;
                  }
             } else if (header.type == clink::hook::ipc::PacketType::Disconnect) {
                  // Handle socket close request from client
                  std::shared_ptr<clink::server::modules::IpcProxySession> session;
                  {
                      std::lock_guard<std::mutex> lock(session_state->mutex);
                      auto key = std::make_pair(static_cast<void*>(conn.get()), header.socket_id);
                      if (session_state->sessions.count(key)) {
                          session = session_state->sessions[key];
                          session_state->sessions.erase(key);
                      }
                  }
                  if (session) {
                      session->close();
                  }
             }
        });

        // Handle IPCConnection disconnect to cleanup sessions
        ipc_server_->set_disconnect_handler([this, session_state](std::shared_ptr<clink::hook::IPCConnection> conn) {
            std::vector<std::shared_ptr<clink::server::modules::IpcProxySession>> sessions_to_close;
            {
                std::lock_guard<std::mutex> lock(session_state->mutex);
                for (auto it = session_state->sessions.begin(); it != session_state->sessions.end(); ) {
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
                session->close();
            }
        });
        
        ipc_server_->start();
        
        if (socks_port > 0) {
            ipc_server_->set_socks_port(socks_port);
        }
        
        logger_->info("Process IPC Server started");
#else
        logger_->info("Process IPC Server not supported on this platform");
#endif
        
        running_ = true;
        return true;
    } catch (const std::exception& e) {
        logger_->error("Failed to start Process Manager: " + std::string(e.what()));
        return false;
    }
}

void ProcessManager::stop() {
    if (!running_) return;
    
    if (socks_server_) {
        socks_server_->stop();
        socks_server_.reset();
    }
    
#ifdef _WIN32
    if (ipc_server_) {
        ipc_server_->stop();
        ipc_server_.reset();
    }
#endif
    
    running_ = false;
}

} // namespace clink::server::modules
