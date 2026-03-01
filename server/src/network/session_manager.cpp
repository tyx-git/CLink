#include "server/include/clink/core/network/session_manager_impl.hpp"
#include "server/include/clink/core/network/tcp_adapter.hpp"
#include "server/include/clink/core/network/tls_adapter.hpp"
#include "server/include/clink/core/network/packet.hpp"
#include "server/include/clink/core/observability/telemetry.hpp"
#include <chrono>
#include <new>
#include <sstream>
#include <thread>

namespace {
std::string tid_str() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return oss.str();
}
}

namespace clink::core::network {

DefaultSessionManager::DefaultSessionManager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), logger_(std::move(logger)), heartbeat_timer_(io_context) {
}

DefaultSessionManager::~DefaultSessionManager() {
    shutdown();
}

VirtualInterfacePtr DefaultSessionManager::create_interface() {
    if (logger_) logger_->info(std::string("[session] create_interface.enter enabled=") + (virtual_interface_enabled_ ? "true" : "false"));

    if (!virtual_interface_enabled_) {
        if (logger_) logger_->warn("[session] create_interface.skip (virtual interface disabled)");
        return nullptr;
    }

    auto vif = create_virtual_interface(io_context_);
    if (logger_) logger_->info(std::string("[session] create_interface.exit ptr=") + (vif ? "non-null" : "null"));
    return vif;
}

std::error_code DefaultSessionManager::initialize() {
    if (logger_) {
        logger_->info("[session] initializing session manager");
    }

    const std::string if_name = interface_name_;
    const std::string address = interface_address_;
    const std::string netmask = interface_netmask_;

    if (logger_) {
        logger_->info("[session] init params if_name='" + if_name + "' address='" + address + "' netmask='" + netmask + "' vif_enabled=" + (virtual_interface_enabled_ ? std::string("true") : std::string("false")));
    }

    virtual_interface_address_ = address;

    if (virtual_interface_enabled_) {
        try {
            if (logger_) logger_->info("[session] creating virtual interface instance");
            virtual_interface_ = create_interface();
        } catch (const std::exception& e) {
            if (logger_) logger_->error(std::string("[session] exception creating virtual interface: ") + e.what());
            virtual_interface_enabled_ = false;
        } catch (...) {
            if (logger_) logger_->error("[session] unknown exception creating virtual interface");
            virtual_interface_enabled_ = false;
        }

        if (!virtual_interface_) {
            if (logger_) logger_->error("[session] failed to create virtual interface instance, degrade to no-vif mode");
            virtual_interface_enabled_ = false;
        }

        if (virtual_interface_enabled_) {
            if (logger_) logger_->info("[session] opening virtual interface");
            auto ec = virtual_interface_->open(if_name, address, netmask);
            if (ec) {
                if (logger_) logger_->error("[session] failed to open virtual interface: " + ec.message());
                virtual_interface_.reset();
                virtual_interface_enabled_ = false;
            } else if (logger_) {
                logger_->info("[session] virtual interface opened");
            }
        }
    }

    if (!virtual_interface_enabled_ && logger_) {
        logger_->warn("[session] virtual interface disabled, running in degraded mode");
    }

    running_ = true;
    if (logger_) logger_->info("[session] starting heartbeat and data loops");
    start_heartbeat_timer();
    if (virtual_interface_) {
        start_tun_read();
    } else if (logger_) {
        logger_->warn("[session] tun read loop skipped (no virtual interface)");
    }

    return {};
}

void DefaultSessionManager::start_tun_read() {
    if (!running_) return;

    // 使用 BufferPool 分配缓冲区
    auto buffer = memory::BufferPool::instance()->acquire(2000);
    auto self = weak_from_this();
    virtual_interface_->async_read_packet(buffer, [self, buffer](std::error_code ec, size_t size) {
        auto this_ptr = std::dynamic_pointer_cast<DefaultSessionManager>(self.lock());
        if (!this_ptr || !this_ptr->running_) return;

        if (ec) {
            if (this_ptr->running_ && this_ptr->logger_) this_ptr->logger_->error("[session] tun async read error: " + ec.message());
            return;
        }

        if (size > 0) {
            auto tracer = observability::Telemetry::get_tracer("clink-data");
            observability::ScopedSpan span(tracer->start_span("tun_to_network"));
            
            std::shared_lock lock(this_ptr->sessions_mutex_);
            if (!this_ptr->engines_.empty()) {
                // 演示：发送到第一个活跃会话
                auto it = this_ptr->engines_.begin();
                it->second->send_reliable(PacketType::Data, buffer);
            }
        }

        // 继续下一轮读取
        this_ptr->start_tun_read();
    });
}

void DefaultSessionManager::start_heartbeat_timer() {
    if (!running_) return;

    heartbeat_timer_.expires_after(std::chrono::seconds(5));
    auto self = weak_from_this();
    heartbeat_timer_.async_wait([self](std::error_code ec) {
        if (ec) return;
        auto this_ptr = std::dynamic_pointer_cast<DefaultSessionManager>(self.lock());
        if (!this_ptr || !this_ptr->running_) return;

        // 1) Send heartbeat to active reliability engines
        {
            std::shared_lock lock(this_ptr->sessions_mutex_);
            for (auto& [id, engine] : this_ptr->engines_) {
                if (this_ptr->logger_) this_ptr->logger_->trace("[session] sending heartbeat to " + id);
                engine->send_heartbeat();
            }
        }

        // 2) Sweep disconnected adapters and terminate only those sessions
        std::vector<std::string> stale_sessions;
        {
            std::shared_lock lock(this_ptr->sessions_mutex_);
            for (const auto& [id, adapter] : this_ptr->adapters_) {
                if (!adapter || !adapter->is_connected()) {
                    stale_sessions.push_back(id);
                }
            }
        }

        for (const auto& id : stale_sessions) {
            if (this_ptr->logger_) this_ptr->logger_->info("[session] adapter disconnected, terminating session: " + id);
            this_ptr->terminate_session(id);
        }

        this_ptr->start_heartbeat_timer();
    });
}

std::error_code DefaultSessionManager::start_listen(TransportListenerPtr listener, const std::string& endpoint) {
    if (!listener) return std::make_error_code(std::errc::invalid_argument);
    
    if (logger_) logger_->info("[session] starting listener on " + endpoint);

    auto ec = listener->listen(endpoint);
    if (ec) {
        if (logger_) logger_->error("[session] failed to start listener on " + endpoint + ": " + ec.message());
        return ec;
    }

    add_listener(std::move(listener));
    return {};
}

void DefaultSessionManager::create_session(TransportAdapterPtr adapter) {
    if (logger_) logger_->info("[session.stage] create_session.enter");
    try {
        handle_new_connection(std::move(adapter));
        if (logger_) logger_->info("[session.stage] create_session.exit.ok");
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("[session.stage] create_session.exception: ") + ex.what());
        throw;
    } catch (...) {
        if (logger_) logger_->error("[session.stage] create_session.exception: unknown");
        throw;
    }
}

void DefaultSessionManager::handle_new_connection(TransportAdapterPtr adapter) {
    if (!adapter) return;

    if (logger_) logger_->info("[session.stage] new_connection.enter");

    try {
        auto tracer = observability::Telemetry::get_tracer("clink-network");
        observability::ScopedSpan span(tracer->start_span("handle_new_connection"));
    span->set_attribute("remote_endpoint", std::string(adapter->remote_endpoint()));
    span->set_attribute("adapter_type", adapter->type());

    // 1. ACL 验证
    if (acl_ && adapter->type() == "tls") {
        if (logger_) logger_->info("[session.stage] acl.check.begin remote=" + std::string(adapter->remote_endpoint()));
        span->add_event("acl_check_start");
        if (!acl_->is_allowed(std::string(adapter->remote_endpoint()))) {
            if (logger_) logger_->error("[session] acl denied connection from " + std::string(adapter->remote_endpoint()));
            span->set_attribute("acl_status", "denied");
            adapter->stop();
            return;
        }
        span->set_attribute("acl_status", "allowed");
    }

    std::string session_id = "sess_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());

    if (policy_engine_) {
        if (logger_) logger_->info("[session.stage] policy.evaluate.begin session_id=" + session_id);
        std::string device_id = "device-001";
        std::string group_id = "vip";
        auto policy = policy_engine_->evaluate(device_id, group_id);
        if (logger_) logger_->info("[session.stage] policy.evaluate.ok session_id=" + session_id);

        if (logger_) {
            logger_->info("[session] applied policy for " + session_id +
                         ": bw_up=" + std::to_string(policy.max_bandwidth_up.value_or(0)) +
                         ", bw_down=" + std::to_string(policy.max_bandwidth_down.value_or(0)));
        }
    }

    if (logger_) logger_->info("[session.stage] reliability_engine.create.begin session_id=" + session_id);
    if (logger_) logger_->info("[session.stage] reliability_engine.create.thread session_id=" + session_id + " tid=" + tid_str());
    std::shared_ptr<ReliabilityEngine> engine;
    try {
        if (logger_) logger_->info("[session.stage] reliability_engine.alloc.begin session_id=" + session_id + " tid=" + tid_str());
        void* raw = ::operator new(sizeof(ReliabilityEngine));
        if (logger_) logger_->info("[session.stage] reliability_engine.alloc.ok session_id=" + session_id + " raw=" + std::to_string(reinterpret_cast<uintptr_t>(raw)));

        if (logger_) logger_->info("[session.stage] reliability_engine.placement_new.begin session_id=" + session_id);
        ReliabilityEngine* re = nullptr;
        try {
            re = new (raw) ReliabilityEngine(io_context_, logger_, [adapter](const Packet& packet) {
                adapter->send(packet);
            });
        } catch (...) {
            ::operator delete(raw);
            throw;
        }
        if (logger_) logger_->info("[session.stage] reliability_engine.placement_new.ok session_id=" + session_id + " ptr=" + std::to_string(reinterpret_cast<uintptr_t>(re)));

        if (logger_) logger_->info("[session.stage] reliability_engine.shared_ptr.wrap.begin session_id=" + session_id);
        engine = std::shared_ptr<ReliabilityEngine>(re, [](ReliabilityEngine* p) {
            if (!p) return;
            p->~ReliabilityEngine();
            ::operator delete(static_cast<void*>(p));
        });
        if (logger_) logger_->info("[session.stage] reliability_engine.shared_ptr.wrap.ok session_id=" + session_id);
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("[session.stage] reliability_engine.create.exception session_id=") + session_id + " error=" + ex.what());
        throw;
    } catch (...) {
        if (logger_) logger_->error("[session.stage] reliability_engine.create.exception session_id=" + session_id + " error=unknown");
        throw;
    }
    if (logger_) logger_->info("[session.stage] reliability_engine.create.ok session_id=" + session_id + " ptr=" + std::to_string(reinterpret_cast<uintptr_t>(engine.get())));

    if (default_bytes_per_second_ > 0) {
        if (logger_) logger_->info("[session.stage] reliability_engine.rate_limit.set session_id=" + session_id);
        engine->set_rate_limit(default_bytes_per_second_, default_burst_size_);
    }

    if (logger_) logger_->info("[session.stage] lock.acquire.begin");
    {
        std::unique_lock lock(sessions_mutex_);
        if (logger_) logger_->info("[session.stage] lock.acquire.ok");

        SessionContext ctx;
        ctx.session_id = session_id;
        ctx.status = SessionStatus::Active;
        ctx.last_activity = std::chrono::system_clock::now();

        sessions_[session_id] = ctx;
        adapters_[session_id] = adapter;
        engines_[session_id] = engine;
        span->set_attribute("session_id", session_id);
        if (logger_) logger_->info("[session.stage] context.created session_id=" + session_id);

        if (logger_) logger_->info("[session.stage] lock.release session_id=" + session_id);
    }

    if (logger_) logger_->info("[session.stage] receive_callback.bind.begin session_id=" + session_id);
    auto self = weak_from_this();
    adapter->on_receive([self, session_id, adapter](std::shared_ptr<memory::Block> block) {
        auto this_ptr = std::dynamic_pointer_cast<DefaultSessionManager>(self.lock());
        if (!this_ptr || !this_ptr->running_) return;

        auto tracer = observability::Telemetry::get_tracer("clink-data");
        observability::ScopedSpan span(tracer->start_span("network_to_tun"));
        
        // 反序列化数据包 (Zero-Copy)
        bool corrupted = false;
        auto packet = Packet::deserialize(block, &corrupted);
        if (!packet) {
            // Note: If TCP stream fragmentation occurs, this might drop data. 
            // Framing logic should be implemented in TransportAdapter or here.
            
            if (corrupted) {
                if (this_ptr->logger_) this_ptr->logger_->warn("[session] received corrupted packet from " + session_id);
                {
                    std::shared_lock lock(this_ptr->sessions_mutex_);
                    auto it = this_ptr->engines_.find(session_id);
                    if (it != this_ptr->engines_.end()) {
                        it->second->report_corrupted_packet();
                    }
                }
            } else {
                 // Incomplete packet (or just wait for more data)
                 // For now, we drop it, but in a real TCP stream we should buffer.
            }
            return;
        }
        
        // Verify checksum if enabled (optional)
        // ...

        {
            std::shared_lock lock(this_ptr->sessions_mutex_);
            auto it = this_ptr->sessions_.find(session_id);
            if (it != this_ptr->sessions_.end()) {
                it->second.last_activity = std::chrono::system_clock::now();
            }

            // Update reliability engine and send ACK for Data packets
            auto engine_it = this_ptr->engines_.find(session_id);
            if (engine_it != this_ptr->engines_.end()) {
                auto& engine = engine_it->second;
                engine->set_last_received_seq(packet->header.seq_num);
                
                if (static_cast<PacketType>(packet->header.type) == PacketType::Data) {
                    engine->send_ack();
                }
            }
        }

        // 处理心跳包
        if (static_cast<PacketType>(packet->header.type) == PacketType::Heartbeat) {
            if (this_ptr->logger_) this_ptr->logger_->trace("[session] received heartbeat from " + session_id);
            return;
        }

        // 处理业务数据包
        if (static_cast<PacketType>(packet->header.type) == PacketType::Data) {
            if (this_ptr->virtual_interface_) {
                this_ptr->virtual_interface_->write_packet(packet->payload_data(), packet->payload_size());
            }
        }
    });

    if (logger_) logger_->info("[session.stage] receive_callback.bind.ok session_id=" + session_id);

    if (logger_) logger_->info("[session.stage] engine.start_async.begin session_id=" + session_id);

    auto started_flag = std::make_shared<std::atomic<bool>>(false);
    auto watchdog = std::make_shared<asio::steady_timer>(io_context_);
    watchdog->expires_after(std::chrono::milliseconds(200));
    watchdog->async_wait([this, session_id, started_flag](const std::error_code& ec) {
        if (ec) return;
        if (!started_flag->load()) {
            if (logger_) logger_->error("[session.stage] engine.start.watchdog.timeout session_id=" + session_id);
        }
    });

    engine->start_async([this, session_id, started_flag, watchdog](std::error_code ec) {
        started_flag->store(true);
        watchdog->cancel();
        if (ec) {
            if (logger_) logger_->error("[session.stage] engine.start_async.failed session_id=" + session_id + " ec=" + ec.message());
            return;
        }
        if (logger_) logger_->info("[session.stage] engine.start_async.ok session_id=" + session_id);
    });

    if (logger_) logger_->info("[session] new connection handled, id: " + session_id);
    if (logger_) logger_->info("[session.stage] connect.final status=pending session_id=" + session_id);
    if (logger_) logger_->info("[session.stage] new_connection.exit.ok");
    } catch (const std::exception& ex) {
        if (logger_) logger_->error(std::string("[session.stage] new_connection.exception: ") + ex.what());
        throw;
    } catch (...) {
        if (logger_) logger_->error("[session.stage] new_connection.exception: unknown");
        throw;
    }
}

void DefaultSessionManager::add_listener(TransportListenerPtr listener) {
    if (!listener) return;
    
    std::unique_lock lock(sessions_mutex_);
    listeners_.push_back(listener);
    
    auto self = weak_from_this();
    listener->on_connection([self](TransportAdapterPtr adapter) {
        auto this_ptr = std::dynamic_pointer_cast<DefaultSessionManager>(self.lock());
        if (!this_ptr) {
            return;
        }

        if (this_ptr->logger_) this_ptr->logger_->info("[session.stage] listener.on_connection.enter");

        if (!this_ptr->running_) {
            if (this_ptr->logger_) this_ptr->logger_->warn("[session.stage] listener.on_connection.skip_not_running");
            return;
        }

        bool serialize = false;
        if (const char* env = std::getenv("CLINK_SERIALIZE_NEW_CONNECTION")) {
            if (std::string(env) == "1") serialize = true;
        }

        if (serialize) {
            if (this_ptr->logger_) this_ptr->logger_->warn("[session.stage] listener.on_connection.serialized=1");
            static std::mutex s_conn_mutex;
            std::lock_guard<std::mutex> lk(s_conn_mutex);
            if (this_ptr->logger_) this_ptr->logger_->info("[session.stage] listener.on_connection.dispatch(serialized)");
            this_ptr->handle_new_connection(std::move(adapter));
            if (this_ptr->logger_) this_ptr->logger_->info("[session.stage] listener.on_connection.return(serialized)");
        } else {
            if (this_ptr->logger_) this_ptr->logger_->info("[session.stage] listener.on_connection.dispatch");
            this_ptr->handle_new_connection(std::move(adapter));
            if (this_ptr->logger_) this_ptr->logger_->info("[session.stage] listener.on_connection.return");
        }
    });
}

void DefaultSessionManager::terminate_session(const std::string& session_id) {
    std::unique_lock lock(sessions_mutex_);
    
    auto it = engines_.find(session_id);
    if (it != engines_.end()) {
        it->second->stop();
        engines_.erase(it);
    }

    sessions_.erase(session_id);
    adapters_.erase(session_id);
    
    if (logger_) {
        logger_->info("[session] session terminated: " + session_id);
    }
}

std::vector<SessionContext> DefaultSessionManager::get_active_sessions() const {
    std::shared_lock lock(sessions_mutex_);
    std::vector<SessionContext> result;
    result.reserve(sessions_.size());
    for (const auto& [id, ctx] : sessions_) {
        SessionContext updated_ctx = ctx;
        auto it = engines_.find(id);
        if (it != engines_.end()) {
            auto stats = it->second->get_stats();
            updated_ctx.rtt = stats.rtt;
            updated_ctx.rto = stats.rto;
            updated_ctx.bytes_sent = stats.bytes_sent;
            updated_ctx.bytes_received = stats.bytes_received;
            
            // Quality Metrics
            updated_ctx.retransmission_count = stats.retransmission_count;
            updated_ctx.corrupted_packets = stats.corrupted_packets;
            updated_ctx.latency_bucket_10ms = stats.latency_bucket_10ms;
            updated_ctx.latency_bucket_50ms = stats.latency_bucket_50ms;
            updated_ctx.latency_bucket_100ms = stats.latency_bucket_100ms;
            updated_ctx.latency_bucket_200ms = stats.latency_bucket_200ms;
            updated_ctx.latency_bucket_500ms = stats.latency_bucket_500ms;
            updated_ctx.latency_bucket_1s = stats.latency_bucket_1s;
            updated_ctx.latency_bucket_inf = stats.latency_bucket_inf;
        }
        result.push_back(updated_ctx);
    }
    return result;
}

std::string DefaultSessionManager::get_virtual_interface_address() const {
    return virtual_interface_address_;
}

std::error_code DefaultSessionManager::route_packet(const uint8_t* data, size_t size) {
    if (!virtual_interface_) return std::make_error_code(std::errc::no_such_device);
    return virtual_interface_->write_packet(data, size);
}

void DefaultSessionManager::broadcast(const uint8_t* data, size_t size) {
    std::shared_lock lock(sessions_mutex_);
    for (auto& [id, adapter] : adapters_) {
        adapter->send(data, size);
    }
}

void DefaultSessionManager::shutdown() {
    if (!running_.exchange(false)) return;

    if (logger_) {
        logger_->info("[session] shutting down session manager");
    }
    
    heartbeat_timer_.cancel();

    std::unique_lock lock(sessions_mutex_);
    for (auto& listener : listeners_) {
        listener->stop();
    }
    listeners_.clear();

    for (auto& [id, adapter] : adapters_) {
        adapter->stop();
    }
    
    for (auto& [id, engine] : engines_) {
        engine->stop();
    }
    
    engines_.clear();
    adapters_.clear();
    sessions_.clear();

    if (virtual_interface_) {
        virtual_interface_->close();
    }
}

std::shared_ptr<SessionManager> create_session_manager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger) {
    return std::make_shared<DefaultSessionManager>(io_context, std::move(logger));
}

}  // namespace clink::core::network
