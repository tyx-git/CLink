#include "server/include/clink/core/network/session_manager_impl.hpp"
#include "server/include/clink/core/network/tcp_adapter.hpp"
#include "server/include/clink/core/network/tls_adapter.hpp"
#include "server/include/clink/core/network/packet.hpp"
#include "server/include/clink/core/observability/telemetry.hpp"
#include <chrono>

namespace clink::core::network {

DefaultSessionManager::DefaultSessionManager(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), logger_(std::move(logger)), heartbeat_timer_(io_context) {
}

DefaultSessionManager::~DefaultSessionManager() {
    shutdown();
}

VirtualInterfacePtr DefaultSessionManager::create_interface() {
    return create_virtual_interface(io_context_);
}

std::error_code DefaultSessionManager::initialize() {
    if (logger_) {
        logger_->info("[session] initializing session manager");
    }
    
    std::string if_name = interface_name_;
    std::string address = interface_address_;
    std::string netmask = interface_netmask_;

    virtual_interface_address_ = address;

    virtual_interface_ = create_interface();
    if (!virtual_interface_) {
        if (logger_) logger_->error("[session] failed to create virtual interface instance");
        return std::make_error_code(std::errc::no_such_device);
    }

    auto ec = virtual_interface_->open(if_name, address, netmask);
    if (ec) {
        if (logger_) logger_->error("[session] failed to open virtual interface: " + ec.message());
        return ec;
    }

    running_ = true;
    start_heartbeat_timer();
    start_tun_read();

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

        {
            std::shared_lock lock(this_ptr->sessions_mutex_);
            for (auto& [id, engine] : this_ptr->engines_) {
                if (this_ptr->logger_) this_ptr->logger_->trace("[session] sending heartbeat to " + id);
                engine->send_heartbeat();
            }
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
    handle_new_connection(std::move(adapter));
}

void DefaultSessionManager::handle_new_connection(TransportAdapterPtr adapter) {
    if (!adapter) return;

    auto tracer = observability::Telemetry::get_tracer("clink-network");
    observability::ScopedSpan span(tracer->start_span("handle_new_connection"));
    span->set_attribute("remote_endpoint", std::string(adapter->remote_endpoint()));
    span->set_attribute("adapter_type", adapter->type());

    // 1. ACL 验证
    if (acl_ && adapter->type() == "tls") {
        span->add_event("acl_check_start");
        if (!acl_->is_allowed(std::string(adapter->remote_endpoint()))) {
            if (logger_) logger_->error("[session] acl denied connection from " + std::string(adapter->remote_endpoint()));
            span->set_attribute("acl_status", "denied");
            adapter->stop();
            return;
        }
        span->set_attribute("acl_status", "allowed");
    }

    std::unique_lock lock(sessions_mutex_);
    
    std::string session_id = "sess_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    
    SessionContext ctx;
    ctx.session_id = session_id;
    ctx.status = SessionStatus::Active;
    ctx.last_activity = std::chrono::system_clock::now();
    
    sessions_[session_id] = ctx;
    adapters_[session_id] = adapter;
    span->set_attribute("session_id", session_id);
    
    // 2. 评估并应用策略
    if (policy_engine_) {
        std::string device_id = "device-001"; 
        std::string group_id = "vip";
        auto policy = policy_engine_->evaluate(device_id, group_id);
        
        if (logger_) {
            logger_->info("[session] applied policy for " + session_id + 
                         ": bw_up=" + std::to_string(policy.max_bandwidth_up.value_or(0)) +
                         ", bw_down=" + std::to_string(policy.max_bandwidth_down.value_or(0)));
        }
    }

    // 初始化可靠传输引擎
    auto engine = std::make_shared<ReliabilityEngine>(io_context_, logger_, [adapter](const Packet& packet) {
            adapter->send(packet);
        });
        
    if (default_bytes_per_second_ > 0) {
        engine->set_rate_limit(default_bytes_per_second_, default_burst_size_);
    }

    engine->start();
    engines_[session_id] = engine;
    
    if (logger_) {
        logger_->info("[session] new connection handled, id: " + session_id);
    }

    // 绑定异步接收回调，取代之前的阻塞线程
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

    lock.unlock();
}

void DefaultSessionManager::add_listener(TransportListenerPtr listener) {
    if (!listener) return;
    
    std::unique_lock lock(sessions_mutex_);
    listeners_.push_back(listener);
    
    auto self = weak_from_this();
    listener->on_connection([self](TransportAdapterPtr adapter) {
        auto this_ptr = std::dynamic_pointer_cast<DefaultSessionManager>(self.lock());
        if (this_ptr && this_ptr->running_) {
            this_ptr->handle_new_connection(std::move(adapter));
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
