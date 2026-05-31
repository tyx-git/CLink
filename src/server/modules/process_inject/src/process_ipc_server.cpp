#include "process_ipc_server.hpp"
#include <iostream>
#include <array>
#include <windows.h>
#include <atomic>
#include <sddl.h>
#include <deque>
#include <mutex>
#include <cstring>

namespace {
struct PipeSecurityAttributes {
    SECURITY_ATTRIBUTES attributes{};
    PSECURITY_DESCRIPTOR descriptor{nullptr};

    PipeSecurityAttributes() {
        attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
        attributes.bInheritHandle = FALSE;
        attributes.lpSecurityDescriptor = nullptr;
        const wchar_t* sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr)) {
            attributes.lpSecurityDescriptor = descriptor;
        }
    }

    ~PipeSecurityAttributes() {
        if (descriptor) {
            LocalFree(descriptor);
        }
    }

    SECURITY_ATTRIBUTES* get() {
        return attributes.lpSecurityDescriptor ? &attributes : nullptr;
    }
};
}

namespace clink::hook {

namespace {
void log_ipc(const ProcessIPCServer::LogSink& sink, bool is_error, const std::string& msg) {
    if (sink) {
        sink(is_error, msg);
        return;
    }
    if (is_error) {
        std::cerr << "[ipc.server][error] " << msg << std::endl;
    } else {
        std::cerr << "[ipc.server] " << msg << std::endl;
    }
}
}

// Forward declaration
class NamedPipeAcceptor;

class WindowsNamedPipeConnection : public IPCConnection, public std::enable_shared_from_this<WindowsNamedPipeConnection> {
public:
    static constexpr uint32_t kMaxPacketBody = 4 * 1024 * 1024; // 4MB upper bound for safety

    WindowsNamedPipeConnection(asio::io_context& ioc, HANDLE pipe_handle, ProcessIPCServer::LogSink log_sink)
        : pipe_(ioc, pipe_handle), log_sink_(std::move(log_sink)) {}

    void start(ProcessIPCServer::PacketHandler handler, ProcessIPCServer::DisconnectHandler disconnect_handler) {
        log_ipc(log_sink_, false, "connection start");
        handler_ = handler;
        {
            std::lock_guard<std::mutex> lock(handler_mutex_);
            disconnect_handler_ = std::move(disconnect_handler);
        }
        read_header();
    }

    void write_packet(ipc::PacketType type, uint64_t socket_id, const std::vector<char>& data) override {
        if (closed_.load(std::memory_order_acquire)) {
            log_ipc(log_sink_, false,
                    "write drop: closed type=" + std::to_string(static_cast<int>(type)) +
                    " sid=" + std::to_string(socket_id));
            return;
        }

        log_ipc(log_sink_, false,
                "write enqueue type=" + std::to_string(static_cast<int>(type)) +
                " sid=" + std::to_string(socket_id) +
                " len=" + std::to_string(data.size()));

        if (data.size() > static_cast<size_t>(kMaxPacketBody)) {
            close();
            return;
        }

        auto packet = std::make_shared<std::vector<char>>();
        const size_t total_size = sizeof(ipc::PacketHeader) + data.size();
        packet->resize(total_size);

        ipc::PacketHeader* header = reinterpret_cast<ipc::PacketHeader*>(packet->data());
        header->magic = ipc::IPC_MAGIC;
        header->type = type;
        header->socket_id = socket_id;
        header->length = static_cast<uint32_t>(data.size());

        if (!data.empty()) {
            std::memcpy(packet->data() + sizeof(ipc::PacketHeader), data.data(), data.size());
        }

        bool should_start_write = false;
        {
            std::lock_guard<std::mutex> lock(write_mutex_);
            should_start_write = write_queue_.empty();
            write_queue_.push_back(packet);
        }

        if (should_start_write) {
            do_write();
        }
    }

    void close() override {
        bool expected = false;
        if (!closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            return;
        }

        log_ipc(log_sink_, false, "connection close");

        std::error_code ec;
        if (pipe_.is_open()) {
            pipe_.cancel(ec);
            pipe_.close(ec);
        }

        ProcessIPCServer::DisconnectHandler handler;
        {
            std::lock_guard<std::mutex> lock(handler_mutex_);
            handler = std::move(disconnect_handler_);
        }
        if (handler) {
            handler(shared_from_this());
        }
    }

private:
    void do_write() {
        std::shared_ptr<std::vector<char>> packet;
        {
            std::lock_guard<std::mutex> lock(write_mutex_);
            if (write_queue_.empty()) {
                return;
            }
            packet = write_queue_.front();
        }

        auto self = shared_from_this();
        asio::async_write(pipe_, asio::buffer(*packet),
            [self, packet](const std::error_code& ec, std::size_t) {
                if (ec) {
                    self->close();
                    return;
                }

                bool has_more = false;
                {
                    std::lock_guard<std::mutex> lock(self->write_mutex_);
                    if (!self->write_queue_.empty()) {
                        self->write_queue_.pop_front();
                    }
                    has_more = !self->write_queue_.empty();
                }

                if (has_more) {
                    self->do_write();
                }
            });
    }

    void read_header() {
        auto self = shared_from_this();
        asio::async_read(pipe_, asio::buffer(&header_buffer_, sizeof(ipc::PacketHeader)),
            [self](const std::error_code& ec, std::size_t) {
                if (!ec) {
                    log_ipc(self->log_sink_, false,
                            "read header type=" + std::to_string(static_cast<int>(self->header_buffer_.type)) +
                            " sid=" + std::to_string(self->header_buffer_.socket_id) +
                            " len=" + std::to_string(self->header_buffer_.length));
                    if (self->header_buffer_.magic != ipc::IPC_MAGIC ||
                        self->header_buffer_.length > kMaxPacketBody) {
                        log_ipc(self->log_sink_, true, "invalid header/magic or body too large");
                        self->close();
                        return;
                    }
                    self->read_body();
                } else {
                    self->close();
                }
            });
    }

    void read_body() {
        auto self = shared_from_this();
        if (header_buffer_.length > 0) {
            body_buffer_.resize(header_buffer_.length);
            asio::async_read(pipe_, asio::buffer(body_buffer_),
                [self](const std::error_code& ec, std::size_t) {
                    if (!ec) {
                        log_ipc(self->log_sink_, false,
                                "read body ok len=" + std::to_string(self->body_buffer_.size()));
                        if (self->handler_) {
                            self->handler_(self, self->header_buffer_, self->body_buffer_);
                        }
                        self->read_header();
                    } else {
                        log_ipc(self->log_sink_, true, std::string("read body failed: ") + ec.message());
                        self->close();
                    }
                });
        } else {
            body_buffer_.clear();
            if (handler_) {
                handler_(shared_from_this(), header_buffer_, body_buffer_);
            }
            read_header();
        }
    }

    asio::windows::stream_handle pipe_;
    ipc::PacketHeader header_buffer_;
    std::vector<char> body_buffer_;
    ProcessIPCServer::PacketHandler handler_;
    ProcessIPCServer::DisconnectHandler disconnect_handler_;
    ProcessIPCServer::LogSink log_sink_;
    std::mutex write_mutex_;
    std::deque<std::shared_ptr<std::vector<char>>> write_queue_;
    std::mutex handler_mutex_;
    std::atomic<bool> closed_{false};
};

class NamedPipeAcceptor : public std::enable_shared_from_this<NamedPipeAcceptor> {
public:
    NamedPipeAcceptor(asio::io_context& ioc, std::weak_ptr<ProcessIPCServer> server, ProcessIPCServer::LogSink log_sink)
        : ioc_(ioc), server_(server), event_handle_(ioc), log_sink_(std::move(log_sink)) {
        current_pipe_ = INVALID_HANDLE_VALUE;
        std::memset(&overlapped_, 0, sizeof(overlapped_));
    }

    ~NamedPipeAcceptor() {
        stop();
    }

    void start() {
        if (!closed_) {
            accept_next();
        }
    }

    void stop() {
        if (closed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        std::error_code ec;
        if (event_handle_.is_open()) {
            event_handle_.cancel(ec);
            event_handle_.close(ec);
        }

        if (current_pipe_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(current_pipe_, &overlapped_);
            DisconnectNamedPipe(current_pipe_);
            CloseHandle(current_pipe_);
            current_pipe_ = INVALID_HANDLE_VALUE;
        }

        overlapped_.hEvent = NULL;
    }

private:
    void accept_next() {
        if (closed_) return;

        // Create Named Pipe
        // Use PIPE_READMODE_BYTE to ensure compatibility with asio::async_read which expects stream behavior
        PipeSecurityAttributes sa;
        HANDLE hPipe = CreateNamedPipeA(
            ipc::PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096, // Out buffer
            4096, // In buffer
            0,    // Default timeout
            sa.get()
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            log_ipc(log_sink_, true, "CreateNamedPipe failed err=" + std::to_string(GetLastError()));
            schedule_retry();
            return;
        }

        current_pipe_ = hPipe;

        // Setup Overlapped
        if (overlapped_.hEvent) {
            // Should be closed by handle_connection or cleanup, but if we are here, ensure it is clean
             // Actually we can reuse the event if we want, but let's recreate to be safe and simple
            CloseHandle(overlapped_.hEvent);
        }
        std::memset(&overlapped_, 0, sizeof(overlapped_));
        overlapped_.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
        if (!overlapped_.hEvent) {
            CloseHandle(hPipe);
            current_pipe_ = INVALID_HANDLE_VALUE;
            schedule_retry();
            return;
        }

        // Assign event to object_handle
        try {
            if (event_handle_.is_open()) event_handle_.close();
            event_handle_.assign(overlapped_.hEvent);
        } catch (const std::exception& e) {
            log_ipc(log_sink_, true, std::string("Failed to assign event handle: ") + e.what());
            CloseHandle(overlapped_.hEvent);
            overlapped_.hEvent = NULL;
            CloseHandle(hPipe);
            current_pipe_ = INVALID_HANDLE_VALUE;
            schedule_retry();
            return;
        }

        // Start asynchronous connect
        BOOL connected = ConnectNamedPipe(hPipe, &overlapped_);
        if (connected) {
            // Connected immediately
            auto self = shared_from_this();
            asio::post(ioc_, [self, hPipe]() {
                self->handle_connection(hPipe);
            });
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                // Connected immediately
                auto self = shared_from_this();
                asio::post(ioc_, [self, hPipe]() {
                    self->handle_connection(hPipe);
                });
            } else if (err == ERROR_IO_PENDING) {
                auto self = shared_from_this();
                event_handle_.async_wait([self, hPipe](const std::error_code& ec) {
                    if (!ec) {
                        DWORD transferred;
                        if (GetOverlappedResult(hPipe, &self->overlapped_, &transferred, FALSE)) {
                            self->handle_connection(hPipe);
                        } else {
                            // Connection failed
                            self->cleanup_current();
                            if (!self->closed_) self->accept_next();
                        }
                    } else {
                        // Wait aborted or error (e.g. stop called)
                        self->cleanup_current();
                    }
                });
            } else {
                cleanup_current();
                schedule_retry();
            }
        }
    }

    void handle_connection(HANDLE hPipe) {
        if (closed_) {
            CloseHandle(hPipe);
            return;
        }

        // We successfully connected.
        // Detach handle from our tracking so we don't close it in cleanup/stop
        // (Ownership transfers to WindowsNamedPipeConnection)
        current_pipe_ = INVALID_HANDLE_VALUE;
        
        // We also need to close the event handle used for this connection attempt
        // because we will create a new one for the next attempt (or reuse, but logic above creates new)
        // Note: event_handle_ owns the event handle now (via assign), so closing it closes the handle?
        // No, object_handle does NOT own the underlying kernel object (HANDLE) unless constructed with it?
        // assign() docs: "Assign an existing native handle to the handle."
        // Windows object_handle implementation usually wraps the handle.
        // But here we assigned the *Event* handle.
        // We need to verify if closing event_handle_ closes the HANDLE.
        // Typically Asio object_handle closes the handle on destruction/close.
        // So we should close event_handle_ here to free the Event object.
        if (event_handle_.is_open()) {
            std::error_code ec;
            event_handle_.close(ec); // Closes the event handle
        }
        // Also clear overlapped struct
        overlapped_.hEvent = NULL;

        auto srv = server_.lock();
        if (srv) {
            auto conn = std::make_shared<WindowsNamedPipeConnection>(ioc_, hPipe, log_sink_);
            if (srv->packet_handler_) {
                conn->start(srv->packet_handler_, srv->disconnect_handler_);
            }
        } else {
            CloseHandle(hPipe);
        }

        // Accept next
        accept_next();
    }

    void cleanup_current() {
        if (current_pipe_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(current_pipe_, &overlapped_);
            DisconnectNamedPipe(current_pipe_);
            CloseHandle(current_pipe_);
            current_pipe_ = INVALID_HANDLE_VALUE;
        }
        if (event_handle_.is_open()) {
            std::error_code ec;
            event_handle_.close(ec);
        }
        overlapped_.hEvent = NULL;
    }

    void schedule_retry() {
        if (closed_) return;
        auto timer = std::make_shared<asio::steady_timer>(ioc_);
        timer->expires_after(std::chrono::milliseconds(100));
        auto self = shared_from_this();
        timer->async_wait([self, timer](const std::error_code& ec) {
            if (!ec) {
                self->accept_next();
            }
        });
    }

    asio::io_context& ioc_;
    std::weak_ptr<ProcessIPCServer> server_;
    asio::windows::object_handle event_handle_;
    OVERLAPPED overlapped_;
    HANDLE current_pipe_;
    ProcessIPCServer::LogSink log_sink_;
    std::atomic<bool> closed_{false};
};

ProcessIPCServer::ProcessIPCServer(asio::io_context& io_context)
    : io_context_(io_context) {}

ProcessIPCServer::~ProcessIPCServer() {
    stop();
}

void ProcessIPCServer::set_packet_handler(PacketHandler handler) {
    packet_handler_ = handler;
}

void ProcessIPCServer::set_disconnect_handler(DisconnectHandler handler) {
    disconnect_handler_ = std::move(handler);
}

void ProcessIPCServer::set_log_sink(LogSink sink) {
    log_sink_ = std::move(sink);
}

void ProcessIPCServer::set_socks_port(uint16_t port) {
    socks_port_ = port;
}

void ProcessIPCServer::start() {
    if (!acceptor_) {
        acceptor_ = std::make_shared<NamedPipeAcceptor>(io_context_, shared_from_this(), log_sink_);
        acceptor_->start();
    }
}

void ProcessIPCServer::stop() {
    if (acceptor_) {
        acceptor_->stop();
        acceptor_.reset();
    }
}

} // namespace clink::hook
