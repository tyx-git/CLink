#include "process_ipc_server.hpp"
#include <iostream>
#include <array>
#include <windows.h>
#include <atomic>
#include <sddl.h>

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

// Forward declaration
class NamedPipeAcceptor;

class WindowsNamedPipeConnection : public IPCConnection, public std::enable_shared_from_this<WindowsNamedPipeConnection> {
public:
    WindowsNamedPipeConnection(asio::io_context& ioc, HANDLE pipe_handle)
        : pipe_(ioc, pipe_handle) {}

    void start(ProcessIPCServer::PacketHandler handler, ProcessIPCServer::DisconnectHandler disconnect_handler) {
        handler_ = handler;
        disconnect_handler_ = disconnect_handler;
        read_header();
    }

    void write_packet(ipc::PacketType type, uint64_t socket_id, const std::vector<char>& data) override {
        auto self = shared_from_this();
        
        auto packet = std::make_shared<std::vector<char>>();
        size_t total_size = sizeof(ipc::PacketHeader) + data.size();
        packet->resize(total_size);

        ipc::PacketHeader* header = reinterpret_cast<ipc::PacketHeader*>(packet->data());
        header->magic = ipc::IPC_MAGIC;
        header->type = type;
        header->socket_id = socket_id;
        header->length = static_cast<uint32_t>(data.size());

        if (!data.empty()) {
            std::memcpy(packet->data() + sizeof(ipc::PacketHeader), data.data(), data.size());
        }

        asio::async_write(pipe_, asio::buffer(*packet),
            [self, packet](const std::error_code& ec, std::size_t) {
                if (ec) {
                    self->close();
                }
            });
    }

    void close() override {
        if (pipe_.is_open()) {
            std::error_code ec;
            pipe_.close(ec);
            if (disconnect_handler_) {
                // Use a local copy and clear the member first to avoid recursion loops if handler calls close
                auto handler = disconnect_handler_;
                disconnect_handler_ = nullptr;
                handler(shared_from_this());
            }
        }
    }

private:
    void read_header() {
        auto self = shared_from_this();
        asio::async_read(pipe_, asio::buffer(&header_buffer_, sizeof(ipc::PacketHeader)),
            [self](const std::error_code& ec, std::size_t) {
                if (!ec) {
                    if (self->header_buffer_.magic != ipc::IPC_MAGIC) {
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
                        if (self->handler_) {
                            self->handler_(self, self->header_buffer_, self->body_buffer_);
                        }
                        self->read_header();
                    } else {
                        self->close();
                    }
                });
        } else {
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
};

class NamedPipeAcceptor : public std::enable_shared_from_this<NamedPipeAcceptor> {
public:
    NamedPipeAcceptor(asio::io_context& ioc, std::weak_ptr<ProcessIPCServer> server)
        : ioc_(ioc), server_(server), event_handle_(ioc) {
        current_pipe_ = INVALID_HANDLE_VALUE;
        memset(&overlapped_, 0, sizeof(overlapped_));
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
        if (closed_) return;
        closed_ = true;
        
        // Cancel any pending operations
        if (event_handle_.is_open()) {
            std::error_code ec;
            event_handle_.cancel(ec);
            event_handle_.close(ec);
        }
        
        if (overlapped_.hEvent) {
            CloseHandle(overlapped_.hEvent);
            overlapped_.hEvent = NULL;
        }

        if (current_pipe_ != INVALID_HANDLE_VALUE) {
            CloseHandle(current_pipe_);
            current_pipe_ = INVALID_HANDLE_VALUE;
        }
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
            std::cerr << "CreateNamedPipe failed: " << GetLastError() << std::endl;
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
        memset(&overlapped_, 0, sizeof(overlapped_));
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
            std::cerr << "Failed to assign event handle: " << e.what() << std::endl;
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
            event_handle_.close(); // Closes the event handle
        }
        // Also clear overlapped struct
        overlapped_.hEvent = NULL;

        auto srv = server_.lock();
        if (srv) {
            auto conn = std::make_shared<WindowsNamedPipeConnection>(ioc_, hPipe);
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
            CloseHandle(current_pipe_);
            current_pipe_ = INVALID_HANDLE_VALUE;
        }
        if (event_handle_.is_open()) {
            event_handle_.close();
        }
        if (overlapped_.hEvent) {
            // If event_handle_ was open, it closed it. If not, we might need to close it.
            // But overlapped_.hEvent holds the raw handle.
            // If we assigned it to event_handle_, event_handle_ closed it.
            // To be safe, we can check validity, but standard practice is rely on event_handle_.
            overlapped_.hEvent = NULL;
        }
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
    bool closed_ = false;
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
    disconnect_handler_ = handler;
}

void ProcessIPCServer::set_socks_port(uint16_t port) {
    socks_port_ = port;
}

void ProcessIPCServer::start() {
    if (!acceptor_) {
        acceptor_ = std::make_shared<NamedPipeAcceptor>(io_context_, shared_from_this());
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
