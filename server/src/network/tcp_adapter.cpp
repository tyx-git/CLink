#include "server/include/clink/core/network/tcp_adapter.hpp"
#include <iostream>
#include <chrono>

namespace clink::core::network {

TcpTransportAdapter::TcpTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), logger_(std::move(logger)), socket_(io_context), receive_buffer_(8192) {
}

TcpTransportAdapter::TcpTransportAdapter(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger, asio::ip::tcp::socket socket)
    : io_context_(io_context), logger_(std::move(logger)), socket_(std::move(socket)), receive_buffer_(8192) {
    running_ = true;
    try {
        remote_endpoint_ = socket_.remote_endpoint().address().to_string() + ":" + std::to_string(socket_.remote_endpoint().port());
    } catch (...) {
        remote_endpoint_ = "unknown";
    }
}

TcpTransportAdapter::~TcpTransportAdapter() {
    stop();
}

void TcpTransportAdapter::start() {
    if (running_ && socket_.is_open()) {
        do_receive();
    }
}

std::error_code TcpTransportAdapter::start(const std::string& endpoint) {
    if (running_) return {};

    remote_endpoint_ = endpoint;
    
    // Parse endpoint
    size_t colon_pos = endpoint.find(':');
    if (colon_pos == std::string::npos) {
        return std::make_error_code(std::errc::invalid_argument);
    }

    std::string ip = endpoint.substr(0, colon_pos);
    int port = std::stoi(endpoint.substr(colon_pos + 1));

    asio::ip::tcp::resolver resolver(io_context_);
    auto endpoints = resolver.resolve(ip, std::to_string(port));

    std::error_code ec;
    asio::connect(socket_, endpoints, ec);
    if (ec) {
        if (logger_) {
            logger_->error("[tcp] failed to connect to " + endpoint + ": " + ec.message());
        }
        return ec;
    }

    running_ = true;

    if (logger_) {
        logger_->info("[tcp] starting adapter on " + endpoint);
    }

    do_receive();
    return {};
}

void TcpTransportAdapter::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (logger_) {
            logger_->info("[tcp] stopping adapter");
        }
        std::error_code ec;
        socket_.close(ec);
    }
}

std::error_code TcpTransportAdapter::send(const uint8_t* data, size_t size) {
    if (!running_) return std::make_error_code(std::errc::not_connected);

    std::error_code ec;
    asio::write(socket_, asio::buffer(data, size), ec);
    
    if (ec && logger_) {
        logger_->error("[tcp] send failed: " + ec.message());
    }
    
    return ec;
}

std::error_code TcpTransportAdapter::send(const Packet& packet) {
    if (!running_) return std::make_error_code(std::errc::not_connected);

    // Make a local copy to finalize checksum
    Packet temp = packet;
    temp.finalize();

    std::error_code ec;
    asio::write(socket_, temp.serialize_to_buffers(), ec);
    
    if (ec && logger_) {
        logger_->error("[tcp] send packet failed: " + ec.message());
    }
    
    return ec;
}

void TcpTransportAdapter::on_receive(ZeroCopyReceiveCallback callback) {
    zero_copy_receive_callback_ = std::move(callback);
}

void TcpTransportAdapter::on_receive(ReceiveCallback callback) {
    receive_callback_ = std::move(callback);
}

bool TcpTransportAdapter::is_connected() const noexcept {
    return running_.load() && socket_.is_open();
}

void TcpTransportAdapter::do_receive() {
    do_read_header();
}

void TcpTransportAdapter::do_read_header() {
    auto self = shared_from_this();
    // Use a small buffer for header
    auto block = memory::BufferPool::instance()->acquire(sizeof(PacketHeader));
    
    asio::async_read(socket_, asio::buffer(block->write_ptr(), sizeof(PacketHeader)),
        [this, self, block](std::error_code ec, std::size_t length) mutable {
            if (!ec) {
                block->commit(length);
                
                // Parse header to get payload size
                const PacketHeader* hdr = reinterpret_cast<const PacketHeader*>(block->begin());
                uint16_t payload_size = hdr->payload_size;
                
                if (payload_size > 0) {
                    // We need a block that can hold header + payload
                    // If current block is too small, we need a new one
                    if (block->tailroom() < payload_size) {
                         auto new_block = memory::BufferPool::instance()->acquire(sizeof(PacketHeader) + payload_size);
                         std::memcpy(new_block->write_ptr(), block->begin(), length);
                         new_block->commit(length);
                         block = new_block;
                    }
                    do_read_body(block, payload_size);
                } else {
                    // No payload, dispatch immediately
                    if (zero_copy_receive_callback_) {
                        zero_copy_receive_callback_(block);
                    } else if (receive_callback_) {
                        receive_callback_(block->begin(), length);
                    }
                    do_receive();
                }
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) logger_->error("[tcp] read header error: " + ec.message());
                stop();
            }
        });
}

void TcpTransportAdapter::do_read_body(std::shared_ptr<memory::Block> block, uint16_t payload_size) {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(block->write_ptr(), payload_size),
        [this, self, block, payload_size](std::error_code ec, std::size_t length) {
            if (!ec) {
                block->commit(length);
                if (zero_copy_receive_callback_) {
                    zero_copy_receive_callback_(block);
                } else if (receive_callback_) {
                    receive_callback_(block->begin(), block->size());
                }
                do_receive();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) logger_->error("[tcp] read body error: " + ec.message());
                stop();
            }
        });
}

// --- TcpTransportListener ---

TcpTransportListener::TcpTransportListener(asio::io_context& io_context, std::shared_ptr<logging::Logger> logger)
    : io_context_(io_context), logger_(std::move(logger)), acceptor_(io_context) {
}

TcpTransportListener::~TcpTransportListener() {
    stop();
}

std::error_code TcpTransportListener::listen(const std::string& endpoint) {
    if (running_) return {};

    listen_endpoint_ = endpoint;
    
    // Parse endpoint
    size_t colon_pos = endpoint.find(':');
    if (colon_pos == std::string::npos) {
        return std::make_error_code(std::errc::invalid_argument);
    }

    std::string ip = endpoint.substr(0, colon_pos);
    int port = std::stoi(endpoint.substr(colon_pos + 1));

    asio::ip::tcp::endpoint asio_endpoint(asio::ip::make_address(ip), static_cast<unsigned short>(port));
    
    std::error_code ec;
    acceptor_.open(asio_endpoint.protocol(), ec);
    if (ec) return ec;

    acceptor_.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
    if (ec) return ec;

    acceptor_.bind(asio_endpoint, ec);
    if (ec) return ec;

    acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) return ec;

    running_ = true;

    if (logger_) {
        logger_->info("[tcp] listening on " + endpoint);
    }

    do_accept();
    return {};
}

void TcpTransportListener::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (logger_) {
            logger_->info("[tcp] stopping listener on " + listen_endpoint_);
        }
        std::error_code ec;
        acceptor_.close(ec);
    }
}

void TcpTransportListener::on_connection(NewConnectionCallback callback) {
    connection_callback_ = std::move(callback);
}

void TcpTransportListener::do_accept() {
    acceptor_.async_accept(
        [this](std::error_code ec, asio::ip::tcp::socket socket) {
            if (!ec) {
                if (connection_callback_) {
                    auto adapter = std::make_shared<TcpTransportAdapter>(io_context_, logger_, std::move(socket));
                    // Start receiving after adapter construction is complete (safe for shared_from_this)
                    adapter->start();
                    connection_callback_(std::move(adapter));
                }
                do_accept();
            } else if (ec != asio::error::operation_aborted) {
                if (logger_) {
                    logger_->error("[tcp] accept error: " + ec.message());
                }
            }
        });
}

} // namespace clink::core::network
