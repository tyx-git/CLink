#pragma once
#include <cstring>
#include <mutex>
#include <vector>
#include <memory>
#include <stdexcept>

namespace clink::core::memory {

class BufferPool; // Forward declaration

/**
 * @brief Memory Block for zero-copy operations
 * Represents a fixed-size buffer with head/tail pointers for efficient prepending/appending.
 */
struct Block {
    std::vector<uint8_t> data;
    size_t head = 0;
    size_t tail = 0;
    
    explicit Block(size_t capacity) : data(capacity) {}

    void reset() {
        head = 0;
        tail = 0;
    }
    
    // Accessors
    uint8_t* begin() { return data.data() + head; }
    const uint8_t* begin() const { return data.data() + head; }
    uint8_t* end() { return data.data() + tail; }
    const uint8_t* end() const { return data.data() + tail; }
    
    size_t size() const { return tail - head; }
    size_t capacity() const { return data.size(); }
    size_t headroom() const { return head; }
    size_t tailroom() const { return data.size() - tail; }

    // Modification
    void append(const void* src, size_t len) {
        if (len > tailroom()) {
            throw std::overflow_error("Block overflow (append)");
        }
        std::memcpy(data.data() + tail, src, len);
        tail += len;
    }

    void prepend(const void* src, size_t len) {
        if (len > headroom()) {
            throw std::overflow_error("Block underflow (prepend)");
        }
        head -= len;
        std::memcpy(data.data() + head, src, len);
    }
    
    // Reserve space at the beginning (e.g. for headers)
    void reserve_headroom(size_t size) {
        if (size > capacity()) {
             data.resize(size);
        }
        head = size;
        tail = size;
    }

    // Direct write access
    uint8_t* write_ptr() { return data.data() + tail; }
    void commit(size_t len) {
        if (len > tailroom()) throw std::overflow_error("Block overflow (commit)");
        tail += len;
    }
};

/**
 * @brief Thread-safe Buffer Pool
 * Manages reusable Block objects to reduce allocation overhead.
 */
class BufferPool : public std::enable_shared_from_this<BufferPool> {
public:
    static std::shared_ptr<BufferPool> instance() {
        static auto pool = std::shared_ptr<BufferPool>(new BufferPool());
        return pool;
    }

    // Acquire a block from the pool
    std::shared_ptr<Block> acquire(size_t min_capacity = 4096) {
        std::unique_lock<std::mutex> lock(mutex_);
        
        Block* block = nullptr;
        if (!pool_.empty()) {
            block = pool_.back();
            pool_.pop_back();
        }
        lock.unlock(); // Release lock before allocation if needed

        if (!block) {
            block = new Block(min_capacity);
        } else {
            block->reset();
            if (block->capacity() < min_capacity) {
                block->data.resize(min_capacity);
            }
        }

        // Return shared_ptr with custom deleter that returns block to pool
        return std::shared_ptr<Block>(block, [self = shared_from_this()](Block* b) {
            self->release(b);
        });
    }

    // Explicit release (usually called by shared_ptr deleter)
    void release(Block* block) {
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(block);
    }
    
    size_t pooled_count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return pool_.size();
    }

    // Public constructor required for make_shared (or use new with private ctor)
    // Here we use private ctor + static instance with new
    ~BufferPool() {
        for (auto* block : pool_) {
            delete block;
        }
    }

private:
    BufferPool() = default;
    
    std::vector<Block*> pool_;
    mutable std::mutex mutex_;
};

} // namespace clink::core::memory
