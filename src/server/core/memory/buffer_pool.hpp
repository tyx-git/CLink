#pragma once
#include <cstring>
#include <mutex>
#include <vector>
#include <memory>
#include <stdexcept>

// 零拷贝内存块 + 缓冲池
// Block 使用 head/tail 双指针，支持前置填充（协议头）和后置追加（数据）
// BufferPool 复用 Block 对象，减少频繁分配/释放的开销
namespace clink::core::memory {

class BufferPool;

// Block：可变大小缓冲区，带 head/tail 指针
// head 之前的空间留给协议头 prepend，tail 到 capacity 留给数据 append
struct Block {
    std::vector<uint8_t> data;  // 底层存储
    size_t head = 0;            // 有效数据起始位置
    size_t tail = 0;            // 有效数据结束位置
    
    explicit Block(size_t capacity) : data(capacity) {}

    void reset() { head = 0; tail = 0; }  // 重置清空
    
    uint8_t* begin() { return data.data() + head; }
    const uint8_t* begin() const { return data.data() + head; }
    uint8_t* end() { return data.data() + tail; }
    const uint8_t* end() const { return data.data() + tail; }
    
    size_t size() const { return tail - head; }           // 有效数据大小
    size_t capacity() const { return data.size(); }        // 总容量
    size_t headroom() const { return head; }               // 头部空闲空间
    size_t tailroom() const { return data.size() - tail; } // 尾部空闲空间

    void append(const void* src, size_t len) {             // 尾部追加数据
        if (len > tailroom()) throw std::overflow_error("Block overflow (append)");
        std::memcpy(data.data() + tail, src, len);
        tail += len;
    }

    void prepend(const void* src, size_t len) {           // 头部前置写入（用于添加协议头）
        if (len > headroom()) throw std::overflow_error("Block underflow (prepend)");
        head -= len;
        std::memcpy(data.data() + head, src, len);
    }
    
    void reserve_headroom(size_t size) {                  // 预留给协议头的空间
        if (size > capacity()) data.resize(size);
        head = size;
        tail = size;
    }

    uint8_t* write_ptr() { return data.data() + tail; }   // 直接写指针
    void commit(size_t len) {                              // 提交写入的数据
        if (len > tailroom()) throw std::overflow_error("Block overflow (commit)");
        tail += len;
    }
};

// BufferPool：线程安全的 Block 复用池
// 使用自定义 shared_ptr 删除器，Block 析构时自动归还池中，减少内存分配
class BufferPool : public std::enable_shared_from_this<BufferPool> {
public:
    static std::shared_ptr<BufferPool> instance() {   // 全局单例
        static auto pool = std::shared_ptr<BufferPool>(new BufferPool());
        return pool;
    }

    std::shared_ptr<Block> acquire(size_t min_capacity = 4096) {  // 从池中获取一个 Block
        std::unique_lock<std::mutex> lock(mutex_);
        Block* block = nullptr;
        if (!pool_.empty()) {
            block = pool_.back();
            pool_.pop_back();
        }
        lock.unlock();

        if (!block) {
            block = new Block(min_capacity);
        } else {
            block->reset();
            if (block->capacity() < min_capacity) {
                block->data.resize(min_capacity);
            }
        }

        // 自定义删除器：shared_ptr 析构时自动归还池，而不是 delete
        return std::shared_ptr<Block>(block, [self = shared_from_this()](Block* b) {
            self->release(b);
        });
    }

    void release(Block* block) {                      // 归还 Block 到池中
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push_back(block);
    }
    
    size_t pooled_count() const {                     // 当前池中 Block 数量
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
