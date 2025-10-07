#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

template <typename T>
class ThreadSafeQueue {
public:
    void push(T item) {
        {
            std::lock_guard<std::mutex> lock(m_);
            q_.push(std::move(item));
        }
        cv_.notify_one();
    }

    //blocks item until item available or stop requested
    std::optional<T> pop_blocking(bool& stop_flag) {
        std::unique_lock<std::mutex> lock(m_);
        cv_.wait(lock, [&]{ return stop_flag || !q_.empty(); });
        if (q_.empty()) return std::nullopt;
        T item = std::move(q_.front());
        q_.pop();
        return item;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(m_);
        return q_.size();
    }

private:
    mutable std::mutex m_;
    std::condition_variable cv_;
    std::queue<T> q_;
};
