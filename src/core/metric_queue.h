#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// core/metric_queue.h — Thread-safe queue for collector→analyzer decoupling
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY a queue?
//   Previously, each collector thread called analyzer_.analyze() directly.
//   The Analyzer used a mutex to serialize access, but this coupling made it
//   fragile:  if anyone accessed baselines() or timeline() from another
//   thread, instant UB.
//
//   Now, collectors push snapshots into this lock-free-ish queue, and a
//   single dedicated analysis thread drains it.  The Analyzer never needs
//   a mutex at all — it's single-threaded by design.
//
// DESIGN:
//   - std::deque + mutex + condition_variable  (simple, correct, fast enough)
//   - Bounded: if queue exceeds MAX_PENDING, oldest snapshots are dropped
//     (back-pressure — analysis can't keep up with collection)
//   - wait_and_pop() supports stop_token for clean shutdown
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <optional>

namespace sysmon {

class MetricQueue {
public:
    static constexpr size_t MAX_PENDING = 256;

    /// Push a snapshot. If queue is full, drops the oldest entry.
    void push(MetricSnapshot snapshot) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(std::move(snapshot));
            while (queue_.size() > MAX_PENDING) {
                queue_.pop_front();  // back-pressure: drop oldest
            }
        }
        cv_.notify_one();
    }

    /// Block until a snapshot is available or stop is requested.
    /// Returns std::nullopt if stop was requested (for clean shutdown).
    std::optional<MetricSnapshot> wait_and_pop(std::stop_token stop_token) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, stop_token, [this] { return !queue_.empty(); });

        if (stop_token.stop_requested() && queue_.empty()) {
            return std::nullopt;
        }

        MetricSnapshot snap = std::move(queue_.front());
        queue_.pop_front();
        return snap;
    }

    /// Non-blocking try: returns nullopt if empty.
    std::optional<MetricSnapshot> try_pop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return std::nullopt;
        MetricSnapshot snap = std::move(queue_.front());
        queue_.pop_front();
        return snap;
    }

    /// Wake up any waiting consumer (used during shutdown).
    void notify_all() {
        cv_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable_any cv_;
    std::deque<MetricSnapshot> queue_;
};

} // namespace sysmon
