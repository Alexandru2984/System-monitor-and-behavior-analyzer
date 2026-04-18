#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// core/scheduler.h — Orchestrates collection, storage, and analysis
// ─────────────────────────────────────────────────────────────────────────────
//
// ARCHITECTURE:
//   The Scheduler owns the main loop.  For each collector, it creates a
//   std::jthread that:
//     1. Sleeps for the configured interval
//     2. Calls collector->collect()
//     3. Pushes the snapshot to storage->store()
//     4. Pushes the snapshot into a MetricQueue
//
//   A SINGLE dedicated analysis thread drains the MetricQueue and feeds
//   each snapshot through the Analyzer pipeline.  This means:
//     - The Analyzer is single-threaded by design (no mutex needed)
//     - Collectors never block on analysis
//     - If analysis falls behind, the queue applies back-pressure
//
//   std::jthread (C++20) provides:
//     - Automatic joining on destruction (no resource leaks)
//     - std::stop_token for cooperative cancellation (no manual bool flags)
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"
#include "storage/sqlite_storage.h"
#include "analyzer/analyzer.h"
#include "core/config.h"
#include "core/metric_queue.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace sysmon {

class Scheduler {
public:
    Scheduler(std::shared_ptr<SqliteStorage> storage, const Config& config);

    /// Register a collector with its sampling interval.
    void addCollector(std::shared_ptr<ICollector> collector,
                      std::chrono::milliseconds interval);

    /// Start all collection threads.  Non-blocking (threads run in background).
    void start();

    /// Request graceful shutdown and wait for all threads to finish.
    void stop();

    /// Is the scheduler currently running?
    bool running() const { return running_; }

    /// Access the analyzer (read-only queries from dashboard — safe because
    /// the analyzer is only mutated by the single analysis thread).
    const Analyzer& analyzer() const { return analyzer_; }

private:
    struct ScheduledTask {
        std::shared_ptr<ICollector> collector;
        std::chrono::milliseconds interval;
    };

    std::shared_ptr<SqliteStorage> storage_;
    Config config_;
    Analyzer analyzer_;
    MetricQueue analysis_queue_;

    std::vector<ScheduledTask> tasks_;
    std::vector<std::jthread> threads_;
    std::jthread analysis_thread_;
    std::atomic<bool> running_ = false;

    void collectionLoop(std::stop_token stop_token, ScheduledTask task);
    void analysisLoop(std::stop_token stop_token);
};

} // namespace sysmon
