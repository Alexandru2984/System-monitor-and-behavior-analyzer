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
//     4. Passes the snapshot through the Analyzer pipeline
//     5. If anomalies/patterns are found, stores them and logs explanations
//
//   std::jthread (C++20) provides:
//     - Automatic joining on destruction (no resource leaks)
//     - std::stop_token for cooperative cancellation (no manual bool flags)
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"
#include "storage/storage_engine.h"
#include "analyzer/analyzer.h"
#include "core/config.h"

#include <chrono>
#include <memory>
#include <thread>
#include <vector>

namespace sysmon {

class Scheduler {
public:
    Scheduler(std::shared_ptr<IStorageEngine> storage, const Config& config);

    /// Register a collector with its sampling interval.
    void addCollector(std::shared_ptr<ICollector> collector,
                      std::chrono::milliseconds interval);

    /// Start all collection threads.  Non-blocking (threads run in background).
    void start();

    /// Request graceful shutdown and wait for all threads to finish.
    void stop();

    /// Is the scheduler currently running?
    bool running() const { return running_; }

    /// Access the analyzer (for dashboard integration)
    Analyzer& analyzer() { return analyzer_; }

private:
    struct ScheduledTask {
        std::shared_ptr<ICollector> collector;
        std::chrono::milliseconds interval;
    };

    std::shared_ptr<IStorageEngine> storage_;
    Config config_;
    Analyzer analyzer_;

    std::vector<ScheduledTask> tasks_;
    std::vector<std::jthread> threads_;
    bool running_ = false;

    void collectionLoop(std::stop_token stop_token, ScheduledTask task);
};

} // namespace sysmon
