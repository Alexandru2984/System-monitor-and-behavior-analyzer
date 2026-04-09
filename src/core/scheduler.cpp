// ─────────────────────────────────────────────────────────────────────────────
// core/scheduler.cpp — Scheduler implementation
// ─────────────────────────────────────────────────────────────────────────────

#include "core/scheduler.h"
#include "utils/logger.h"

#include <condition_variable>
#include <mutex>

namespace sysmon {

Scheduler::Scheduler(std::shared_ptr<IStorageEngine> storage, const Config& config)
    : storage_(std::move(storage))
    , config_(config)
    , analyzer_(config.db_path, config.anomaly_sigma, config.ema_alpha)
{}

void Scheduler::addCollector(std::shared_ptr<ICollector> collector,
                             std::chrono::milliseconds interval) {
    tasks_.push_back({std::move(collector), interval});
}

void Scheduler::start() {
    if (running_) return;
    running_ = true;

    for (auto& task : tasks_) {
        LOG_INFO("Starting {} (interval: {}ms)",
                 task.collector->name(), task.interval.count());

        // std::jthread passes its stop_token as the first arg to the callable
        threads_.emplace_back(
            [this](std::stop_token st, ScheduledTask t) {
                collectionLoop(std::move(st), std::move(t));
            },
            task
        );
    }
}

void Scheduler::stop() {
    if (!running_) return;
    running_ = false;

    // Request stops on all jthreads — they check stop_token each cycle
    for (auto& t : threads_) {
        t.request_stop();
    }

    // jthreads auto-join on destruction, but we join explicitly for clarity
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }

    threads_.clear();
    LOG_INFO("Scheduler stopped — all collection threads joined");
}

void Scheduler::collectionLoop(std::stop_token stop_token, ScheduledTask task) {
    LOG_INFO("{}: collection thread started", task.collector->name());

    // We use a condition_variable to enable interruptible sleep.
    std::mutex mtx;
    std::condition_variable_any cv;

    while (!stop_token.stop_requested()) {
        try {
            // ── Collect ────────────────────────────────────────────────────
            MetricSnapshot snapshot = task.collector->collect();

            // ── Store ──────────────────────────────────────────────────────
            storage_->store(snapshot);

            // ── Analyze (replaces old detector_ + scorer_) ─────────────────
            auto report = analyzer_.analyze(snapshot);
            if (!report.anomalies.empty()) {
                for (const auto& a : report.anomalies) {
                    storage_->storeAnomaly(a);
                }
            }

        } catch (const std::exception& e) {
            LOG_ERROR("{}: error during collection: {}",
                      task.collector->name(), e.what());
        }

        // ── Interruptible sleep ────────────────────────────────────────────
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait_for(lock, task.interval, [&] {
                return stop_token.stop_requested();
            });
        }
    }

    LOG_INFO("{}: collection thread stopped", task.collector->name());
}

} // namespace sysmon
