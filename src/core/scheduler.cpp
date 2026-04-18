// ─────────────────────────────────────────────────────────────────────────────
// core/scheduler.cpp — Scheduler implementation
// ─────────────────────────────────────────────────────────────────────────────

#include "core/scheduler.h"
#include "utils/logger.h"

#include <condition_variable>
#include <mutex>

namespace sysmon {

Scheduler::Scheduler(std::shared_ptr<SqliteStorage> storage, const Config& config)
    : storage_(std::move(storage))
    , config_(config)
    , analyzer_(storage_->db(), config.anomaly_sigma, config.ema_alpha)
{}

void Scheduler::addCollector(std::shared_ptr<ICollector> collector,
                             std::chrono::milliseconds interval) {
    tasks_.push_back({std::move(collector), interval});
}

void Scheduler::start() {
    if (running_) return;
    running_ = true;

    // Start the dedicated analysis thread FIRST so it's ready to consume
    analysis_thread_ = std::jthread([this](std::stop_token st) {
        analysisLoop(std::move(st));
    });

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

    // Periodic data pruning thread
    if (config_.retention_hours > 0) {
        threads_.emplace_back([this](std::stop_token st) {
            LOG_INFO("Prune thread started (retention: {}h)", config_.retention_hours);
            std::mutex mtx;
            std::condition_variable_any cv;
            while (!st.stop_requested()) {
                try {
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    int64_t cutoff = now_ms - static_cast<int64_t>(config_.retention_hours) * 3600 * 1000;
                    storage_->pruneOlderThan(cutoff);
                } catch (const std::exception& e) {
                    LOG_ERROR("Prune error: {}", e.what());
                }
                // Prune every 5 minutes
                std::unique_lock<std::mutex> lock(mtx);
                cv.wait_for(lock, std::chrono::minutes(5), [&] {
                    return st.stop_requested();
                });
            }
        });
    }
}

void Scheduler::stop() {
    if (!running_) return;
    running_ = false;

    // Request stops on all jthreads — they check stop_token each cycle
    for (auto& t : threads_) {
        t.request_stop();
    }

    // Stop the analysis thread and wake it up
    analysis_thread_.request_stop();
    analysis_queue_.notify_all();

    // jthreads auto-join on destruction, but we join explicitly for clarity
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    if (analysis_thread_.joinable()) analysis_thread_.join();

    threads_.clear();
    LOG_INFO("Scheduler stopped — all collection and analysis threads joined");
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

            // ── Enqueue for analysis (non-blocking) ────────────────────────
            analysis_queue_.push(snapshot);

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

void Scheduler::analysisLoop(std::stop_token stop_token) {
    LOG_INFO("Analysis thread started");

    while (!stop_token.stop_requested()) {
        auto maybe_snapshot = analysis_queue_.wait_and_pop(stop_token);
        if (!maybe_snapshot) break;  // shutdown requested

        try {
            auto report = analyzer_.analyze(*maybe_snapshot);
            if (!report.anomalies.empty()) {
                for (const auto& a : report.anomalies) {
                    storage_->storeAnomaly(a);
                }
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Analysis error: {}", e.what());
        }
    }

    LOG_INFO("Analysis thread stopped");
}

} // namespace sysmon
