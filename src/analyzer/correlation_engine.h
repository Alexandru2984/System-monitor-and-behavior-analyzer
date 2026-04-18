#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/correlation_engine.h — Cross-metric anomaly correlation
// ─────────────────────────────────────────────────────────────────────────────
//
// PURPOSE:
//   When CPU and Memory both spike at the same time, that's not two separate
//   problems — it's ONE problem (likely a runaway process).  The Correlation
//   Engine detects these multi-metric events and produces a unified assessment.
//
// HOW IT WORKS:
//   1. Receives analysis reports from the Analyzer
//   2. Maintains a sliding window of recent reports (last 30s)
//   3. Checks for temporal overlap between anomalies across different metrics
//   4. If correlated, generates a CorrelationEvent with higher combined severity
//   5. Tries to identify the root cause (e.g., which process is spiking)
//
// THREAD SAFETY: Single-threaded (called only from analysis thread)
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"

#include <deque>
#include <string>
#include <vector>

namespace sysmon {

struct CorrelationEvent {
    int64_t timestamp;
    std::vector<std::string> correlated_metrics;  // e.g. {"cpu", "memory", "disk"}
    double combined_severity;                     // 0..1
    std::string root_cause_hypothesis;            // "Process 'firefox' (PID 1234)"
    std::string description;                      // Human-readable summary
};

class CorrelationEngine {
public:
    /// @param window_ms  Time window for correlation (default: 10s)
    explicit CorrelationEngine(int64_t window_ms = 10'000);

    /// Feed a new analysis report. Returns correlations if found.
    std::vector<CorrelationEvent> correlate(const AnalysisReport& report,
                                            const MetricSnapshot& snapshot);

    /// Get all active correlations
    const std::vector<CorrelationEvent>& activeCorrelations() const { return active_; }

    /// Get the most recent process snapshot for root cause analysis
    void updateProcessContext(const ProcessSnapshot& ps);

private:
    int64_t window_ms_;

    struct TimedReport {
        int64_t timestamp;
        std::vector<std::string> metric_types;  // which metrics had anomalies
        double max_severity;
    };

    std::deque<TimedReport> recent_reports_;
    std::vector<CorrelationEvent> active_;
    ProcessSnapshot last_process_snapshot_;
    bool has_process_data_ = false;

    // Cleanup old reports outside the window
    void pruneOld(int64_t now);

    // Find which process is most likely causing the issue
    std::string identifyRootCause(const std::vector<std::string>& metrics);
};

} // namespace sysmon
