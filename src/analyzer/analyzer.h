#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/analyzer.h — Facade: wires baseline, detection, explanation, risk
// ─────────────────────────────────────────────────────────────────────────────
//
// THREAD SAFETY:
//   The Analyzer is designed to be called from a SINGLE thread only
//   (the dedicated analysis thread in Scheduler).  It has NO internal mutex.
//   Do NOT call analyze() from multiple threads concurrently.
//
//   The const accessors (baselines(), timeline()) are safe to call from
//   other threads only for READ operations, and only when the analysis
//   thread is not actively running (e.g., after Scheduler::stop()).
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/alerter.h"
#include "analyzer/baseline_manager.h"
#include "analyzer/correlation_engine.h"
#include "analyzer/event_timeline.h"
#include "analyzer/explainer.h"
#include "analyzer/pattern_detector.h"
#include "analyzer/risk_engine.h"
#include "core/types.h"

#include <memory>
#include <string>

struct sqlite3;  // forward declaration

namespace sysmon {

class Analyzer {
public:
    /// @param db       Shared SQLite handle (owned by SqliteStorage)
    /// @param sigma    Sigma threshold for anomaly detection
    /// @param ema_alpha EMA smoothing factor
    explicit Analyzer(sqlite3* db, double sigma_threshold = 2.0, double ema_alpha = 0.05);

    /// Analyze a metric snapshot: detect anomalies, patterns, compute risk,
    /// generate explanation, record in timeline, and fire alerts.
    /// Returns a full AnalysisReport.
    /// NOTE: Must only be called from a single thread.
    AnalysisReport analyze(const MetricSnapshot& snapshot);

    /// Access sub-components (const — safe for read-only dashboard queries)
    const BaselineManager& baselines() const { return baselines_; }
    const EventTimeline& timeline() const { return timeline_; }

    /// Non-const access for timeline queries that need to write (e.g., getRecentEvents).
    /// Only safe when called from the analysis thread or after stop().
    EventTimeline& mutableTimeline() { return timeline_; }

    /// Access alerter for runtime configuration
    Alerter& alerter() { return alerter_; }

    /// Access correlation engine (const — safe for read-only dashboard queries)
    const CorrelationEngine& correlations() const { return correlator_; }

private:
    BaselineManager baselines_;
    PatternDetector pattern_detector_;
    Explainer explainer_;
    RiskEngine risk_engine_;
    EventTimeline timeline_;
    Alerter alerter_;
    CorrelationEngine correlator_;

    double sigma_threshold_;

    // Anomaly detection using baselines (replaces old AnomalyDetector)
    std::vector<AnomalyEvent> detectAnomalies(const MetricSnapshot& snapshot);
    std::vector<AnomalyEvent> checkCpu(const CpuSnapshot& s);
    std::vector<AnomalyEvent> checkMemory(const MemorySnapshot& s);
    std::vector<AnomalyEvent> checkNetwork(const NetworkSnapshot& s);
    std::vector<AnomalyEvent> checkDisk(const DiskSnapshot& s);

    // Update baselines after detection
    void updateBaselines(const MetricSnapshot& snapshot);
};

} // namespace sysmon
