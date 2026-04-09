#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/analyzer.h — Facade: wires baseline, detection, explanation, risk
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/baseline_manager.h"
#include "analyzer/event_timeline.h"
#include "analyzer/explainer.h"
#include "analyzer/pattern_detector.h"
#include "analyzer/risk_engine.h"
#include "core/types.h"

#include <memory>

namespace sysmon {

class Analyzer {
public:
    /// @param db         Shared SQLite handle (for EventTimeline)
    /// @param sigma      Sigma threshold for anomaly detection
    explicit Analyzer(sqlite3* db, double sigma_threshold = 2.0);

    /// Analyze a metric snapshot: detect anomalies, patterns, compute risk,
    /// generate explanation, record in timeline.
    /// Returns a full AnalysisReport.
    AnalysisReport analyze(const MetricSnapshot& snapshot);

    /// Access sub-components for dashboard queries
    BaselineManager& baselines() { return baselines_; }
    EventTimeline& timeline() { return timeline_; }

private:
    BaselineManager baselines_;
    PatternDetector pattern_detector_;
    Explainer explainer_;
    RiskEngine risk_engine_;
    EventTimeline timeline_;

    double sigma_threshold_;

    // Anomaly detection using baselines (replaces old AnomalyDetector)
    std::vector<AnomalyEvent> detectAnomalies(const MetricSnapshot& snapshot);
    std::vector<AnomalyEvent> checkCpu(const CpuSnapshot& s);
    std::vector<AnomalyEvent> checkMemory(const MemorySnapshot& s);
    std::vector<AnomalyEvent> checkNetwork(const NetworkSnapshot& s);

    // Update baselines after detection
    void updateBaselines(const MetricSnapshot& snapshot);
};

} // namespace sysmon
