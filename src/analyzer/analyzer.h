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
#include <mutex>
#include <string>

namespace sysmon {

class Analyzer {
public:
    /// @param db_path    Path to SQLite DB (Timeline opens its own connection)
    /// @param sigma      Sigma threshold for anomaly detection
    explicit Analyzer(const std::string& db_path, double sigma_threshold = 2.0, double ema_alpha = 0.05);

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

    std::mutex analyze_mutex_;
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
