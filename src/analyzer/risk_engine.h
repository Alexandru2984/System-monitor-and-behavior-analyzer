#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/risk_engine.h — Multi-factor weighted risk scoring
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"

#include <deque>
#include <vector>

namespace sysmon {

class RiskEngine {
public:
    /// Compute risk breakdown from anomalies, patterns, and history
    RiskBreakdown evaluate(const std::vector<AnomalyEvent>& anomalies,
                           const std::vector<PatternEvent>& patterns,
                           int64_t current_time);

private:
    // Factor weights (must sum to 100)
    static constexpr double W_SEVERITY    = 30.0;
    static constexpr double W_PERSISTENCE = 25.0;
    static constexpr double W_BREADTH     = 20.0;
    static constexpr double W_RECENCY     = 15.0;
    static constexpr double W_FAMILIARITY = 10.0;

    // History for persistence and familiarity tracking
    struct HistoryEntry {
        int64_t timestamp;
        double severity;
        std::string metric_type;
    };
    std::deque<HistoryEntry> history_;
    static constexpr size_t MAX_HISTORY = 500;
    static constexpr int64_t HISTORY_WINDOW_MS = 600'000;  // 10 minutes

    double computeSeverity(const std::vector<AnomalyEvent>& anomalies);
    double computePersistence(int64_t current_time);
    double computeBreadth(const std::vector<AnomalyEvent>& anomalies,
                          const std::vector<PatternEvent>& patterns);
    double computeRecency(int64_t current_time);
    double computeFamiliarity(const std::vector<AnomalyEvent>& anomalies);
};

} // namespace sysmon
