#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/explainer.h — Human-readable analysis reports
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/baseline_manager.h"
#include "core/types.h"

#include <string>
#include <vector>

namespace sysmon {

class Explainer {
public:
    /// Generate a human-readable explanation from anomalies, patterns,
    /// the current snapshot, and baseline context.
    std::string explain(const std::vector<AnomalyEvent>& anomalies,
                        const std::vector<PatternEvent>& patterns,
                        const MetricSnapshot& snapshot,
                        const BaselineManager& baselines);

private:
    std::string explainAnomaly(const AnomalyEvent& a,
                               const BaselineManager& bm);
    std::string explainPattern(const PatternEvent& p);
    std::string contextFromSnapshot(const MetricSnapshot& snapshot);
    static std::string severityLabel(double severity);
    static std::string patternTypeName(PatternType type);
};

} // namespace sysmon
