#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analysis/risk_scorer.h
// ─────────────────────────────────────────────────────────────────────────────
// Aggregates anomaly events into a composite risk score (0–100).
//
// WEIGHT TABLE:
//   CPU spike:         30 points max
//   Memory pressure:   25 points max
//   Unknown process:   30 points max  (not yet implemented)
//   Network spike:     15 points max
//
// Each anomaly's contribution = weight × severity (where severity ∈ [0, 1]).
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"
#include <vector>

namespace sysmon {

class RiskScorer {
public:
    /// Take a batch of anomaly events and assign risk_score to each.
    /// Returns the total composite risk score (0–100).
    double score(std::vector<AnomalyEvent>& events);

private:
    static constexpr double WEIGHT_CPU     = 30.0;
    static constexpr double WEIGHT_MEMORY  = 25.0;
    static constexpr double WEIGHT_PROCESS = 30.0;
    static constexpr double WEIGHT_NETWORK = 15.0;

    double weightFor(const std::string& metric_type) const;
};

} // namespace sysmon
