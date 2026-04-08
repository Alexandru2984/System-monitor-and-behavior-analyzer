// ─────────────────────────────────────────────────────────────────────────────
// analysis/risk_scorer.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "analysis/risk_scorer.h"
#include "utils/logger.h"

#include <algorithm>

namespace sysmon {

double RiskScorer::weightFor(const std::string& metric_type) const {
    if (metric_type == "cpu")     return WEIGHT_CPU;
    if (metric_type == "memory")  return WEIGHT_MEMORY;
    if (metric_type == "process") return WEIGHT_PROCESS;
    if (metric_type == "network") return WEIGHT_NETWORK;
    return 0.0;
}

double RiskScorer::score(std::vector<AnomalyEvent>& events) {
    double total_risk = 0.0;

    for (auto& event : events) {
        double weight = weightFor(event.metric_type);
        event.risk_score = weight * event.severity;
        total_risk += event.risk_score;
    }

    // Cap at 100
    total_risk = std::min(total_risk, 100.0);

    if (total_risk > 0.0) {
        LOG_INFO("Risk score: {:.1f}/100 ({} anomalies)", total_risk, events.size());
    }

    return total_risk;
}

} // namespace sysmon
