// ─────────────────────────────────────────────────────────────────────────────
// analyzer/risk_engine.cpp — Multi-factor weighted risk scoring
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/risk_engine.h"

#include <algorithm>
#include <cmath>
#include <set>

namespace sysmon {

RiskBreakdown RiskEngine::evaluate(
    const std::vector<AnomalyEvent>& anomalies,
    const std::vector<PatternEvent>& patterns,
    int64_t current_time)
{
    // Record new anomalies in history
    for (const auto& a : anomalies) {
        history_.push_back({a.timestamp, a.severity, a.metric_type});
    }
    while (history_.size() > MAX_HISTORY) history_.pop_front();

    // Prune old history
    while (!history_.empty() &&
           current_time - history_.front().timestamp > HISTORY_WINDOW_MS) {
        history_.pop_front();
    }

    RiskBreakdown risk;

    if (anomalies.empty() && history_.empty()) {
        return risk;  // all zeros
    }

    risk.severity_score    = computeSeverity(anomalies);
    risk.persistence_score = computePersistence(current_time);
    risk.breadth_score     = computeBreadth(anomalies, patterns);
    risk.recency_score     = computeRecency(current_time);
    risk.familiarity_score = computeFamiliarity(anomalies);

    risk.total = risk.severity_score    * (W_SEVERITY / 100.0)
               + risk.persistence_score * (W_PERSISTENCE / 100.0)
               + risk.breadth_score     * (W_BREADTH / 100.0)
               + risk.recency_score     * (W_RECENCY / 100.0)
               + risk.familiarity_score * (W_FAMILIARITY / 100.0);

    risk.total = std::min(risk.total, 100.0);

    return risk;
}

double RiskEngine::computeSeverity(const std::vector<AnomalyEvent>& anomalies) {
    if (anomalies.empty()) return 0.0;

    // Max severity across all current anomalies, scaled to 0-100
    double max_sev = 0.0;
    for (const auto& a : anomalies) {
        max_sev = std::max(max_sev, a.severity);
    }
    return max_sev * 100.0;
}

double RiskEngine::computePersistence(int64_t current_time) {
    if (history_.empty()) return 0.0;

    // How many of the last 60 seconds have had anomalies?
    int recent_count = 0;
    for (const auto& h : history_) {
        if (current_time - h.timestamp < 60'000) {
            recent_count++;
        }
    }

    // Normalize: if anomalies every second for 60s → 100
    return std::min(100.0, recent_count * (100.0 / 60.0));
}

double RiskEngine::computeBreadth(const std::vector<AnomalyEvent>& anomalies,
                                   const std::vector<PatternEvent>& patterns)
{
    // Count distinct metric types affected
    std::set<std::string> affected;
    for (const auto& a : anomalies) affected.insert(a.metric_type);
    for (const auto& p : patterns)  affected.insert(p.metric_type);

    // 1 type = 25, 2 = 50, 3 = 75, 4 = 100
    return std::min(100.0, static_cast<double>(affected.size()) * 25.0);
}

double RiskEngine::computeRecency(int64_t current_time) {
    if (history_.empty()) return 0.0;

    // Exponential decay: 100 * exp(-age / τ)
    // τ = 30s → score halves every ~21 seconds (ln(2) * 30 ≈ 20.8s)
    static constexpr double TAU_MS = 30'000.0;  // decay time constant

    int64_t most_recent = history_.back().timestamp;
    double age_ms = static_cast<double>(current_time - most_recent);
    if (age_ms < 0) age_ms = 0;

    return 100.0 * std::exp(-age_ms / TAU_MS);
}

double RiskEngine::computeFamiliarity(const std::vector<AnomalyEvent>& anomalies) {
    if (anomalies.empty()) return 0.0;

    // Check how many times we've seen similar anomalies in history.
    // More familiar = LOWER risk (inverted: 100 = unfamiliar, 0 = very familiar)
    int total_similar = 0;
    for (const auto& a : anomalies) {
        for (const auto& h : history_) {
            if (h.metric_type == a.metric_type) {
                total_similar++;
            }
        }
    }

    // If we've seen this type >20 times recently, it's familiar → low risk contribution
    if (total_similar > 20) return 10.0;
    if (total_similar > 10) return 30.0;
    if (total_similar > 5)  return 50.0;
    if (total_similar > 0)  return 70.0;
    return 100.0;  // completely new type of anomaly
}

} // namespace sysmon
