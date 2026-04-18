// ─────────────────────────────────────────────────────────────────────────────
// analyzer/correlation_engine.cpp — Cross-metric anomaly correlation
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/correlation_engine.h"
#include "utils/logger.h"

#include <algorithm>
#include <format>
#include <set>

namespace sysmon {

CorrelationEngine::CorrelationEngine(int64_t window_ms)
    : window_ms_(window_ms) {}

void CorrelationEngine::updateProcessContext(const ProcessSnapshot& ps) {
    last_process_snapshot_ = ps;
    has_process_data_ = true;
}

void CorrelationEngine::pruneOld(int64_t now) {
    while (!recent_reports_.empty() &&
           now - recent_reports_.front().timestamp > window_ms_) {
        recent_reports_.pop_front();
    }
}

std::string CorrelationEngine::identifyRootCause(
    const std::vector<std::string>& metrics)
{
    if (!has_process_data_ || last_process_snapshot_.processes.empty()) {
        return "Unable to identify (no process data available)";
    }

    // Find the process with the highest combined CPU + Memory usage
    const ProcessInfo* suspect = nullptr;
    double max_impact = 0.0;

    bool has_cpu = std::find(metrics.begin(), metrics.end(), "cpu") != metrics.end();
    bool has_mem = std::find(metrics.begin(), metrics.end(), "memory") != metrics.end();

    for (const auto& p : last_process_snapshot_.processes) {
        double impact = 0.0;
        if (has_cpu)  impact += p.cpu_percent;
        if (has_mem)  impact += p.mem_percent;
        if (!has_cpu && !has_mem) impact = p.cpu_percent + p.mem_percent;

        if (impact > max_impact) {
            max_impact = impact;
            suspect = &p;
        }
    }

    if (suspect && max_impact > 5.0) {
        return std::format("Process '{}' (PID {}) — CPU: {:.1f}%, MEM: {:.1f}%",
                           suspect->name, suspect->pid,
                           suspect->cpu_percent, suspect->mem_percent);
    }

    return "No single process dominating — possible system-wide load";
}

std::vector<CorrelationEvent> CorrelationEngine::correlate(
    const AnalysisReport& report, const MetricSnapshot& snapshot)
{
    // Update process context if this is a process snapshot
    if (auto* ps = std::get_if<ProcessSnapshot>(&snapshot)) {
        updateProcessContext(*ps);
    }

    // Collect which metrics have anomalies in this report
    std::set<std::string> current_metrics;
    for (const auto& a : report.anomalies) {
        current_metrics.insert(a.metric_type);
    }

    // If no anomalies, just prune and return
    if (current_metrics.empty()) {
        pruneOld(report.timestamp);
        active_.clear();
        return {};
    }

    // Record this report
    TimedReport tr;
    tr.timestamp = report.timestamp;
    tr.metric_types = {current_metrics.begin(), current_metrics.end()};
    tr.max_severity = 0.0;
    for (const auto& a : report.anomalies) {
        tr.max_severity = std::max(tr.max_severity, a.severity);
    }
    recent_reports_.push_back(tr);

    // Prune old reports
    pruneOld(report.timestamp);

    // Collect ALL unique metric types with anomalies within the window
    std::set<std::string> all_metrics;
    double peak_severity = 0.0;
    for (const auto& r : recent_reports_) {
        for (const auto& m : r.metric_types) {
            all_metrics.insert(m);
        }
        peak_severity = std::max(peak_severity, r.max_severity);
    }

    // Correlation requires at least 2 different metric types
    if (all_metrics.size() < 2) {
        active_.clear();
        return {};
    }

    // Build correlation event
    CorrelationEvent event;
    event.timestamp = report.timestamp;
    event.correlated_metrics = {all_metrics.begin(), all_metrics.end()};

    // Combined severity: boost by 20% per additional correlated metric (capped at 1.0)
    double boost = 1.0 + 0.2 * (static_cast<double>(all_metrics.size()) - 1.0);
    event.combined_severity = std::min(1.0, peak_severity * boost);

    // Build description
    std::string metric_list;
    for (const auto& m : all_metrics) {
        if (!metric_list.empty()) metric_list += " + ";
        // Capitalize first letter
        std::string upper_m = m;
        if (!upper_m.empty()) upper_m[0] = static_cast<char>(std::toupper(upper_m[0]));
        metric_list += upper_m;
    }

    event.root_cause_hypothesis = identifyRootCause(event.correlated_metrics);

    event.description = std::format(
        "Correlated anomaly across {} metrics ({}) — severity: {:.0f}%\n"
        "  Root cause: {}",
        all_metrics.size(), metric_list,
        event.combined_severity * 100.0,
        event.root_cause_hypothesis);

    LOG_WARN("CORRELATION: {}", event.description);

    active_ = {event};
    return {event};
}

} // namespace sysmon
