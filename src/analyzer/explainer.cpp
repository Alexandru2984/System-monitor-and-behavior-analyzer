// ─────────────────────────────────────────────────────────────────────────────
// analyzer/explainer.cpp — Human-readable analysis reports
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/explainer.h"

#include <ctime>
#include <format>
#include <sstream>

namespace sysmon {

std::string Explainer::explain(
    const std::vector<AnomalyEvent>& anomalies,
    const std::vector<PatternEvent>& patterns,
    const MetricSnapshot& snapshot,
    const BaselineManager& baselines)
{
    if (anomalies.empty() && patterns.empty()) return {};

    std::ostringstream out;

    // Timestamp header — use the event timestamp, not the current wall clock,
    // so that replayed / imported data shows the correct time.
    int64_t event_ts = !anomalies.empty() ? anomalies[0].timestamp :
                       !patterns.empty()  ? patterns[0].timestamp : 0;
    std::time_t event_sec = static_cast<std::time_t>(event_ts / 1000);
    struct tm tm_buf;
    localtime_r(&event_sec, &tm_buf);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", &tm_buf);

    out << "--- Analysis Report @ " << time_str << " ---\n\n";

    // Anomalies section
    if (!anomalies.empty()) {
        for (const auto& a : anomalies) {
            out << explainAnomaly(a, baselines) << "\n";
        }
    }

    // Patterns section
    if (!patterns.empty()) {
        out << "-- Patterns Detected --\n";
        for (const auto& p : patterns) {
            out << explainPattern(p) << "\n";
        }
    }

    // Context
    std::string ctx = contextFromSnapshot(snapshot);
    if (!ctx.empty()) {
        out << "-- Context --\n" << ctx << "\n";
    }

    return out.str();
}

std::string Explainer::explainAnomaly(const AnomalyEvent& a,
                                       const BaselineManager& bm)
{
    std::ostringstream out;

    std::string icon = a.metric_type == "cpu" ? "[CPU]" :
                       a.metric_type == "memory" ? "[MEM]" :
                       a.metric_type == "network" ? "[NET]" : "[SYS]";

    out << icon << " " << severityLabel(a.severity) << " - " << a.description << "\n";

    // Add baseline context if available
    std::string baseline_key;
    if (a.metric_type == "cpu") baseline_key = "cpu_total";
    else if (a.metric_type == "memory") baseline_key = "mem_usage";
    else if (a.metric_type == "network") baseline_key = "net_rx";

    if (const auto* bl = bm.find(baseline_key)) {
        auto lw = bl->longWindow();
        auto sw = bl->shortWindow();

        if (lw.ready && lw.sigma > 0) {
            // Compute how many sigma away from baseline
            double deviation_sigmas = lw.sigma > 0.001 ?
                (sw.mean - lw.mean) / lw.sigma : 0.0;

            out << std::format("  Deviation: {:.1f}σ from long-term baseline\n",
                               deviation_sigmas);
            out << std::format("  Baseline: {:.1f} ± {:.1f}  |  Range: [{:.1f}, {:.1f}]\n",
                               lw.mean, lw.sigma, lw.min_val, lw.max_val);
            out << std::format("  P95: {:.1f}  |  P99: {:.1f}\n", lw.p95, lw.p99);

            // Trend info (normalized: 0.01 = 1% relative change per sample)
            double trend = bl->trend();
            if (std::abs(trend) > 0.002) {
                out << std::format("  Trend: {} ({:+.1f}%/sample)\n",
                    trend > 0 ? "^ increasing" : "v decreasing", trend * 100.0);
            }
        }
    }

    return out.str();
}

std::string Explainer::explainPattern(const PatternEvent& p) {
    std::string confidence_bar;
    int filled = static_cast<int>(p.confidence * 10);
    for (int i = 0; i < 10; ++i)
        confidence_bar += (i < filled) ? "#" : ".";

    return std::format("  {} [{}] {} (confidence: {} {:.0f}%)",
        patternTypeName(p.type),
        p.metric_type,
        p.description,
        confidence_bar,
        p.confidence * 100.0);
}

std::string Explainer::contextFromSnapshot(const MetricSnapshot& snapshot) {
    return std::visit([](const auto& s) -> std::string {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, ProcessSnapshot>) {
            if (s.processes.empty()) return {};
            // Show top 3 CPU consumers
            auto sorted = s.processes;
            std::sort(sorted.begin(), sorted.end(),
                [](const ProcessInfo& a, const ProcessInfo& b) {
                    return a.cpu_percent > b.cpu_percent;
                });

            std::ostringstream out;
            out << "  Top CPU consumers:\n";
            for (size_t i = 0; i < std::min(sorted.size(), (size_t)3); ++i) {
                out << std::format("    {}. '{}' (PID {}) — CPU: {:.1f}%, MEM: {:.1f}%\n",
                    i + 1, sorted[i].name, sorted[i].pid,
                    sorted[i].cpu_percent, sorted[i].mem_percent);
            }
            return out.str();
        }
        return {};
    }, snapshot);
}

std::string Explainer::severityLabel(double severity) {
    if (severity < 0.2) return "[i] LOW";
    if (severity < 0.5) return "[!] MODERATE";
    if (severity < 0.8) return "[!!] HIGH";
    return "[!!!] CRITICAL";
}

std::string Explainer::patternTypeName(PatternType type) {
    switch (type) {
        case PatternType::SustainedHighLoad:  return "SUSTAINED";
        case PatternType::Oscillation:        return "OSCILLATION";
        case PatternType::Trend:              return "TREND";
        case PatternType::MemoryLeak:         return "LEAK";
        case PatternType::NewProcess:         return "NEW PROC";
        case PatternType::DisappearedProcess: return "GONE PROC";
    }
    return "UNKNOWN";
}

} // namespace sysmon
