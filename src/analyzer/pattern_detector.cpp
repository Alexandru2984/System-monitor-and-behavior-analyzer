// ─────────────────────────────────────────────────────────────────────────────
// analyzer/pattern_detector.cpp — Heuristic pattern detection
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/pattern_detector.h"

#include <format>

namespace sysmon {

std::vector<PatternEvent> PatternDetector::detect(
    const MetricSnapshot& snapshot, BaselineManager& baselines)
{
    return std::visit([this, &baselines](const auto& s) -> std::vector<PatternEvent> {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, CpuSnapshot>)
            return detectCpuPatterns(s, baselines);
        else if constexpr (std::is_same_v<T, MemorySnapshot>)
            return detectMemoryPatterns(s, baselines);
        else if constexpr (std::is_same_v<T, NetworkSnapshot>)
            return detectNetworkPatterns(s, baselines);
        else if constexpr (std::is_same_v<T, ProcessSnapshot>)
            return detectProcessPatterns(s);
        else
            return {};
    }, snapshot);
}

std::vector<PatternEvent> PatternDetector::detectCpuPatterns(
    const CpuSnapshot& s, BaselineManager& bm)
{
    std::vector<PatternEvent> events;
    auto& bl = bm.get("cpu_total");

    // Sustained high load
    if (bl.isSustainedHigh(5)) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::SustainedHighLoad,
            .metric_type = "cpu",
            .description = std::format(
                "CPU sustained above P95 for {}+ consecutive samples (current: {:.1f}%)",
                5, s.total_usage_percent),
            .confidence = 0.9
        });
    }

    // Oscillation (thrashing)
    int osc = bl.oscillationCount();
    if (osc > 15) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::Oscillation,
            .metric_type = "cpu",
            .description = std::format(
                "CPU oscillating rapidly ({} mean-crossings in short window)",
                osc),
            .confidence = std::min(1.0, osc / 30.0)
        });
    }

    // Upward trend
    double slope = bl.trend();
    if (slope > 0.5 && bl.shortWindow().count > 20) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::Trend,
            .metric_type = "cpu",
            .description = std::format(
                "CPU usage trending upward (slope: {:.2f}%/sample)", slope),
            .confidence = std::min(1.0, slope / 2.0)
        });
    }

    return events;
}

std::vector<PatternEvent> PatternDetector::detectMemoryPatterns(
    const MemorySnapshot& s, BaselineManager& bm)
{
    std::vector<PatternEvent> events;
    auto& bl = bm.get("mem_usage");

    // Sustained high memory
    if (bl.isSustainedHigh(10)) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::SustainedHighLoad,
            .metric_type = "memory",
            .description = std::format(
                "Memory sustained above P95 for 10+ samples (current: {:.1f}%)",
                s.usage_percent),
            .confidence = 0.85
        });
    }

    // Memory leak detection — monotonically increasing
    if (bl.isMonotonicallyIncreasing(30)) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::MemoryLeak,
            .metric_type = "memory",
            .description = std::format(
                "Possible memory leak: usage monotonically increasing for 30+ "
                "samples ({:.1f}% → {:.1f}%)",
                bl.shortWindow().min_val, s.usage_percent),
            .confidence = 0.7
        });
    }

    // Upward trend
    double slope = bl.trend();
    if (slope > 0.1 && bl.shortWindow().count > 20) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::Trend,
            .metric_type = "memory",
            .description = std::format(
                "Memory usage trending upward (slope: {:.3f}%/sample)", slope),
            .confidence = std::min(1.0, slope / 0.5)
        });
    }

    return events;
}

std::vector<PatternEvent> PatternDetector::detectNetworkPatterns(
    const NetworkSnapshot& s, BaselineManager& bm)
{
    std::vector<PatternEvent> events;

    double total_rx = 0.0;
    for (const auto& iface : s.interfaces) total_rx += iface.rx_rate_kbps;

    auto& bl = bm.get("net_rx");

    if (bl.isSustainedHigh(5)) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::SustainedHighLoad,
            .metric_type = "network",
            .description = std::format(
                "Network RX sustained above P95 ({:.1f} kbps)", total_rx),
            .confidence = 0.8
        });
    }

    int osc = bl.oscillationCount();
    if (osc > 20) {
        events.push_back(PatternEvent{
            .timestamp = s.timestamp,
            .type = PatternType::Oscillation,
            .metric_type = "network",
            .description = std::format(
                "Network traffic oscillating ({} crossings)", osc),
            .confidence = std::min(1.0, osc / 40.0)
        });
    }

    return events;
}

std::vector<PatternEvent> PatternDetector::detectProcessPatterns(
    const ProcessSnapshot& s)
{
    std::vector<PatternEvent> events;

    std::set<int> current_pids;
    for (const auto& p : s.processes) {
        current_pids.insert(p.pid);
    }

    if (has_prev_pids_) {
        // New processes
        for (const auto& p : s.processes) {
            if (prev_pids_.find(p.pid) == prev_pids_.end()) {
                // Only report if it's consuming resources
                if (p.cpu_percent > 2.0 || p.mem_percent > 1.0) {
                    events.push_back(PatternEvent{
                        .timestamp = s.timestamp,
                        .type = PatternType::NewProcess,
                        .metric_type = "process",
                        .description = std::format(
                            "New process: '{}' (PID {}, CPU: {:.1f}%, MEM: {:.1f}%)",
                            p.name, p.pid, p.cpu_percent, p.mem_percent),
                        .confidence = 0.6
                    });
                }
            }
        }

        // Disappeared processes (only high-resource ones)
        for (int old_pid : prev_pids_) {
            if (current_pids.find(old_pid) == current_pids.end()) {
                // We don't have info about the old process anymore,
                // so we just note it disappeared
                events.push_back(PatternEvent{
                    .timestamp = s.timestamp,
                    .type = PatternType::DisappearedProcess,
                    .metric_type = "process",
                    .description = std::format(
                        "Process PID {} disappeared", old_pid),
                    .confidence = 0.4
                });
            }
        }
    }

    prev_pids_ = current_pids;
    has_prev_pids_ = true;
    return events;
}

} // namespace sysmon
