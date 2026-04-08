// ─────────────────────────────────────────────────────────────────────────────
// analysis/anomaly_detector.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "analysis/anomaly_detector.h"
#include "utils/logger.h"

#include <cmath>
#include <format>

namespace sysmon {

AnomalyDetector::AnomalyDetector(double sigma_threshold, double alpha)
    : sigma_threshold_(sigma_threshold)
    , cpu_baseline_(alpha)
    , mem_baseline_(alpha)
    , net_rx_baseline_(alpha)
    , net_tx_baseline_(alpha)
{}

std::vector<AnomalyEvent> AnomalyDetector::process(const MetricSnapshot& snapshot) {
    return std::visit([this](const auto& s) -> std::vector<AnomalyEvent> {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, CpuSnapshot>)
            return checkCpu(s);
        else if constexpr (std::is_same_v<T, MemorySnapshot>)
            return checkMemory(s);
        else if constexpr (std::is_same_v<T, NetworkSnapshot>)
            return checkNetwork(s);
        else
            return {};  // ProcessSnapshot: no baseline-based detection yet
    }, snapshot);
}

std::vector<AnomalyEvent> AnomalyDetector::checkCpu(const CpuSnapshot& s) {
    std::vector<AnomalyEvent> events;

    if (cpu_baseline_.ready()) {
        // Use a minimum sigma floor of 1.0 to avoid false positives when
        // the baseline is perfectly stable (sigma ≈ 0).  Without this,
        // even a 0.1% deviation from a flat baseline would trigger.
        double effective_sigma = std::max(cpu_baseline_.sigma(), 1.0);
        double threshold = cpu_baseline_.mean() + sigma_threshold_ * effective_sigma;
        if (s.total_usage_percent > threshold && cpu_baseline_.count() > 10) {
            double severity = std::min(1.0,
                (s.total_usage_percent - cpu_baseline_.mean()) / (effective_sigma * 4.0));

            events.push_back(AnomalyEvent{
                .timestamp = s.timestamp,
                .metric_type = "cpu",
                .description = std::format(
                    "CPU spike: {:.1f}% (baseline: {:.1f}% ± {:.1f}%)",
                    s.total_usage_percent, cpu_baseline_.mean(), cpu_baseline_.sigma()),
                .severity = severity,
                .risk_score = 0.0  // will be set by RiskScorer
            });

            LOG_WARN("ANOMALY: {}", events.back().description);
        }
    }

    cpu_baseline_.update(s.total_usage_percent);
    return events;
}

std::vector<AnomalyEvent> AnomalyDetector::checkMemory(const MemorySnapshot& s) {
    std::vector<AnomalyEvent> events;

    if (mem_baseline_.ready()) {
        double effective_sigma = std::max(mem_baseline_.sigma(), 1.0);
        double threshold = mem_baseline_.mean() + sigma_threshold_ * effective_sigma;
        if (s.usage_percent > threshold && mem_baseline_.count() > 10) {
            double severity = std::min(1.0,
                (s.usage_percent - mem_baseline_.mean()) / (effective_sigma * 4.0));

            events.push_back(AnomalyEvent{
                .timestamp = s.timestamp,
                .metric_type = "memory",
                .description = std::format(
                    "Memory pressure: {:.1f}% (baseline: {:.1f}% ± {:.1f}%)",
                    s.usage_percent, mem_baseline_.mean(), mem_baseline_.sigma()),
                .severity = severity,
                .risk_score = 0.0
            });

            LOG_WARN("ANOMALY: {}", events.back().description);
        }
    }

    mem_baseline_.update(s.usage_percent);
    return events;
}

std::vector<AnomalyEvent> AnomalyDetector::checkNetwork(const NetworkSnapshot& s) {
    std::vector<AnomalyEvent> events;

    // Sum total rates across all interfaces
    double total_rx = 0.0, total_tx = 0.0;
    for (const auto& iface : s.interfaces) {
        total_rx += iface.rx_rate_kbps;
        total_tx += iface.tx_rate_kbps;
    }

    // Check RX
    if (net_rx_baseline_.ready() && net_rx_baseline_.count() > 10) {
        double threshold = net_rx_baseline_.mean() + sigma_threshold_ * net_rx_baseline_.sigma();
        if (total_rx > threshold && net_rx_baseline_.sigma() > 0) {
            double severity = std::min(1.0,
                (total_rx - net_rx_baseline_.mean()) / (net_rx_baseline_.sigma() * 4.0));

            events.push_back(AnomalyEvent{
                .timestamp = s.timestamp,
                .metric_type = "network",
                .description = std::format(
                    "Network RX spike: {:.1f} kbps (baseline: {:.1f} ± {:.1f})",
                    total_rx, net_rx_baseline_.mean(), net_rx_baseline_.sigma()),
                .severity = severity,
                .risk_score = 0.0
            });
        }
    }

    // Check TX
    if (net_tx_baseline_.ready() && net_tx_baseline_.count() > 10) {
        double threshold = net_tx_baseline_.mean() + sigma_threshold_ * net_tx_baseline_.sigma();
        if (total_tx > threshold && net_tx_baseline_.sigma() > 0) {
            double severity = std::min(1.0,
                (total_tx - net_tx_baseline_.mean()) / (net_tx_baseline_.sigma() * 4.0));

            events.push_back(AnomalyEvent{
                .timestamp = s.timestamp,
                .metric_type = "network",
                .description = std::format(
                    "Network TX spike: {:.1f} kbps (baseline: {:.1f} ± {:.1f})",
                    total_tx, net_tx_baseline_.mean(), net_tx_baseline_.sigma()),
                .severity = severity,
                .risk_score = 0.0
            });
        }
    }

    net_rx_baseline_.update(total_rx);
    net_tx_baseline_.update(total_tx);
    return events;
}

} // namespace sysmon
