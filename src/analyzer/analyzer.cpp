// ─────────────────────────────────────────────────────────────────────────────
// analyzer/analyzer.cpp — Facade implementation
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/analyzer.h"
#include "utils/logger.h"

#include <cmath>
#include <format>

namespace sysmon {

Analyzer::Analyzer(sqlite3* db, double sigma_threshold, double ema_alpha)
    : baselines_(std::min(ema_alpha * 3.0, 1.0), ema_alpha)
    , timeline_(db)
    , sigma_threshold_(sigma_threshold)
{
    timeline_.initialize();
}

AnalysisReport Analyzer::analyze(const MetricSnapshot& snapshot) {
    // No mutex needed — this method is only called from the single analysis thread.
    AnalysisReport report;

    // Extract timestamp from any snapshot type
    report.timestamp = std::visit([](const auto& s) { return s.timestamp; }, snapshot);

    // 1. Detect anomalies using dual-window baselines
    report.anomalies = detectAnomalies(snapshot);

    // 2. Detect patterns (sustained load, oscillation, etc.)
    report.patterns = pattern_detector_.detect(snapshot, baselines_);

    // 3. Update baselines AFTER detection (so current value doesn't bias the check)
    updateBaselines(snapshot);

    // 4. Compute multi-factor risk score
    report.risk = risk_engine_.evaluate(
        report.anomalies, report.patterns, report.timestamp);

    // 5. Generate human-readable explanation
    if (!report.anomalies.empty() || !report.patterns.empty()) {
        report.explanation = explainer_.explain(
            report.anomalies, report.patterns, snapshot, baselines_);

        // Set risk_score on individual anomaly events proportional to their severity
        for (auto& a : report.anomalies) {
            a.risk_score = a.severity * report.risk.total;
        }

        LOG_INFO("Analysis: risk={:.1f}/100 ({} anomalies, {} patterns)",
                 report.risk.total, report.anomalies.size(), report.patterns.size());

        if (!report.explanation.empty()) {
            LOG_DEBUG("Explanation:\n{}", report.explanation);
        }
    }

    // 6. Record in timeline
    timeline_.record(report);

    // 7. Fire desktop alerts if risk is high
    alerter_.check(report);

    return report;
}

// ── Anomaly detection (integrated with BaselineManager) ─────────────────────

std::vector<AnomalyEvent> Analyzer::detectAnomalies(const MetricSnapshot& snapshot) {
    return std::visit([this](const auto& s) -> std::vector<AnomalyEvent> {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, CpuSnapshot>)
            return checkCpu(s);
        else if constexpr (std::is_same_v<T, MemorySnapshot>)
            return checkMemory(s);
        else if constexpr (std::is_same_v<T, NetworkSnapshot>)
            return checkNetwork(s);
        else if constexpr (std::is_same_v<T, DiskSnapshot>)
            return checkDisk(s);
        else
            return {};
    }, snapshot);
}

std::vector<AnomalyEvent> Analyzer::checkCpu(const CpuSnapshot& s) {
    std::vector<AnomalyEvent> events;
    auto& bl = baselines_.get("cpu_total");
    auto lw = bl.longWindow();

    if (lw.ready && lw.count > 10) {
        double threshold = bl.anomalyThreshold(sigma_threshold_);
        if (s.total_usage_percent > threshold) {
            double effective_sigma = std::max(lw.sigma, 1.0);
            double severity = std::min(1.0,
                (s.total_usage_percent - lw.mean) / (effective_sigma * sigma_threshold_));

            events.push_back(AnomalyEvent{
                {s.timestamp, "cpu", std::format(
                    "CPU spike: {:.1f}% (baseline: {:.1f}% ± {:.1f}%, P95: {:.1f}%)",
                    s.total_usage_percent, lw.mean, lw.sigma, lw.p95)},
                severity, 0.0
            });

            LOG_WARN("ANOMALY: {}", events.back().description);
        }
    }

    return events;
}

std::vector<AnomalyEvent> Analyzer::checkMemory(const MemorySnapshot& s) {
    std::vector<AnomalyEvent> events;
    auto& bl = baselines_.get("mem_usage");
    auto lw = bl.longWindow();

    if (lw.ready && lw.count > 10) {
        double threshold = bl.anomalyThreshold(sigma_threshold_);
        if (s.usage_percent > threshold) {
            double effective_sigma = std::max(lw.sigma, 1.0);
            double severity = std::min(1.0,
                (s.usage_percent - lw.mean) / (effective_sigma * sigma_threshold_));

            events.push_back(AnomalyEvent{
                {s.timestamp, "memory", std::format(
                    "Memory pressure: {:.1f}% (baseline: {:.1f}% ± {:.1f}%, P95: {:.1f}%)",
                    s.usage_percent, lw.mean, lw.sigma, lw.p95)},
                severity, 0.0
            });

            LOG_WARN("ANOMALY: {}", events.back().description);
        }
    }

    return events;
}

std::vector<AnomalyEvent> Analyzer::checkNetwork(const NetworkSnapshot& s) {
    std::vector<AnomalyEvent> events;

    double total_rx = 0.0, total_tx = 0.0;
    for (const auto& iface : s.interfaces) {
        total_rx += iface.rx_rate_kbps;
        total_tx += iface.tx_rate_kbps;
    }

    auto& bl_rx = baselines_.get("net_rx");
    auto lw_rx = bl_rx.longWindow();

    if (lw_rx.ready && lw_rx.count > 10) {
        double threshold = bl_rx.anomalyThreshold(sigma_threshold_, 100.0);
        if (total_rx > threshold) {
            double effective_sigma = std::max(lw_rx.sigma, 100.0);
            double severity = std::min(1.0,
                (total_rx - lw_rx.mean) / (effective_sigma * sigma_threshold_));

            events.push_back(AnomalyEvent{
                {s.timestamp, "network", std::format(
                    "Network RX spike: {:.1f} kbps (baseline: {:.1f} ± {:.1f})",
                    total_rx, lw_rx.mean, lw_rx.sigma)},
                severity, 0.0
            });
        }
    }

    auto& bl_tx = baselines_.get("net_tx");
    auto lw_tx = bl_tx.longWindow();

    if (lw_tx.ready && lw_tx.count > 10) {
        double threshold = bl_tx.anomalyThreshold(sigma_threshold_, 100.0);
        if (total_tx > threshold) {
            double effective_sigma = std::max(lw_tx.sigma, 100.0);
            double severity = std::min(1.0,
                (total_tx - lw_tx.mean) / (effective_sigma * sigma_threshold_));

            events.push_back(AnomalyEvent{
                {s.timestamp, "network", std::format(
                    "Network TX spike: {:.1f} kbps (baseline: {:.1f} ± {:.1f})",
                    total_tx, lw_tx.mean, lw_tx.sigma)},
                severity, 0.0
            });
        }
    }

    return events;
}

std::vector<AnomalyEvent> Analyzer::checkDisk(const DiskSnapshot& s) {
    std::vector<AnomalyEvent> events;

    // Aggregate total I/O across all disk devices
    double total_read = 0.0, total_write = 0.0, max_util = 0.0;
    for (const auto& dev : s.devices) {
        total_read += dev.read_rate_kbps;
        total_write += dev.write_rate_kbps;
        max_util = std::max(max_util, dev.io_util_percent);
    }

    // Check read rate anomaly
    auto& bl_read = baselines_.get("disk_read");
    auto lw_read = bl_read.longWindow();

    if (lw_read.ready && lw_read.count > 10) {
        double threshold = bl_read.anomalyThreshold(sigma_threshold_, 50.0);
        if (total_read > threshold) {
            double effective_sigma = std::max(lw_read.sigma, 50.0);
            double severity = std::min(1.0,
                (total_read - lw_read.mean) / (effective_sigma * sigma_threshold_));

            events.push_back(AnomalyEvent{
                {s.timestamp, "disk", std::format(
                    "Disk read spike: {:.1f} KB/s (baseline: {:.1f} ± {:.1f})",
                    total_read, lw_read.mean, lw_read.sigma)},
                severity, 0.0
            });
        }
    }

    // Check write rate anomaly
    auto& bl_write = baselines_.get("disk_write");
    auto lw_write = bl_write.longWindow();

    if (lw_write.ready && lw_write.count > 10) {
        double threshold = bl_write.anomalyThreshold(sigma_threshold_, 50.0);
        if (total_write > threshold) {
            double effective_sigma = std::max(lw_write.sigma, 50.0);
            double severity = std::min(1.0,
                (total_write - lw_write.mean) / (effective_sigma * sigma_threshold_));

            events.push_back(AnomalyEvent{
                {s.timestamp, "disk", std::format(
                    "Disk write spike: {:.1f} KB/s (baseline: {:.1f} ± {:.1f})",
                    total_write, lw_write.mean, lw_write.sigma)},
                severity, 0.0
            });
        }
    }

    // Check I/O utilization (sustained high = disk bottleneck)
    if (max_util > 90.0) {
        events.push_back(AnomalyEvent{
            {s.timestamp, "disk", std::format(
                "Disk I/O saturation: {:.0f}% utilization", max_util)},
            std::min(1.0, max_util / 100.0), 0.0
        });
    }

    return events;
}

// ── Baseline updates ────────────────────────────────────────────────────────

void Analyzer::updateBaselines(const MetricSnapshot& snapshot) {
    std::visit([this](const auto& s) {
        using T = std::decay_t<decltype(s)>;
        if constexpr (std::is_same_v<T, CpuSnapshot>) {
            baselines_.update("cpu_total", s.total_usage_percent);
            for (size_t i = 0; i < s.core_usage_percent.size(); ++i) {
                baselines_.update("cpu_core_" + std::to_string(i),
                                  s.core_usage_percent[i]);
            }
        } else if constexpr (std::is_same_v<T, MemorySnapshot>) {
            baselines_.update("mem_usage", s.usage_percent);
        } else if constexpr (std::is_same_v<T, NetworkSnapshot>) {
            double total_rx = 0, total_tx = 0;
            for (const auto& iface : s.interfaces) {
                total_rx += iface.rx_rate_kbps;
                total_tx += iface.tx_rate_kbps;
            }
            baselines_.update("net_rx", total_rx);
            baselines_.update("net_tx", total_tx);
        } else if constexpr (std::is_same_v<T, DiskSnapshot>) {
            double total_read = 0, total_write = 0;
            for (const auto& dev : s.devices) {
                total_read += dev.read_rate_kbps;
                total_write += dev.write_rate_kbps;
            }
            baselines_.update("disk_read", total_read);
            baselines_.update("disk_write", total_write);
        }
    }, snapshot);
}

} // namespace sysmon
