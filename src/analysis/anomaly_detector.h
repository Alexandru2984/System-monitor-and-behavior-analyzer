#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analysis/anomaly_detector.h
// ─────────────────────────────────────────────────────────────────────────────
// Detects anomalies by comparing current metrics against baselines.
//
// DETECTION RULE:
//   A metric is anomalous if:   value > baseline_mean + N × sigma
//   where N is configurable (default: 2.0).
//
//   In a normal distribution, N=2 means ~2.3% false positive rate.
//   For system metrics (often skewed), this is a reasonable starting point.
//   We can tune N per-metric type later.
// ─────────────────────────────────────────────────────────────────────────────

#include "analysis/baseline_calculator.h"
#include "core/types.h"

#include <vector>

namespace sysmon {

class AnomalyDetector {
public:
    explicit AnomalyDetector(double sigma_threshold = 2.0, double alpha = 0.1);

    /// Process a metric snapshot.  Returns anomaly events (possibly empty).
    std::vector<AnomalyEvent> process(const MetricSnapshot& snapshot);

private:
    double sigma_threshold_;

    BaselineCalculator cpu_baseline_;
    BaselineCalculator mem_baseline_;
    BaselineCalculator net_rx_baseline_;
    BaselineCalculator net_tx_baseline_;

    std::vector<AnomalyEvent> checkCpu(const CpuSnapshot& s);
    std::vector<AnomalyEvent> checkMemory(const MemorySnapshot& s);
    std::vector<AnomalyEvent> checkNetwork(const NetworkSnapshot& s);
};

} // namespace sysmon
