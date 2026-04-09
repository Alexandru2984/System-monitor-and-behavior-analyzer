#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/baseline_manager.h — Dual-window baseline tracking
// ─────────────────────────────────────────────────────────────────────────────
//
// Unlike the simple BaselineCalculator (single EMA), BaselineManager maintains
// TWO statistical windows per metric:
//
//   SHORT window (60 samples ≈ 1 minute):
//     - Reacts fast to state changes
//     - Used for trend detection and oscillation analysis
//
//   LONG window (600 samples ≈ 10 minutes):
//     - Stable reference baseline
//     - Used for anomaly thresholds (less prone to false positives)
//
// Both windows track: mean (EMA), running stddev, min, max.
// The long window also estimates P95/P99 using a lightweight approach:
//
//   P95 ESTIMATION:
//     For a normal distribution, P95 ≈ mean + 1.645 × sigma.
//     For skewed system metrics, we use a sorted circular buffer of the
//     last 100 values and take the actual 95th percentile.  This is O(N log N)
//     per update, but N=100 so it's ~700ns — negligible.
// ─────────────────────────────────────────────────────────────────────────────

#include <algorithm>
#include <cmath>
#include <deque>
#include <string>
#include <unordered_map>

namespace sysmon {

/// Statistics for a single window
struct WindowStats {
    double mean    = 0.0;
    double sigma   = 0.0;
    double min_val = 0.0;
    double max_val = 0.0;
    double p95     = 0.0;
    double p99     = 0.0;
    int    count   = 0;
    bool   ready   = false;
};

/// A single metric's dual-window tracker
class MetricBaseline {
public:
    explicit MetricBaseline(size_t short_window = 60, size_t long_window = 600,
                            double alpha_short = 0.15, double alpha_long = 0.05);

    /// Feed a new value
    void update(double value);

    /// Get statistics for each window
    WindowStats shortWindow() const;
    WindowStats longWindow() const;

    /// Convenience: anomaly threshold = long_mean + N * long_sigma (with floor)
    double anomalyThreshold(double sigma_multiplier, double sigma_floor = 1.0) const;

    /// Trend: slope of short window (positive = increasing)
    double trend() const { return trend_slope_; }

    /// Oscillation count: how many times we crossed the long mean in the short window
    int oscillationCount() const;

    /// Is the value sustained above P95 of the long window?
    bool isSustainedHigh(int min_consecutive = 5) const;

    /// Is the value monotonically increasing over the last N samples?
    bool isMonotonicallyIncreasing(int samples = 30) const;

private:
    // Short window — circular buffer
    std::deque<double> short_buf_;
    size_t short_max_;
    double short_ema_     = 0.0;
    double short_ema_var_ = 0.0;
    double short_alpha_;
    int    short_count_   = 0;

    // Long window — EMA only (too expensive to buffer 600 values for all metrics)
    double long_ema_      = 0.0;
    double long_ema_var_  = 0.0;
    double long_alpha_;
    double long_min_      = 1e18;
    double long_max_      = -1e18;
    int    long_count_    = 0;

    // Percentile estimation — small sorted buffer
    std::deque<double> pctl_buf_;
    static constexpr size_t PCTL_BUF_SIZE = 100;

    // Trend tracking
    double trend_slope_ = 0.0;
    void updateTrend();

    // Sustained high tracking
    int consecutive_above_p95_ = 0;
};

/// Manages baselines for all metrics by name
class BaselineManager {
public:
    BaselineManager(double short_alpha = 0.15, double long_alpha = 0.05)
        : short_alpha_(short_alpha), long_alpha_(long_alpha) {}

    /// Feed a metric value
    void update(const std::string& metric_name, double value);

    /// Get a metric's baseline (creates if not exists)
    MetricBaseline& get(const std::string& metric_name);
    const MetricBaseline& get(const std::string& metric_name) const;

    bool has(const std::string& metric_name) const;

private:
    double short_alpha_;
    double long_alpha_;
    std::unordered_map<std::string, MetricBaseline> baselines_;
    // Dummy for const access to non-existent metrics
    static const MetricBaseline kEmpty;
};

} // namespace sysmon
