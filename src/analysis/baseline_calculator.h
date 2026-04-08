#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analysis/baseline_calculator.h
// ─────────────────────────────────────────────────────────────────────────────
// Maintains exponential moving averages (EMA) and variance estimates
// for CPU and memory usage.
//
// EMA FORMULA:
//   ema_new = α * value  +  (1 - α) * ema_old
//
//   α (alpha) controls how fast the baseline adapts:
//     α close to 1  → adapts fast, forgets history quickly
//     α close to 0  → adapts slowly, very stable baseline
//     Default: 0.1  → weighted average over ~10 samples
//
// VARIANCE (for anomaly detection):
//   We also maintain an EMA of the squared deviation:
//     var_new = α * (value - ema_old)²  +  (1 - α) * var_old
//     sigma   = sqrt(var)
//
//   This gives us a running standard deviation without storing a window buffer.
// ─────────────────────────────────────────────────────────────────────────────

namespace sysmon {

class BaselineCalculator {
public:
    explicit BaselineCalculator(double alpha = 0.1);

    /// Feed a new observation value.  Updates EMA and variance.
    void update(double value);

    /// Current baseline (EMA).
    double mean() const { return ema_; }

    /// Current estimated standard deviation.
    double sigma() const;

    /// Has the baseline been initialized (at least one observation)?
    bool ready() const { return count_ > 0; }

    /// Number of observations received.
    int count() const { return count_; }

private:
    double alpha_;
    double ema_      = 0.0;
    double ema_var_  = 0.0;   // EMA of squared deviation
    int    count_    = 0;
};

} // namespace sysmon
