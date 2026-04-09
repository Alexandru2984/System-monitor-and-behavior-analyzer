// ─────────────────────────────────────────────────────────────────────────────
// analyzer/baseline_manager.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/baseline_manager.h"

#include <vector>

namespace sysmon {

// ── MetricBaseline ──────────────────────────────────────────────────────────

MetricBaseline::MetricBaseline(size_t short_window, size_t long_window,
                               double alpha_short, double alpha_long)
    : short_max_(short_window)
    , short_alpha_(alpha_short)
    , long_alpha_(alpha_long)
{
    (void)long_window;  // long window uses EMA, not a buffer
}

void MetricBaseline::update(double value) {
    // ── Short window (buffered) ───────────────────────────────────────────
    short_buf_.push_back(value);
    while (short_buf_.size() > short_max_) short_buf_.pop_front();

    if (short_count_ == 0) {
        short_ema_ = value;
        short_ema_var_ = 0.0;
    } else {
        double delta = value - short_ema_;
        short_ema_ += short_alpha_ * delta;
        short_ema_var_ = (1.0 - short_alpha_) * (short_ema_var_ + short_alpha_ * delta * delta);
    }
    short_count_++;

    // ── Long window (EMA only) ────────────────────────────────────────────
    if (long_count_ == 0) {
        long_ema_ = value;
        long_ema_var_ = 0.0;
    } else {
        double delta = value - long_ema_;
        long_ema_ += long_alpha_ * delta;
        long_ema_var_ = (1.0 - long_alpha_) * (long_ema_var_ + long_alpha_ * delta * delta);
    }
    long_min_ = std::min(long_min_, value);
    long_max_ = std::max(long_max_, value);
    long_count_++;

    // ── Sustained high tracking ───────────────────────────────────────────
    // Must compute P95 BEFORE adding value to pctl_buf (avoids self-contamination)
    {
        double prev_p95 = longWindow().p95;
        if (long_count_ > 20 && value > prev_p95) {
            consecutive_above_p95_++;
        } else {
            consecutive_above_p95_ = 0;
        }
    }

    // ── Percentile buffer ─────────────────────────────────────────────────
    pctl_buf_.push_back(value);
    while (pctl_buf_.size() > PCTL_BUF_SIZE) pctl_buf_.pop_front();

    // ── Trend ─────────────────────────────────────────────────────────────
    updateTrend();
}

WindowStats MetricBaseline::shortWindow() const {
    WindowStats s;
    s.count = short_count_;
    s.ready = short_count_ > 5;
    s.mean  = short_ema_;
    s.sigma = std::sqrt(std::max(0.0, short_ema_var_));

    if (!short_buf_.empty()) {
        s.min_val = *std::min_element(short_buf_.begin(), short_buf_.end());
        s.max_val = *std::max_element(short_buf_.begin(), short_buf_.end());
    }

    // P95/P99 from short buffer
    if (short_buf_.size() >= 10) {
        auto sorted = std::vector<double>(short_buf_.begin(), short_buf_.end());
        std::sort(sorted.begin(), sorted.end());
        s.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        s.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
    }

    return s;
}

WindowStats MetricBaseline::longWindow() const {
    WindowStats s;
    s.count   = long_count_;
    s.ready   = long_count_ > 20;
    s.mean    = long_ema_;
    s.sigma   = std::sqrt(std::max(0.0, long_ema_var_));
    s.min_val = long_min_ < 1e17 ? long_min_ : 0.0;
    s.max_val = long_max_ > -1e17 ? long_max_ : 0.0;

    // P95/P99 from percentile buffer
    if (pctl_buf_.size() >= 20) {
        auto sorted = std::vector<double>(pctl_buf_.begin(), pctl_buf_.end());
        std::sort(sorted.begin(), sorted.end());
        s.p95 = sorted[static_cast<size_t>(sorted.size() * 0.95)];
        s.p99 = sorted[static_cast<size_t>(sorted.size() * 0.99)];
    } else {
        // Fallback: approximate from EMA
        s.p95 = long_ema_ + 1.645 * s.sigma;
        s.p99 = long_ema_ + 2.326 * s.sigma;
    }

    return s;
}

double MetricBaseline::anomalyThreshold(double sigma_multiplier, double sigma_floor) const {
    double sigma = std::max(std::sqrt(std::max(0.0, long_ema_var_)), sigma_floor);
    return long_ema_ + sigma_multiplier * sigma;
}

void MetricBaseline::updateTrend() {
    // Simple linear regression on the short buffer
    // slope = Σ((x - x̄)(y - ȳ)) / Σ((x - x̄)²)
    if (short_buf_.size() < 10) {
        trend_slope_ = 0.0;
        return;
    }

    int n = static_cast<int>(short_buf_.size());
    double x_mean = (n - 1) / 2.0;
    double y_mean = 0.0;
    for (auto v : short_buf_) y_mean += v;
    y_mean /= n;

    double num = 0.0, den = 0.0;
    for (int i = 0; i < n; ++i) {
        double dx = i - x_mean;
        num += dx * (short_buf_[static_cast<size_t>(i)] - y_mean);
        den += dx * dx;
    }

    trend_slope_ = (den > 0) ? num / den : 0.0;
}

int MetricBaseline::oscillationCount() const {
    if (short_buf_.size() < 5 || long_count_ < 20) return 0;

    double mean = long_ema_;
    int crossings = 0;
    bool above = short_buf_.front() > mean;

    for (size_t i = 1; i < short_buf_.size(); ++i) {
        bool now_above = short_buf_[i] > mean;
        if (now_above != above) {
            crossings++;
            above = now_above;
        }
    }

    return crossings;
}

bool MetricBaseline::isSustainedHigh(int min_consecutive) const {
    return consecutive_above_p95_ >= min_consecutive;
}

bool MetricBaseline::isMonotonicallyIncreasing(int samples) const {
    int n = std::min(static_cast<int>(short_buf_.size()), samples);
    if (n < 5) return false;

    int start = static_cast<int>(short_buf_.size()) - n;
    int increases = 0;
    for (int i = start + 1; i < static_cast<int>(short_buf_.size()); ++i) {
        if (short_buf_[static_cast<size_t>(i)] >= short_buf_[static_cast<size_t>(i - 1)]) {
            increases++;
        }
    }

    // Allow up to 10% non-increasing samples (noise tolerance)
    return increases >= static_cast<int>((n - 1) * 0.9);
}

// ── BaselineManager ─────────────────────────────────────────────────────────

const MetricBaseline BaselineManager::kEmpty{};

void BaselineManager::update(const std::string& metric_name, double value) {
    baselines_[metric_name].update(value);
}

MetricBaseline& BaselineManager::get(const std::string& metric_name) {
    return baselines_[metric_name];
}

const MetricBaseline& BaselineManager::get(const std::string& metric_name) const {
    auto it = baselines_.find(metric_name);
    return it != baselines_.end() ? it->second : kEmpty;
}

bool BaselineManager::has(const std::string& metric_name) const {
    return baselines_.count(metric_name) > 0;
}

} // namespace sysmon
