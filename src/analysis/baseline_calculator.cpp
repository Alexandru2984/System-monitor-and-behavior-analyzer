// ─────────────────────────────────────────────────────────────────────────────
// analysis/baseline_calculator.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "analysis/baseline_calculator.h"
#include <cmath>

namespace sysmon {

BaselineCalculator::BaselineCalculator(double alpha)
    : alpha_(alpha) {}

void BaselineCalculator::update(double value) {
    if (count_ == 0) {
        // First observation: initialize directly
        ema_ = value;
        ema_var_ = 0.0;
    } else {
        double diff = value - ema_;
        ema_     = alpha_ * value + (1.0 - alpha_) * ema_;
        ema_var_ = alpha_ * (diff * diff) + (1.0 - alpha_) * ema_var_;
    }
    ++count_;
}

double BaselineCalculator::sigma() const {
    return std::sqrt(ema_var_);
}

} // namespace sysmon
