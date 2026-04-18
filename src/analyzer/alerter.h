#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/alerter.h — Desktop notification alerts for high-risk events
// ─────────────────────────────────────────────────────────────────────────────
//
// Sends desktop notifications via notify-send (Linux) when risk exceeds
// configurable thresholds.  Rate-limited to avoid notification spam.
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"

#include <cstdint>
#include <string>

namespace sysmon {

class Alerter {
public:
    /// @param high_threshold  Risk score above which a HIGH alert fires
    /// @param critical_threshold  Risk score above which a CRITICAL alert fires
    /// @param cooldown_ms  Minimum time between notifications (default: 60s)
    explicit Alerter(double high_threshold = 40.0,
                     double critical_threshold = 70.0,
                     int64_t cooldown_ms = 60'000);

    /// Check a report and send a notification if warranted.
    /// Rate-limited: won't fire more than once per cooldown period.
    void check(const AnalysisReport& report);

    /// Enable or disable alerting at runtime
    void setEnabled(bool enabled) { enabled_ = enabled; }
    bool enabled() const { return enabled_; }

private:
    double high_threshold_;
    double critical_threshold_;
    int64_t cooldown_ms_;
    int64_t last_alert_ts_ = 0;
    bool enabled_ = true;

    void sendNotification(const std::string& title,
                          const std::string& body,
                          const std::string& urgency);
};

} // namespace sysmon
