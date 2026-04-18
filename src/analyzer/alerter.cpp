// ─────────────────────────────────────────────────────────────────────────────
// analyzer/alerter.cpp — Desktop notification implementation
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/alerter.h"
#include "utils/logger.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <format>

namespace sysmon {

Alerter::Alerter(double high_threshold, double critical_threshold, int64_t cooldown_ms)
    : high_threshold_(high_threshold)
    , critical_threshold_(critical_threshold)
    , cooldown_ms_(cooldown_ms)
{}

void Alerter::check(const AnalysisReport& report) {
    if (!enabled_) return;
    if (report.risk.total < high_threshold_) return;

    // Rate limit
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now - last_alert_ts_ < cooldown_ms_) return;

    last_alert_ts_ = now;

    bool is_critical = report.risk.total >= critical_threshold_;
    std::string urgency = is_critical ? "critical" : "normal";

    std::string title = is_critical
        ? std::format("⚠ CRITICAL: Risk {:.0f}/100", report.risk.total)
        : std::format("⚡ HIGH: Risk {:.0f}/100", report.risk.total);

    std::string body;
    if (!report.anomalies.empty()) {
        body = std::format("{} anomalies detected", report.anomalies.size());
        // Add first anomaly description as detail
        if (!report.anomalies[0].description.empty()) {
            body += "\n" + report.anomalies[0].description;
        }
    }
    if (!report.patterns.empty()) {
        if (!body.empty()) body += "\n";
        body += std::format("{} patterns detected", report.patterns.size());
    }

    sendNotification(title, body, urgency);
}

void Alerter::sendNotification(const std::string& title,
                                const std::string& body,
                                const std::string& urgency) {
    // Build the notify-send command
    // -u: urgency (low, normal, critical)
    // -t: timeout in ms (5s for normal, 10s for critical)
    // -a: app name
    int timeout = (urgency == "critical") ? 10000 : 5000;

    std::string cmd = std::format(
        "notify-send -u {} -t {} -a 'System Monitor' '{}' '{}' 2>/dev/null &",
        urgency, timeout, title, body);

    // Run asynchronously (& at end) so it doesn't block the analysis thread
    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        // notify-send might not be installed — log once and disable
        LOG_WARN("Alerter: notify-send failed (exit {}). "
                 "Install libnotify-bin for desktop notifications.", ret);
    } else {
        LOG_INFO("Alert sent: {}", title);
    }
}

} // namespace sysmon
