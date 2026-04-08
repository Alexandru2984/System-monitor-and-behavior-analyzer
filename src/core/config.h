#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// core/config.h — Runtime configuration loaded from JSON
// ─────────────────────────────────────────────────────────────────────────────

#include <chrono>
#include <string>

namespace sysmon {

struct Config {
    // Collection intervals
    std::chrono::milliseconds cpu_interval{1000};
    std::chrono::milliseconds memory_interval{1000};
    std::chrono::milliseconds process_interval{5000};
    std::chrono::milliseconds network_interval{2000};

    // Storage
    std::string db_path = "sysmonitor.db";
    int retention_hours = 24;          // prune data older than this

    // Analysis
    double anomaly_sigma = 2.0;        // flag if metric > baseline + N*sigma
    double ema_alpha = 0.1;            // EMA smoothing factor (0 < alpha ≤ 1)

    // Logging
    std::string log_file = "sysmonitor.log";
    std::string log_level = "info";

    /// Load config from a JSON file.  Missing keys keep defaults.
    static Config loadFromFile(const std::string& path);
};

} // namespace sysmon
