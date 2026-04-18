// ─────────────────────────────────────────────────────────────────────────────
// core/config.cpp — Config loading from JSON
// ─────────────────────────────────────────────────────────────────────────────

#include "core/config.h"
#include "utils/logger.h"

#include <nlohmann/json.hpp>
#include <fstream>

namespace sysmon {

Config Config::loadFromFile(const std::string& path) {
    Config cfg;

    std::ifstream file(path);
    if (!file.is_open()) {
        LOG_WARN("Config file '{}' not found — using defaults", path);
        return cfg;
    }

    try {
        nlohmann::json j = nlohmann::json::parse(file);

        // Helper: read a value if the key exists
        auto read = [&](const char* key, auto& target) {
            if (j.contains(key)) {
                target = j[key].get<std::remove_reference_t<decltype(target)>>();
            }
        };

        // Collection intervals (in milliseconds in JSON)
        if (j.contains("cpu_interval_ms"))
            cfg.cpu_interval = std::chrono::milliseconds(j["cpu_interval_ms"].get<int>());
        if (j.contains("memory_interval_ms"))
            cfg.memory_interval = std::chrono::milliseconds(j["memory_interval_ms"].get<int>());
        if (j.contains("process_interval_ms"))
            cfg.process_interval = std::chrono::milliseconds(j["process_interval_ms"].get<int>());
        if (j.contains("network_interval_ms"))
            cfg.network_interval = std::chrono::milliseconds(j["network_interval_ms"].get<int>());
        if (j.contains("disk_interval_ms"))
            cfg.disk_interval = std::chrono::milliseconds(j["disk_interval_ms"].get<int>());

        read("db_path", cfg.db_path);
        read("retention_hours", cfg.retention_hours);
        read("anomaly_sigma", cfg.anomaly_sigma);
        read("ema_alpha", cfg.ema_alpha);
        read("log_file", cfg.log_file);
        read("log_level", cfg.log_level);

        LOG_INFO("Config loaded from '{}'", path);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to parse config '{}': {} — using defaults", path, e.what());
    }

    return cfg;
}

} // namespace sysmon
