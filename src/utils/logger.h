#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// utils/logger.h — Thread-safe logging wrapper around spdlog
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY wrap spdlog instead of using it directly?
//   1. Single point of configuration — all modules call Logger::init() once
//   2. If we ever swap spdlog for something else, only this file changes
//   3. Consistent log format and sink setup across the whole project
// ─────────────────────────────────────────────────────────────────────────────

#include <string>
#include <spdlog/spdlog.h>

namespace sysmon {

class Logger {
public:
    /// Call once at startup.  Sets up console + rotating file sinks.
    /// @param log_file  Path to the rotating log file (default: "sysmonitor.log")
    /// @param level     Minimum log level (default: info)
    static void init(
        const std::string& log_file = "sysmonitor.log",
        spdlog::level::level_enum level = spdlog::level::info
    );

    /// Get the shared logger instance (valid after init()).
    static std::shared_ptr<spdlog::logger>& get();
};

// ── Convenience macros ─────────────────────────────────────────────────────
// Usage:  LOG_INFO("CPU usage: {:.1f}%", total);
#define LOG_TRACE(...)    SPDLOG_LOGGER_TRACE(sysmon::Logger::get(), __VA_ARGS__)
#define LOG_DEBUG(...)    SPDLOG_LOGGER_DEBUG(sysmon::Logger::get(), __VA_ARGS__)
#define LOG_INFO(...)     SPDLOG_LOGGER_INFO(sysmon::Logger::get(), __VA_ARGS__)
#define LOG_WARN(...)     SPDLOG_LOGGER_WARN(sysmon::Logger::get(), __VA_ARGS__)
#define LOG_ERROR(...)    SPDLOG_LOGGER_ERROR(sysmon::Logger::get(), __VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_LOGGER_CRITICAL(sysmon::Logger::get(), __VA_ARGS__)

} // namespace sysmon
