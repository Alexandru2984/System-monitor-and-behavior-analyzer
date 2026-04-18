// ─────────────────────────────────────────────────────────────────────────────
// utils/logger.cpp — Logger implementation
// ─────────────────────────────────────────────────────────────────────────────

#include "utils/logger.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>

namespace sysmon {

// Static storage for the shared logger
static std::shared_ptr<spdlog::logger> s_logger;

void Logger::init(const std::string& log_file, spdlog::level::level_enum level) {
    // Two sinks: colored console + rotating file (5 MB max, 3 rotated files)
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink->set_level(level);

    constexpr size_t max_size = 5 * 1024 * 1024;  // 5 MB
    constexpr size_t max_files = 3;
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file, max_size, max_files
    );
    file_sink->set_level(spdlog::level::trace);  // file captures everything

    // Combine sinks into one logger
    s_logger = std::make_shared<spdlog::logger>(
        "sysmon",
        spdlog::sinks_init_list{console_sink, file_sink}
    );
    s_logger->set_level(level);

    // Pattern: [2026-04-09 02:10:34.123] [sysmon] [info] message
    s_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%n] [%^%l%$] %v");

    // Flush on warnings and above (so we don't lose crash messages)
    s_logger->flush_on(spdlog::level::warn);

    // Register as default so spdlog::info() etc. also work
    spdlog::set_default_logger(s_logger);
}

std::shared_ptr<spdlog::logger>& Logger::get() {
    if (!s_logger) {
        // Fallback: create a minimal console logger if init() was never called.
        // This prevents null pointer dereference in LOG_* macros.
        auto fallback = spdlog::stdout_color_mt("sysmon_fallback");
        fallback->set_level(spdlog::level::debug);
        fallback->warn("Logger::get() called before init() — using fallback console logger");
        s_logger = fallback;
    }
    return s_logger;
}

} // namespace sysmon
