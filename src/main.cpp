// ─────────────────────────────────────────────────────────────────────────────
// main.cpp — Entry point: wires all components and runs the monitor
// ─────────────────────────────────────────────────────────────────────────────
//
// STARTUP FLOW:
//   1. Load config (from CLI arg or default path)
//   2. Initialize logger
//   3. Initialize SQLite storage
//   4. Create collectors
//   5. Create scheduler, register collectors
//   6. Start scheduler (spawns collection threads)
//   7. Wait for SIGINT/SIGTERM → graceful shutdown
// ─────────────────────────────────────────────────────────────────────────────

#include "core/config.h"
#include "core/scheduler.h"
#include "collectors/cpu_collector.h"
#include "collectors/memory_collector.h"
#include "collectors/process_collector.h"
#include "collectors/network_collector.h"
#include "collectors/disk_collector.h"
#include "storage/sqlite_storage.h"
#include "utils/logger.h"

#include <csignal>
#include <memory>
#include <unistd.h>  // write()
#include <atomic>
#include <condition_variable>
#include <mutex>

// ── Global shutdown signal ─────────────────────────────────────────────────
static std::atomic<bool> g_shutdown{false};
static std::condition_variable g_cv;
static std::mutex g_mutex;

static void signalHandler(int signum) {
    // Only use async-signal-safe functions here.
    // std::cout is NOT safe; use write() instead.
    const char msg[] = "\n[sysmonitor] Signal received, shutting down...\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)signum;
    g_shutdown.store(true);
    g_cv.notify_all();
}

int main(int argc, char* argv[]) {
    // ── 1. Load config ─────────────────────────────────────────────────────
    std::string config_path = "config/default.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    // Initialize logger early (with defaults) so config loading can log
    sysmon::Logger::init();
    auto cfg = sysmon::Config::loadFromFile(config_path);

    // Re-init logger with configured settings
    auto level = spdlog::level::from_str(cfg.log_level);
    if (level == spdlog::level::off && cfg.log_level != "off") {
        LOG_WARN("Invalid log_level '{}' in config — falling back to 'info'", cfg.log_level);
        level = spdlog::level::info;
    }
    sysmon::Logger::init(cfg.log_file, level);

    LOG_INFO("═══════════════════════════════════════════════════════════");
    LOG_INFO("  Self-Evolving System Monitor v0.1.0");
    LOG_INFO("═══════════════════════════════════════════════════════════");
    LOG_INFO("DB: {}  |  Log: {}  |  Level: {}",
             cfg.db_path, cfg.log_file, cfg.log_level);
    LOG_INFO("Intervals — CPU: {}ms  RAM: {}ms  Net: {}ms  Proc: {}ms",
             cfg.cpu_interval.count(), cfg.memory_interval.count(),
             cfg.network_interval.count(), cfg.process_interval.count());

    // ── 2. Initialize storage ──────────────────────────────────────────────
    auto storage = std::make_shared<sysmon::SqliteStorage>(cfg.db_path);
    storage->initialize();

    // ── 3. Create collectors ───────────────────────────────────────────────
    auto cpu_collector     = std::make_shared<sysmon::CpuCollector>();
    auto memory_collector  = std::make_shared<sysmon::MemoryCollector>();
    auto process_collector = std::make_shared<sysmon::ProcessCollector>();
    auto network_collector = std::make_shared<sysmon::NetworkCollector>();
    auto disk_collector    = std::make_shared<sysmon::DiskCollector>();

    // ── 4. Create scheduler and register collectors ────────────────────────
    sysmon::Scheduler scheduler(storage, cfg);
    scheduler.addCollector(cpu_collector,     cfg.cpu_interval);
    scheduler.addCollector(memory_collector,  cfg.memory_interval);
    scheduler.addCollector(process_collector, cfg.process_interval);
    scheduler.addCollector(network_collector, cfg.network_interval);
    scheduler.addCollector(disk_collector,    cfg.disk_interval);

    // ── 5. Install signal handlers ─────────────────────────────────────────
    struct sigaction sa{};
    sa.sa_handler = signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    // ── 6. Start monitoring ────────────────────────────────────────────────
    scheduler.start();
    LOG_INFO("Monitoring started — press Ctrl+C to stop");

    // ── 7. Wait for shutdown signal ────────────────────────────────────────
    {
        std::unique_lock<std::mutex> lock(g_mutex);
        g_cv.wait(lock, [] { return g_shutdown.load(); });
    }

    // ── 8. Graceful shutdown ───────────────────────────────────────────────
    scheduler.stop();
    LOG_INFO("Shutdown complete. Goodbye!");

    return 0;
}
