// ─────────────────────────────────────────────────────────────────────────────
// collectors/cpu_collector.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/cpu_collector.h"
#include "utils/logger.h"

#include <chrono>
#include <fstream>
#include <sstream>
#include <thread>

namespace sysmon {

std::vector<CpuCollector::CpuTimes> CpuCollector::readProcStat() {
    std::vector<CpuTimes> result;
    std::ifstream stat("/proc/stat");

    if (!stat.is_open()) {
        LOG_ERROR("Cannot open /proc/stat");
        return result;
    }

    std::string line;
    while (std::getline(stat, line)) {
        // Lines look like:  cpu  12345 678 ...   (aggregate)
        //                   cpu0 12345 678 ...   (per-core)
        if (line.compare(0, 3, "cpu") != 0) break;  // past CPU lines

        std::istringstream iss(line);
        std::string label;
        CpuTimes t{};
        iss >> label >> t.user >> t.nice >> t.system >> t.idle
            >> t.iowait >> t.irq >> t.softirq >> t.steal;
        result.push_back(t);
    }

    return result;
}

MetricSnapshot CpuCollector::collect() {
    // ── First sample ───────────────────────────────────────────────────────
    auto times1 = readProcStat();

    // ── Wait for a measurable delta ────────────────────────────────────────
    // 100ms gives enough jiffies for accurate percentages without blocking
    // the collection thread for too long.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ── Second sample ──────────────────────────────────────────────────────
    auto times2 = readProcStat();

    CpuSnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    if (times1.empty() || times2.empty() || times1.size() != times2.size()) {
        LOG_ERROR("CpuCollector: inconsistent /proc/stat reads");
        snap.total_usage_percent = 0.0;
        return snap;
    }

    // Index 0 is the aggregate "cpu" line; 1..N are individual cores
    for (size_t i = 0; i < times1.size(); ++i) {
        long delta_active = times2[i].activeTime() - times1[i].activeTime();
        long delta_total  = times2[i].totalTime()  - times1[i].totalTime();

        double usage = 0.0;
        if (delta_total > 0) {
            usage = (static_cast<double>(delta_active) /
                     static_cast<double>(delta_total)) * 100.0;
        }

        if (i == 0) {
            snap.total_usage_percent = usage;
        } else {
            snap.core_usage_percent.push_back(usage);
        }
    }

    LOG_DEBUG("CPU: {:.1f}% total, {} cores",
              snap.total_usage_percent, snap.core_usage_percent.size());

    return snap;
}

} // namespace sysmon
