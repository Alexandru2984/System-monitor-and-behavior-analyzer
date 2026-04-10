// ─────────────────────────────────────────────────────────────────────────────
// collectors/cpu_collector.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/cpu_collector.h"
#include "utils/logger.h"

#include <chrono>
#include <fstream>
#include <sstream>

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
    auto current = readProcStat();

    CpuSnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    if (current.empty()) {
        LOG_ERROR("CpuCollector: cannot read /proc/stat");
        snap.total_usage_percent = 0.0;
        prev_times_ = std::move(current);
        return snap;
    }

    // First call: no previous sample yet — store and return zeros.
    // Subsequent calls compute delta against the stored previous sample,
    // eliminating the 100ms sleep that used to block the scheduler thread.
    if (prev_times_.empty() || prev_times_.size() != current.size()) {
        snap.total_usage_percent = 0.0;
        for (size_t i = 1; i < current.size(); ++i)
            snap.core_usage_percent.push_back(0.0);
        prev_times_ = std::move(current);
        return snap;
    }

    // Index 0 is the aggregate "cpu" line; 1..N are individual cores
    for (size_t i = 0; i < current.size(); ++i) {
        long delta_active = current[i].activeTime() - prev_times_[i].activeTime();
        long delta_total  = current[i].totalTime()  - prev_times_[i].totalTime();

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

    prev_times_ = std::move(current);

    LOG_DEBUG("CPU: {:.1f}% total, {} cores",
              snap.total_usage_percent, snap.core_usage_percent.size());

    return snap;
}

} // namespace sysmon
