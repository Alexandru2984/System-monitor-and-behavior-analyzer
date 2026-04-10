#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// collectors/cpu_collector.h
// ─────────────────────────────────────────────────────────────────────────────
// Reads /proc/stat to compute per-core and aggregate CPU usage.
//
// HOW IT WORKS:
//   /proc/stat reports cumulative "jiffies" (CPU time slices) per core.
//   To get a *percentage*, we need TWO reads separated by a short delay:
//
//     delta_active = active_jiffies(t2) - active_jiffies(t1)
//     delta_total  = total_jiffies(t2)  - total_jiffies(t1)
//     usage%       = (delta_active / delta_total) * 100
//
//   The delay between reads is 100ms — short enough to be near-instant,
//   long enough for meaningful deltas.
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"
#include <vector>

namespace sysmon {

class CpuCollector : public ICollector {
public:
    MetricSnapshot collect() override;
    std::string name() const override { return "CpuCollector"; }

private:
    // One set of jiffy readings per core (index 0 = aggregate "cpu" line)
    struct CpuTimes {
        long user = 0, nice = 0, system = 0, idle = 0;
        long iowait = 0, irq = 0, softirq = 0, steal = 0;

        long activeTime() const {
            return user + nice + system + irq + softirq + steal;
        }
        long totalTime() const {
            return activeTime() + idle + iowait;
        }
    };

    /// Parse all "cpu" lines from /proc/stat
    static std::vector<CpuTimes> readProcStat();

    /// Previous sample stored between calls (eliminates 100ms sleep)
    std::vector<CpuTimes> prev_times_;
};

} // namespace sysmon
