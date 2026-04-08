// ─────────────────────────────────────────────────────────────────────────────
// collectors/memory_collector.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/memory_collector.h"
#include "utils/logger.h"

#include <chrono>
#include <fstream>
#include <sstream>
#include <string>

namespace sysmon {

MetricSnapshot MemoryCollector::collect() {
    MemorySnapshot snap{};
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo.is_open()) {
        LOG_ERROR("Cannot open /proc/meminfo");
        return snap;
    }

    // /proc/meminfo looks like:
    //   MemTotal:       16384000 kB
    //   MemFree:         2000000 kB
    //   MemAvailable:    5500000 kB
    //   ...
    // We only need MemTotal and MemAvailable.

    std::string line;
    bool got_total = false, got_available = false;

    while (std::getline(meminfo, line) && !(got_total && got_available)) {
        std::istringstream iss(line);
        std::string key;
        uint64_t value;
        iss >> key >> value;   // "MemTotal:" 16384000

        if (key == "MemTotal:") {
            snap.total_kb = value;
            got_total = true;
        } else if (key == "MemAvailable:") {
            snap.available_kb = value;
            got_available = true;
        }
    }

    // used = total - available  (accounts for reclaimable caches)
    snap.used_kb = snap.total_kb - snap.available_kb;
    snap.usage_percent = snap.total_kb > 0
        ? (static_cast<double>(snap.used_kb) / static_cast<double>(snap.total_kb)) * 100.0
        : 0.0;

    LOG_DEBUG("RAM: {:.1f}% used ({} / {} KB)",
              snap.usage_percent, snap.used_kb, snap.total_kb);

    return snap;
}

} // namespace sysmon
