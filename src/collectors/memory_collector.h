#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// collectors/memory_collector.h
// ─────────────────────────────────────────────────────────────────────────────
// Reads /proc/meminfo to get total, available, and used memory.
//
// KEY INSIGHT:
//   "Used" memory is NOT simply Total - Free.  Linux uses "free" RAM for
//   disk caches and buffers, which are reclaimable.  The correct formula:
//
//     used = total - available
//
//   where "available" is MemAvailable from /proc/meminfo (kernel ≥ 3.14),
//   which accounts for reclaimable caches.  This matches what `free -h` shows.
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"

namespace sysmon {

class MemoryCollector : public ICollector {
public:
    MetricSnapshot collect() override;
    std::string name() const override { return "MemoryCollector"; }
};

} // namespace sysmon
