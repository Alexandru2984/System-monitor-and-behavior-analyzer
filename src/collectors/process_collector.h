#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// collectors/process_collector.h
// ─────────────────────────────────────────────────────────────────────────────
// Scans /proc/[pid]/ directories to enumerate running processes.
//
// APPROACH:
//   1. Iterate /proc/ for numeric directories → each is a PID
//   2. Read /proc/[pid]/stat  → process name, state, CPU times
//   3. Read /proc/[pid]/status → UID → map to username
//   4. Compute per-process CPU% using delta of utime+stime between samples
//   5. Read /proc/[pid]/statm → RSS → compute memory%
//
// CAVEAT:
//   Processes can exit between directory listing and file reads.
//   We silently skip any PID whose files we can't open (race condition
//   is expected and harmless).
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"
#include <unordered_map>

namespace sysmon {

class ProcessCollector : public ICollector {
public:
    MetricSnapshot collect() override;
    std::string name() const override { return "ProcessCollector"; }

private:
    // Previous CPU times per PID for delta calculation
    struct ProcTimes {
        long utime = 0;
        long stime = 0;
        int64_t timestamp = 0;  // epoch ms when sampled
    };
    std::unordered_map<int, ProcTimes> prev_times_;
};

} // namespace sysmon
