#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/pattern_detector.h — Heuristic pattern detection
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/baseline_manager.h"
#include "core/types.h"

#include <set>
#include <vector>

namespace sysmon {

class PatternDetector {
public:
    /// Detect patterns given the current snapshot and baseline state
    std::vector<PatternEvent> detect(const MetricSnapshot& snapshot,
                                      BaselineManager& baselines);

private:
    // Previous process PIDs for new/disappeared detection
    std::set<int> prev_pids_;
    bool has_prev_pids_ = false;

    std::vector<PatternEvent> detectCpuPatterns(const CpuSnapshot& s,
                                                 BaselineManager& bm);
    std::vector<PatternEvent> detectMemoryPatterns(const MemorySnapshot& s,
                                                    BaselineManager& bm);
    std::vector<PatternEvent> detectNetworkPatterns(const NetworkSnapshot& s,
                                                     BaselineManager& bm);
    std::vector<PatternEvent> detectProcessPatterns(const ProcessSnapshot& s);
};

} // namespace sysmon
