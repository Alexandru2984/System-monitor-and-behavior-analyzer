#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// collectors/collector.h — Interface that every metric collector implements
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY a pure virtual interface?
//   1. Testability  — we can create mock collectors in unit tests
//   2. Extensibility — new collectors (e.g. disk I/O) plug in without
//      touching the scheduler
//   3. Decoupling   — the scheduler doesn't know or care what it's collecting
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"
#include <string>

namespace sysmon {

class ICollector {
public:
    virtual ~ICollector() = default;

    /// Perform one collection cycle and return a snapshot.
    /// Implementations read from /proc/ and return the appropriate variant.
    virtual MetricSnapshot collect() = 0;

    /// Human-readable name for logging, e.g. "CpuCollector".
    virtual std::string name() const = 0;
};

} // namespace sysmon
