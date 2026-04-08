#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// storage/storage_engine.h — Interface for metric persistence
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"
#include <vector>
#include <cstdint>

namespace sysmon {

class IStorageEngine {
public:
    virtual ~IStorageEngine() = default;

    /// Store any metric snapshot.  The implementation dispatches by variant type.
    virtual void store(const MetricSnapshot& snapshot) = 0;

    /// Query helpers — return snapshots in the [from, to] timestamp range (epoch ms).
    virtual std::vector<CpuSnapshot>     queryCpu(int64_t from, int64_t to) = 0;
    virtual std::vector<MemorySnapshot>  queryMemory(int64_t from, int64_t to) = 0;
    virtual std::vector<NetworkSnapshot> queryNetwork(int64_t from, int64_t to) = 0;

    /// Store an anomaly event.
    virtual void storeAnomaly(const AnomalyEvent& event) = 0;

    /// Initialize the database schema (create tables if not exist).
    virtual void initialize() = 0;
};

} // namespace sysmon
