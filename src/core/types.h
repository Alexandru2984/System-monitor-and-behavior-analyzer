#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// core/types.h — Shared data structures for all metric snapshots
// ─────────────────────────────────────────────────────────────────────────────
//
// WHY std::variant<>?
//   A single pipeline can carry any metric type without void* casts or
//   inheritance overhead.  std::visit gives us compile-time exhaustiveness
//   checks — if you add a new snapshot type and forget to handle it, the
//   compiler tells you.
//
// WHY int64_t for timestamps?
//   Milliseconds since epoch.  Fits in 64 bits until the year 292 million.
//   Consistent across all modules; we convert to human-readable only at
//   display time.
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace sysmon {

// ── CPU ────────────────────────────────────────────────────────────────────
struct CpuSnapshot {
    int64_t timestamp;                        // epoch ms
    std::vector<double> core_usage_percent;   // per-core [0..100]
    double total_usage_percent;               // aggregate [0..100]
};

// ── Memory ─────────────────────────────────────────────────────────────────
struct MemorySnapshot {
    int64_t timestamp;
    uint64_t total_kb;
    uint64_t used_kb;
    uint64_t available_kb;
    double usage_percent;                     // [0..100]
};

// ── Processes ──────────────────────────────────────────────────────────────
struct ProcessInfo {
    int pid;
    std::string name;
    std::string state;      // R, S, D, Z, T …
    std::string user;
    double cpu_percent;
    double mem_percent;
};

struct ProcessSnapshot {
    int64_t timestamp;
    std::vector<ProcessInfo> processes;
};

// ── Network ────────────────────────────────────────────────────────────────
struct InterfaceStats {
    std::string name;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    double rx_rate_kbps;    // delta since last sample
    double tx_rate_kbps;
};

struct NetworkSnapshot {
    int64_t timestamp;
    std::vector<InterfaceStats> interfaces;
};

// ── Variant that can hold any snapshot ─────────────────────────────────────
using MetricSnapshot = std::variant<
    CpuSnapshot,
    MemorySnapshot,
    ProcessSnapshot,
    NetworkSnapshot
>;

// ── Anomaly event (produced by the analysis layer) ─────────────────────────
struct AnomalyEvent {
    int64_t timestamp;
    std::string metric_type;   // "cpu", "memory", "network", "process"
    std::string description;
    double severity;           // 0.0 – 1.0
    double risk_score;         // 0 – 100 composite
};

} // namespace sysmon
