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

// ── Base event (common fields for all analysis events) ─────────────────────
struct BaseEvent {
    int64_t timestamp;
    std::string metric_type;   // "cpu", "memory", "network", "process"
    std::string description;   // human-readable
};

// ── Anomaly event (produced by the analysis layer) ─────────────────────────
struct AnomalyEvent : BaseEvent {
    double severity;           // 0.0 – 1.0
    double risk_score;         // 0 – 100 composite
};

// ── Pattern types (detected by the Analyzer module) ────────────────────────
enum class PatternType {
    SustainedHighLoad,   // Value above P95 for N consecutive samples
    Oscillation,         // Crossing mean >K times in a window (thrashing)
    Trend,               // Linear regression slope exceeds threshold
    MemoryLeak,          // Monotonically increasing memory over long window
    NewProcess,          // A process appeared that wasn't in previous snapshot
    DisappearedProcess,  // A process disappeared unexpectedly
};

struct PatternEvent : BaseEvent {
    PatternType type;
    double confidence;         // 0.0 – 1.0
};

// ── Risk breakdown (multi-factor scoring) ──────────────────────────────────
struct RiskBreakdown {
    double severity_score   = 0.0;   // raw statistical deviation (weight: 30)
    double persistence_score = 0.0;  // how long the anomaly persists (weight: 25)
    double breadth_score    = 0.0;   // how many metrics are anomalous (weight: 20)
    double recency_score    = 0.0;   // time-decayed weight (weight: 15)
    double familiarity_score = 0.0;  // seen before → lower risk (weight: 10)
    double total             = 0.0;  // composite [0..100]
};

// ── Analysis report (full output of one analyze() call) ────────────────────
struct AnalysisReport {
    int64_t timestamp;
    std::vector<AnomalyEvent> anomalies;
    std::vector<PatternEvent> patterns;
    std::string explanation;         // human-readable multi-line report
    RiskBreakdown risk;
};

// ── Incident (group of correlated events within a time window) ─────────────
struct Incident {
    int64_t id;
    int64_t start_time;
    int64_t end_time;
    std::string summary;
    double peak_risk;
    int event_count;
    bool is_active;
};

} // namespace sysmon
