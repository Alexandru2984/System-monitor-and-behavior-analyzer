#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// analyzer/event_timeline.h — SQLite-backed incident timeline
// ─────────────────────────────────────────────────────────────────────────────

#include "core/types.h"

#include <sqlite3.h>
#include <mutex>
#include <string>
#include <vector>

namespace sysmon {

class EventTimeline {
public:
    explicit EventTimeline(sqlite3* db);

    /// Create the events & incidents tables
    void initialize();

    /// Record an analysis report as a timeline event
    void record(const AnalysisReport& report);

    /// Query: get recent incidents
    std::vector<Incident> getIncidents(int64_t from_ts, int64_t to_ts);

    /// Query: get active (ongoing) incident, if any
    Incident getActiveIncident();

    /// Query: get the last N analysis events
    std::vector<AnalysisReport> getRecentEvents(int limit = 20);

private:
    sqlite3* db_;
    std::mutex mutex_;

    // Incident management
    int64_t active_incident_id_ = -1;
    int64_t last_anomaly_ts_ = 0;

    // Gap threshold: if no anomalies for this long, close the incident
    static constexpr int64_t INCIDENT_GAP_MS = 30'000;  // 30 seconds

    void exec(const char* sql);
    void openOrExtendIncident(const AnalysisReport& report);
    void closeActiveIncident(int64_t end_time);
};

} // namespace sysmon
