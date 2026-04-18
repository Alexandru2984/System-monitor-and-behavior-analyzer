// ─────────────────────────────────────────────────────────────────────────────
// analyzer/event_timeline.cpp — SQLite-backed incident timeline
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/event_timeline.h"
#include "utils/logger.h"

#include <chrono>
#include <stdexcept>

namespace sysmon {

EventTimeline::EventTimeline(sqlite3* db)
    : db_(db) {}

EventTimeline::~EventTimeline() {
    // Close any active incident before shutting down so it doesn't remain
    // stuck with is_active=1 across restarts.
    if (db_ && active_incident_id_ >= 0) {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        closeActiveIncident(now);
    }
    // Finalize prepared statements
    if (stmt_insert_event_)    sqlite3_finalize(stmt_insert_event_);
    if (stmt_insert_incident_) sqlite3_finalize(stmt_insert_incident_);
    if (stmt_update_incident_) sqlite3_finalize(stmt_update_incident_);
    // Do NOT close db_ — it's owned by SqliteStorage
}

void EventTimeline::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("EventTimeline SQL error: " + msg);
    }
}

void EventTimeline::initialize() {
    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS analysis_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            anomaly_count INTEGER NOT NULL,
            pattern_count INTEGER NOT NULL,
            risk_total  REAL    NOT NULL,
            explanation TEXT    NOT NULL,
            incident_id INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON analysis_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_incident ON analysis_events(incident_id);
    )SQL");

    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS incidents (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time  INTEGER NOT NULL,
            end_time    INTEGER,
            summary     TEXT,
            peak_risk   REAL    NOT NULL DEFAULT 0,
            event_count INTEGER NOT NULL DEFAULT 0,
            is_active   INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(start_time);
    )SQL");

    // Close any stale incidents left active from a previous unclean shutdown
    exec("UPDATE incidents SET is_active = 0, summary = 'Closed on restart (unclean shutdown)' "
         "WHERE is_active = 1;");

    prepareStatements();
}

void EventTimeline::prepareStatements() {
    auto prepare = [&](const char* sql, sqlite3_stmt** stmt) {
        if (sqlite3_prepare_v2(db_, sql, -1, stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(
                std::string("EventTimeline: failed to prepare statement: ") + sqlite3_errmsg(db_));
        }
    };

    prepare("INSERT INTO analysis_events "
            "(timestamp, anomaly_count, pattern_count, risk_total, "
            "explanation, incident_id) VALUES (?,?,?,?,?,?);",
            &stmt_insert_event_);

    prepare("INSERT INTO incidents "
            "(start_time, peak_risk, event_count, is_active) "
            "VALUES (?,?,1,1);",
            &stmt_insert_incident_);

    prepare("UPDATE incidents SET "
            "peak_risk = MAX(peak_risk, ?), "
            "event_count = event_count + 1 "
            "WHERE id = ?;",
            &stmt_update_incident_);
}

void EventTimeline::record(const AnalysisReport& report) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool has_anomalies = !report.anomalies.empty();
    bool has_patterns = !report.patterns.empty();
    bool has_events = has_anomalies || has_patterns;

    // If there are anomalies, open or extend an incident
    if (has_anomalies) {
        openOrExtendIncident(report);
    } else if (active_incident_id_ >= 0 &&
               report.timestamp - last_anomaly_ts_ > INCIDENT_GAP_MS) {
        // No anomalies and gap exceeded → close incident
        closeActiveIncident(report.timestamp);
    }

    // Throttle empty events to 1 every 5 seconds to prevent DB/UI spam
    if (!has_events && (report.timestamp - last_heartbeat_ts_ < 5000)) {
        return;
    }
    if (!has_events) last_heartbeat_ts_ = report.timestamp;

    // Insert event using prepared statement
    sqlite3_bind_int64(stmt_insert_event_, 1, report.timestamp);
    sqlite3_bind_int(stmt_insert_event_, 2, static_cast<int>(report.anomalies.size()));
    sqlite3_bind_int(stmt_insert_event_, 3, static_cast<int>(report.patterns.size()));
    sqlite3_bind_double(stmt_insert_event_, 4, report.risk.total);
    sqlite3_bind_text(stmt_insert_event_, 5, report.explanation.c_str(),
                      static_cast<int>(report.explanation.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt_insert_event_, 6, active_incident_id_ >= 0 ? active_incident_id_ : 0);

    int rc = sqlite3_step(stmt_insert_event_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("EventTimeline: insert event failed: {}", sqlite3_errmsg(db_));
    }
    sqlite3_reset(stmt_insert_event_);
}

void EventTimeline::openOrExtendIncident(const AnalysisReport& report) {
    last_anomaly_ts_ = report.timestamp;

    if (active_incident_id_ < 0) {
        // Create new incident
        sqlite3_bind_int64(stmt_insert_incident_, 1, report.timestamp);
        sqlite3_bind_double(stmt_insert_incident_, 2, report.risk.total);
        int rc = sqlite3_step(stmt_insert_incident_);
        if (rc != SQLITE_DONE) {
            LOG_ERROR("EventTimeline: insert incident failed: {}", sqlite3_errmsg(db_));
        }
        sqlite3_reset(stmt_insert_incident_);

        active_incident_id_ = sqlite3_last_insert_rowid(db_);
        LOG_INFO("Opened new incident #{}", active_incident_id_);
    } else {
        // Extend existing incident
        sqlite3_bind_double(stmt_update_incident_, 1, report.risk.total);
        sqlite3_bind_int64(stmt_update_incident_, 2, active_incident_id_);
        int rc = sqlite3_step(stmt_update_incident_);
        if (rc != SQLITE_DONE) {
            LOG_ERROR("EventTimeline: update incident failed: {}", sqlite3_errmsg(db_));
        }
        sqlite3_reset(stmt_update_incident_);
    }
}

void EventTimeline::closeActiveIncident(int64_t end_time) {
    if (active_incident_id_ < 0) return;

    // Generate summary from the incident's events
    const char* summary_sql =
        "SELECT COUNT(*) as cnt, MAX(risk_total) as peak "
        "FROM analysis_events WHERE incident_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, summary_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        active_incident_id_ = -1;
        return;
    }
    sqlite3_bind_int64(stmt, 1, active_incident_id_);

    std::string summary = "Incident resolved";
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        int cnt = sqlite3_column_int(stmt, 0);
        double peak = sqlite3_column_double(stmt, 1);
        summary = "Incident with " + std::to_string(cnt) +
                  " events (peak risk: " + std::to_string(static_cast<int>(peak)) + ")";
    }
    sqlite3_finalize(stmt);

    // Close
    const char* close_sql = "UPDATE incidents SET "
                            "end_time = ?, summary = ?, is_active = 0 "
                            "WHERE id = ?;";
    if (sqlite3_prepare_v2(db_, close_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        active_incident_id_ = -1;
        return;
    }
    sqlite3_bind_int64(stmt, 1, end_time);
    sqlite3_bind_text(stmt, 2, summary.c_str(),
                      static_cast<int>(summary.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, active_incident_id_);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    LOG_INFO("Closed incident #{}: {}", active_incident_id_, summary);
    active_incident_id_ = -1;
}

std::vector<Incident> EventTimeline::getIncidents(int64_t from_ts, int64_t to_ts) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Incident> results;

    const char* sql = "SELECT id, start_time, end_time, summary, peak_risk, "
                      "event_count, is_active FROM incidents "
                      "WHERE start_time >= ? AND start_time <= ? "
                      "ORDER BY start_time DESC;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return results;
    sqlite3_bind_int64(stmt, 1, from_ts);
    sqlite3_bind_int64(stmt, 2, to_ts);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Incident inc;
        inc.id = sqlite3_column_int64(stmt, 0);
        inc.start_time = sqlite3_column_int64(stmt, 1);
        inc.end_time = sqlite3_column_int64(stmt, 2);
        auto sum = sqlite3_column_text(stmt, 3);
        inc.summary = sum ? reinterpret_cast<const char*>(sum) : "";
        inc.peak_risk = sqlite3_column_double(stmt, 4);
        inc.event_count = sqlite3_column_int(stmt, 5);
        inc.is_active = sqlite3_column_int(stmt, 6) != 0;
        results.push_back(inc);
    }
    sqlite3_finalize(stmt);
    return results;
}

Incident EventTimeline::getActiveIncident() {
    std::lock_guard<std::mutex> lock(mutex_);
    Incident inc{};

    const char* sql = "SELECT id, start_time, end_time, summary, peak_risk, "
                      "event_count FROM incidents WHERE is_active = 1 LIMIT 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return inc;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        inc.id = sqlite3_column_int64(stmt, 0);
        inc.start_time = sqlite3_column_int64(stmt, 1);
        inc.end_time = sqlite3_column_int64(stmt, 2);
        auto sum = sqlite3_column_text(stmt, 3);
        inc.summary = sum ? reinterpret_cast<const char*>(sum) : "";
        inc.peak_risk = sqlite3_column_double(stmt, 4);
        inc.event_count = sqlite3_column_int(stmt, 5);
        inc.is_active = true;
    }
    sqlite3_finalize(stmt);
    return inc;
}

std::vector<AnalysisReport> EventTimeline::getRecentEvents(int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AnalysisReport> results;

    const char* sql = "SELECT timestamp, anomaly_count, pattern_count, "
                      "risk_total, explanation FROM analysis_events "
                      "ORDER BY timestamp DESC LIMIT ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return results;
    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AnalysisReport r;
        r.timestamp = sqlite3_column_int64(stmt, 0);
        // Note: we don't reconstruct full anomalies/patterns from DB here,
        // just the summary data for display purposes
        auto expl = sqlite3_column_text(stmt, 4);
        r.explanation = expl ? reinterpret_cast<const char*>(expl) : "";
        r.risk.total = sqlite3_column_double(stmt, 3);
        results.push_back(r);
    }
    sqlite3_finalize(stmt);
    return results;
}

} // namespace sysmon
