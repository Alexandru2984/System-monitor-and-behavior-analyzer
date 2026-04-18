// ─────────────────────────────────────────────────────────────────────────────
// storage/sqlite_storage.cpp — SQLite implementation
// ─────────────────────────────────────────────────────────────────────────────

#include "storage/sqlite_storage.h"
#include "utils/logger.h"

#include <stdexcept>

namespace sysmon {

SqliteStorage::SqliteStorage(const std::string& db_path)
    : db_path_(db_path) {}

SqliteStorage::~SqliteStorage() {
    // Finalize all prepared statements before closing the DB
    if (stmt_insert_cpu_)     sqlite3_finalize(stmt_insert_cpu_);
    if (stmt_insert_mem_)     sqlite3_finalize(stmt_insert_mem_);
    if (stmt_insert_net_)     sqlite3_finalize(stmt_insert_net_);
    if (stmt_insert_proc_)    sqlite3_finalize(stmt_insert_proc_);
    if (stmt_insert_anomaly_) sqlite3_finalize(stmt_insert_anomaly_);
    if (db_) sqlite3_close(db_);
}

void SqliteStorage::exec(const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQLite exec failed: " + msg);
    }
}

void SqliteStorage::initialize() {
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Cannot open SQLite DB: " + db_path_);
    }

    // ── Performance pragmas ────────────────────────────────────────────────
    // Busy timeout: wait up to 5s if another connection holds a lock
    // (EventTimeline opens its own connection to the same DB).
    sqlite3_busy_timeout(db_, 5000);

    // WAL mode: lets readers proceed while a writer is active (huge win for
    // our use case where collection writes while analysis reads).
    exec("PRAGMA journal_mode=WAL;");
    // NORMAL sync: fsync on commits but not on every page write.
    // Acceptable tradeoff — we lose at most the last transaction on a
    // power failure, which for metrics is fine.
    exec("PRAGMA synchronous=NORMAL;");

    // ── Create tables ──────────────────────────────────────────────────────
    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS cpu_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            core_id     INTEGER NOT NULL,
            usage_pct   REAL    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cpu_ts ON cpu_metrics(timestamp);
    )SQL");

    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS memory_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            total_kb    INTEGER NOT NULL,
            used_kb     INTEGER NOT NULL,
            avail_kb    INTEGER NOT NULL,
            usage_pct   REAL    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_mem_ts ON memory_metrics(timestamp);
    )SQL");

    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS network_metrics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            interface   TEXT    NOT NULL,
            rx_bytes    INTEGER NOT NULL,
            tx_bytes    INTEGER NOT NULL,
            rx_rate_kbps REAL   NOT NULL,
            tx_rate_kbps REAL   NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_net_ts ON network_metrics(timestamp);
    )SQL");

    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS process_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            pid         INTEGER NOT NULL,
            name        TEXT    NOT NULL,
            state       TEXT,
            user        TEXT,
            cpu_pct     REAL,
            mem_pct     REAL
        );
        CREATE INDEX IF NOT EXISTS idx_proc_ts ON process_snapshots(timestamp);
    )SQL");

    exec(R"SQL(
        CREATE TABLE IF NOT EXISTS anomalies (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER NOT NULL,
            metric_type TEXT    NOT NULL,
            description TEXT    NOT NULL,
            severity    REAL    NOT NULL,
            risk_score  REAL    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_anom_ts ON anomalies(timestamp);
    )SQL");

    prepareStatements();
    LOG_INFO("SQLite storage initialized: {}", db_path_);
}

void SqliteStorage::prepareStatements() {
    auto prepare = [&](const char* sql, sqlite3_stmt** stmt) {
        if (sqlite3_prepare_v2(db_, sql, -1, stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error(
                std::string("Failed to prepare statement: ") + sqlite3_errmsg(db_));
        }
    };

    prepare("INSERT INTO cpu_metrics (timestamp, core_id, usage_pct) VALUES (?,?,?);",
            &stmt_insert_cpu_);
    prepare("INSERT INTO memory_metrics (timestamp, total_kb, used_kb, avail_kb, usage_pct) VALUES (?,?,?,?,?);",
            &stmt_insert_mem_);
    prepare("INSERT INTO network_metrics (timestamp, interface, rx_bytes, tx_bytes, rx_rate_kbps, tx_rate_kbps) VALUES (?,?,?,?,?,?);",
            &stmt_insert_net_);
    prepare("INSERT INTO process_snapshots (timestamp, pid, name, state, user, cpu_pct, mem_pct) VALUES (?,?,?,?,?,?,?);",
            &stmt_insert_proc_);
    prepare("INSERT INTO anomalies (timestamp, metric_type, description, severity, risk_score) VALUES (?,?,?,?,?);",
            &stmt_insert_anomaly_);
}

// ── Store dispatch ─────────────────────────────────────────────────────────

void SqliteStorage::store(const MetricSnapshot& snapshot) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Wrap in a transaction → all inserts from one snapshot are atomic
    // and much faster (SQLite would otherwise commit per-INSERT).
    //
    // If BEGIN itself fails, there's no active transaction to roll back,
    // so we let exec() throw directly without entering the try block.
    exec("BEGIN TRANSACTION;");
    bool committed = false;
    try {
        std::visit([this](const auto& s) {
            using T = std::decay_t<decltype(s)>;
            if constexpr (std::is_same_v<T, CpuSnapshot>)
                storeCpu(s);
            else if constexpr (std::is_same_v<T, MemorySnapshot>)
                storeMemory(s);
            else if constexpr (std::is_same_v<T, ProcessSnapshot>)
                storeProcess(s);
            else if constexpr (std::is_same_v<T, NetworkSnapshot>)
                storeNetwork(s);
        }, snapshot);
        exec("COMMIT;");
        committed = true;
    } catch (...) {
        if (!committed) {
            // Only rollback if we have an active transaction
            try { exec("ROLLBACK;"); } catch (...) {}
        }
        throw;
    }
}

void SqliteStorage::storeCpu(const CpuSnapshot& s) {
    // Insert aggregate (core_id = -1)
    sqlite3_bind_int64(stmt_insert_cpu_, 1, s.timestamp);
    sqlite3_bind_int(stmt_insert_cpu_, 2, -1);
    sqlite3_bind_double(stmt_insert_cpu_, 3, s.total_usage_percent);
    int rc = sqlite3_step(stmt_insert_cpu_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert CPU aggregate: {}", sqlite3_errmsg(db_));
    }
    sqlite3_reset(stmt_insert_cpu_);

    // Insert per-core
    for (size_t i = 0; i < s.core_usage_percent.size(); ++i) {
        sqlite3_bind_int64(stmt_insert_cpu_, 1, s.timestamp);
        sqlite3_bind_int(stmt_insert_cpu_, 2, static_cast<int>(i));
        sqlite3_bind_double(stmt_insert_cpu_, 3, s.core_usage_percent[i]);
        rc = sqlite3_step(stmt_insert_cpu_);
        if (rc != SQLITE_DONE) {
            LOG_ERROR("Failed to insert CPU core {}: {}", i, sqlite3_errmsg(db_));
        }
        sqlite3_reset(stmt_insert_cpu_);
    }
}

void SqliteStorage::storeMemory(const MemorySnapshot& s) {
    sqlite3_bind_int64(stmt_insert_mem_, 1, s.timestamp);
    sqlite3_bind_int64(stmt_insert_mem_, 2, static_cast<int64_t>(s.total_kb));
    sqlite3_bind_int64(stmt_insert_mem_, 3, static_cast<int64_t>(s.used_kb));
    sqlite3_bind_int64(stmt_insert_mem_, 4, static_cast<int64_t>(s.available_kb));
    sqlite3_bind_double(stmt_insert_mem_, 5, s.usage_percent);
    int rc = sqlite3_step(stmt_insert_mem_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert memory metric: {}", sqlite3_errmsg(db_));
    }
    sqlite3_reset(stmt_insert_mem_);
}

void SqliteStorage::storeProcess(const ProcessSnapshot& s) {
    for (const auto& p : s.processes) {
        sqlite3_bind_int64(stmt_insert_proc_, 1, s.timestamp);
        sqlite3_bind_int(stmt_insert_proc_, 2, p.pid);
        sqlite3_bind_text(stmt_insert_proc_, 3, p.name.c_str(),
                          static_cast<int>(p.name.size()), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_insert_proc_, 4, p.state.c_str(),
                          static_cast<int>(p.state.size()), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt_insert_proc_, 5, p.user.c_str(),
                          static_cast<int>(p.user.size()), SQLITE_TRANSIENT);
        sqlite3_bind_double(stmt_insert_proc_, 6, p.cpu_percent);
        sqlite3_bind_double(stmt_insert_proc_, 7, p.mem_percent);
        int rc = sqlite3_step(stmt_insert_proc_);
        if (rc != SQLITE_DONE) {
            LOG_ERROR("Failed to insert process {}: {}", p.pid, sqlite3_errmsg(db_));
        }
        sqlite3_reset(stmt_insert_proc_);
    }
}

void SqliteStorage::storeNetwork(const NetworkSnapshot& s) {
    for (const auto& iface : s.interfaces) {
        sqlite3_bind_int64(stmt_insert_net_, 1, s.timestamp);
        sqlite3_bind_text(stmt_insert_net_, 2, iface.name.c_str(),
                          static_cast<int>(iface.name.size()), SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_insert_net_, 3, static_cast<int64_t>(iface.rx_bytes));
        sqlite3_bind_int64(stmt_insert_net_, 4, static_cast<int64_t>(iface.tx_bytes));
        sqlite3_bind_double(stmt_insert_net_, 5, iface.rx_rate_kbps);
        sqlite3_bind_double(stmt_insert_net_, 6, iface.tx_rate_kbps);
        int rc = sqlite3_step(stmt_insert_net_);
        if (rc != SQLITE_DONE) {
            LOG_ERROR("Failed to insert network {}: {}", iface.name, sqlite3_errmsg(db_));
        }
        sqlite3_reset(stmt_insert_net_);
    }
}

void SqliteStorage::storeAnomaly(const AnomalyEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    sqlite3_bind_int64(stmt_insert_anomaly_, 1, event.timestamp);
    sqlite3_bind_text(stmt_insert_anomaly_, 2, event.metric_type.c_str(),
                      static_cast<int>(event.metric_type.size()), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_anomaly_, 3, event.description.c_str(),
                      static_cast<int>(event.description.size()), SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt_insert_anomaly_, 4, event.severity);
    sqlite3_bind_double(stmt_insert_anomaly_, 5, event.risk_score);
    int rc = sqlite3_step(stmt_insert_anomaly_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert anomaly: {}", sqlite3_errmsg(db_));
    }
    sqlite3_reset(stmt_insert_anomaly_);
}

// ── Query methods ──────────────────────────────────────────────────────────

std::vector<CpuSnapshot> SqliteStorage::queryCpu(int64_t from, int64_t to) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CpuSnapshot> results;

    // Query aggregate rows only (core_id = -1) for simplicity
    const char* sql = "SELECT timestamp, usage_pct FROM cpu_metrics "
                      "WHERE core_id = -1 AND timestamp BETWEEN ? AND ? "
                      "ORDER BY timestamp;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return results;
    sqlite3_bind_int64(stmt, 1, from);
    sqlite3_bind_int64(stmt, 2, to);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CpuSnapshot s;
        s.timestamp = sqlite3_column_int64(stmt, 0);
        s.total_usage_percent = sqlite3_column_double(stmt, 1);
        results.push_back(s);
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<MemorySnapshot> SqliteStorage::queryMemory(int64_t from, int64_t to) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MemorySnapshot> results;

    const char* sql = "SELECT timestamp, total_kb, used_kb, avail_kb, usage_pct "
                      "FROM memory_metrics WHERE timestamp BETWEEN ? AND ? "
                      "ORDER BY timestamp;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return results;
    sqlite3_bind_int64(stmt, 1, from);
    sqlite3_bind_int64(stmt, 2, to);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        MemorySnapshot s;
        s.timestamp    = sqlite3_column_int64(stmt, 0);
        s.total_kb     = static_cast<uint64_t>(sqlite3_column_int64(stmt, 1));
        s.used_kb      = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
        s.available_kb = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
        s.usage_percent = sqlite3_column_double(stmt, 4);
        results.push_back(s);
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<NetworkSnapshot> SqliteStorage::queryNetwork(int64_t from, int64_t to) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NetworkSnapshot> results;

    const char* sql = "SELECT timestamp, interface, rx_bytes, tx_bytes, "
                      "rx_rate_kbps, tx_rate_kbps FROM network_metrics "
                      "WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return results;
    sqlite3_bind_int64(stmt, 1, from);
    sqlite3_bind_int64(stmt, 2, to);

    // Group rows by timestamp into snapshots
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t ts = sqlite3_column_int64(stmt, 0);
        InterfaceStats iface;
        auto name_txt = sqlite3_column_text(stmt, 1);
        iface.name = name_txt ? reinterpret_cast<const char*>(name_txt) : "";
        iface.rx_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 2));
        iface.tx_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 3));
        iface.rx_rate_kbps = sqlite3_column_double(stmt, 4);
        iface.tx_rate_kbps = sqlite3_column_double(stmt, 5);

        if (results.empty() || results.back().timestamp != ts) {
            results.push_back(NetworkSnapshot{.timestamp = ts, .interfaces = {}});
        }
        results.back().interfaces.push_back(iface);
    }
    sqlite3_finalize(stmt);
    return results;
}

void SqliteStorage::pruneOlderThan(int64_t before) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string sql;
    for (const char* table : {"cpu_metrics", "memory_metrics",
                              "network_metrics", "process_snapshots",
                              "anomalies"}) {
        sql = "DELETE FROM " + std::string(table) +
              " WHERE timestamp < " + std::to_string(before) + ";";
        exec(sql.c_str());
    }
    LOG_INFO("Pruned data older than timestamp {}", before);
}

} // namespace sysmon
