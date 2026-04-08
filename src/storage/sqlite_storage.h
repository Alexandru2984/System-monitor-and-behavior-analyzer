#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// storage/sqlite_storage.h — SQLite-based implementation of IStorageEngine
// ─────────────────────────────────────────────────────────────────────────────
//
// PERFORMANCE NOTES:
//   - WAL mode  → allows concurrent reads while writing
//   - Prepared statements → compiled once, reused per insert (avoids SQL parsing)
//   - Batch inserts → wrapped in a transaction per collection cycle
//   - PRAGMA synchronous=NORMAL → good balance between safety and speed
// ─────────────────────────────────────────────────────────────────────────────

#include "storage/storage_engine.h"
#include <sqlite3.h>
#include <string>
#include <mutex>

namespace sysmon {

class SqliteStorage : public IStorageEngine {
public:
    explicit SqliteStorage(const std::string& db_path);
    ~SqliteStorage() override;

    // Non-copyable, non-movable (owns a sqlite3* handle)
    SqliteStorage(const SqliteStorage&) = delete;
    SqliteStorage& operator=(const SqliteStorage&) = delete;

    void initialize() override;
    void store(const MetricSnapshot& snapshot) override;
    void storeAnomaly(const AnomalyEvent& event) override;

    std::vector<CpuSnapshot>     queryCpu(int64_t from, int64_t to) override;
    std::vector<MemorySnapshot>  queryMemory(int64_t from, int64_t to) override;
    std::vector<NetworkSnapshot> queryNetwork(int64_t from, int64_t to) override;

    /// Delete data older than `before` timestamp (epoch ms).
    void pruneOlderThan(int64_t before);

private:
    sqlite3* db_ = nullptr;
    std::string db_path_;
    std::mutex mutex_;   // serialize writes

    // Prepared statements (created once in initialize())
    sqlite3_stmt* stmt_insert_cpu_     = nullptr;
    sqlite3_stmt* stmt_insert_mem_     = nullptr;
    sqlite3_stmt* stmt_insert_net_     = nullptr;
    sqlite3_stmt* stmt_insert_proc_    = nullptr;
    sqlite3_stmt* stmt_insert_anomaly_ = nullptr;

    void exec(const char* sql);
    void prepareStatements();
    void storeCpu(const CpuSnapshot& s);
    void storeMemory(const MemorySnapshot& s);
    void storeProcess(const ProcessSnapshot& s);
    void storeNetwork(const NetworkSnapshot& s);
};

} // namespace sysmon
