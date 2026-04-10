// ─────────────────────────────────────────────────────────────────────────────
// tests/test_sqlite_storage.cpp — Unit tests for SqliteStorage
// ─────────────────────────────────────────────────────────────────────────────

#include "storage/sqlite_storage.h"
#include "utils/logger.h"

#include <gtest/gtest.h>
#include <filesystem>

namespace sysmon::test {

class SqliteStorageTest : public ::testing::Test {
protected:
    std::string db_path = "/tmp/sysmon_test.db";

    void SetUp() override {
        // Clean up from any previous test run
        std::filesystem::remove(db_path);
        std::filesystem::remove(db_path + "-wal");
        std::filesystem::remove(db_path + "-shm");

        // Init logger if needed
        static bool logger_init = false;
        if (!logger_init) {
            Logger::init("/tmp/sysmon_test.log", spdlog::level::warn);
            logger_init = true;
        }
    }

    void TearDown() override {
        std::filesystem::remove(db_path);
        std::filesystem::remove(db_path + "-wal");
        std::filesystem::remove(db_path + "-shm");
    }
};

TEST_F(SqliteStorageTest, InitializesWithoutError) {
    SqliteStorage storage(db_path);
    EXPECT_NO_THROW(storage.initialize());
}

TEST_F(SqliteStorageTest, CpuStoreAndQueryRoundTrip) {
    SqliteStorage storage(db_path);
    storage.initialize();

    CpuSnapshot snap;
    snap.timestamp = 1000;
    snap.total_usage_percent = 42.5;
    snap.core_usage_percent = {30.0, 50.0, 40.0, 45.0};

    storage.store(MetricSnapshot{snap});

    auto results = storage.queryCpu(0, 2000);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].timestamp, 1000);
    EXPECT_DOUBLE_EQ(results[0].total_usage_percent, 42.5);
}

TEST_F(SqliteStorageTest, MemoryStoreAndQueryRoundTrip) {
    SqliteStorage storage(db_path);
    storage.initialize();

    MemorySnapshot snap;
    snap.timestamp = 2000;
    snap.total_kb = 16000000;
    snap.used_kb = 8000000;
    snap.available_kb = 8000000;
    snap.usage_percent = 50.0;

    storage.store(MetricSnapshot{snap});

    auto results = storage.queryMemory(0, 3000);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].timestamp, 2000);
    EXPECT_EQ(results[0].total_kb, 16000000u);
    EXPECT_EQ(results[0].used_kb, 8000000u);
    EXPECT_DOUBLE_EQ(results[0].usage_percent, 50.0);
}

TEST_F(SqliteStorageTest, NetworkStoreAndQueryRoundTrip) {
    SqliteStorage storage(db_path);
    storage.initialize();

    NetworkSnapshot snap;
    snap.timestamp = 3000;
    snap.interfaces.push_back(InterfaceStats{
        .name = "eth0",
        .rx_bytes = 1000000,
        .tx_bytes = 500000,
        .rx_packets = 1000,
        .tx_packets = 500,
        .rx_rate_kbps = 800.0,
        .tx_rate_kbps = 400.0
    });

    storage.store(MetricSnapshot{snap});

    auto results = storage.queryNetwork(0, 4000);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].interfaces.size(), 1u);
    EXPECT_EQ(results[0].interfaces[0].name, "eth0");
    EXPECT_DOUBLE_EQ(results[0].interfaces[0].rx_rate_kbps, 800.0);
}

TEST_F(SqliteStorageTest, AnomalyStorage) {
    SqliteStorage storage(db_path);
    storage.initialize();

    AnomalyEvent event{
        {5000, "cpu", "CPU spike: 95.0%"},
        0.8, 24.0
    };

    EXPECT_NO_THROW(storage.storeAnomaly(event));
}

TEST_F(SqliteStorageTest, QueryRangeFiltersCorrectly) {
    SqliteStorage storage(db_path);
    storage.initialize();

    // Insert 3 snapshots at different timestamps
    for (int64_t ts : {1000, 2000, 3000}) {
        CpuSnapshot snap;
        snap.timestamp = ts;
        snap.total_usage_percent = static_cast<double>(ts) / 100.0;
        storage.store(MetricSnapshot{snap});
    }

    // Query only middle range
    auto results = storage.queryCpu(1500, 2500);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].timestamp, 2000);
}

TEST_F(SqliteStorageTest, PruneDeletesOldData) {
    SqliteStorage storage(db_path);
    storage.initialize();

    for (int64_t ts : {1000, 2000, 3000}) {
        MemorySnapshot snap;
        snap.timestamp = ts;
        snap.total_kb = 16000000;
        snap.used_kb = 8000000;
        snap.available_kb = 8000000;
        snap.usage_percent = 50.0;
        storage.store(MetricSnapshot{snap});
    }

    storage.pruneOlderThan(2500);

    auto results = storage.queryMemory(0, 9000);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].timestamp, 3000);
}

} // namespace sysmon::test
