// ─────────────────────────────────────────────────────────────────────────────
// tests/test_scheduler.cpp — Unit tests for Scheduler (start/stop lifecycle)
// ─────────────────────────────────────────────────────────────────────────────

#include "core/scheduler.h"
#include "storage/sqlite_storage.h"
#include "utils/logger.h"

#include <gtest/gtest.h>
#include <atomic>
#include <chrono>
#include <filesystem>

using namespace sysmon;

// ── Fake collector that counts invocations ─────────────────────────────────
class FakeCpuCollector : public ICollector {
public:
    std::atomic<int> call_count{0};

    MetricSnapshot collect() override {
        call_count++;
        CpuSnapshot snap;
        snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        snap.total_usage_percent = 10.0;
        snap.core_usage_percent = {10.0, 10.0};
        return snap;
    }

    std::string name() const override { return "FakeCpuCollector"; }
};

class FakeMemCollector : public ICollector {
public:
    std::atomic<int> call_count{0};

    MetricSnapshot collect() override {
        call_count++;
        MemorySnapshot snap;
        snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        snap.total_kb = 8000000;
        snap.used_kb = 4000000;
        snap.available_kb = 4000000;
        snap.usage_percent = 50.0;
        return snap;
    }

    std::string name() const override { return "FakeMemCollector"; }
};

class SchedulerTest : public ::testing::Test {
protected:
    std::string db_path = "/tmp/sysmon_scheduler_test.db";

    void SetUp() override {
        cleanup();
        static bool logger_init = false;
        if (!logger_init) {
            Logger::init("/tmp/sysmon_scheduler_test.log", spdlog::level::warn);
            logger_init = true;
        }
    }

    void TearDown() override {
        cleanup();
    }

    void cleanup() {
        std::filesystem::remove(db_path);
        std::filesystem::remove(db_path + "-wal");
        std::filesystem::remove(db_path + "-shm");
    }

    Config makeConfig() {
        Config cfg;
        cfg.db_path = db_path;
        cfg.retention_hours = 0;  // disable pruning thread in tests
        return cfg;
    }
};

TEST_F(SchedulerTest, StartAndStopCleanly) {
    auto storage = std::make_shared<SqliteStorage>(db_path);
    storage->initialize();

    auto collector = std::make_shared<FakeCpuCollector>();
    Scheduler scheduler(storage, makeConfig());
    scheduler.addCollector(collector, std::chrono::milliseconds(50));

    EXPECT_FALSE(scheduler.running());
    scheduler.start();
    EXPECT_TRUE(scheduler.running());

    // Let it run a few cycles
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    scheduler.stop();
    EXPECT_FALSE(scheduler.running());
    EXPECT_GT(collector->call_count.load(), 0);
}

TEST_F(SchedulerTest, CollectorIsInvokedRepeatedly) {
    auto storage = std::make_shared<SqliteStorage>(db_path);
    storage->initialize();

    auto collector = std::make_shared<FakeCpuCollector>();
    Scheduler scheduler(storage, makeConfig());
    scheduler.addCollector(collector, std::chrono::milliseconds(50));

    scheduler.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    scheduler.stop();

    // Should have been called multiple times
    EXPECT_GE(collector->call_count.load(), 3);
}

TEST_F(SchedulerTest, MultipleCollectorsRunConcurrently) {
    auto storage = std::make_shared<SqliteStorage>(db_path);
    storage->initialize();

    auto cpu_col = std::make_shared<FakeCpuCollector>();
    auto mem_col = std::make_shared<FakeMemCollector>();

    Scheduler scheduler(storage, makeConfig());
    scheduler.addCollector(cpu_col, std::chrono::milliseconds(50));
    scheduler.addCollector(mem_col, std::chrono::milliseconds(50));

    scheduler.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    scheduler.stop();

    EXPECT_GE(cpu_col->call_count.load(), 2);
    EXPECT_GE(mem_col->call_count.load(), 2);
}

TEST_F(SchedulerTest, DataIsStoredInDatabase) {
    auto storage = std::make_shared<SqliteStorage>(db_path);
    storage->initialize();

    auto collector = std::make_shared<FakeCpuCollector>();
    Scheduler scheduler(storage, makeConfig());
    scheduler.addCollector(collector, std::chrono::milliseconds(50));

    scheduler.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    scheduler.stop();

    // Verify data was actually stored
    auto results = storage->queryCpu(0, std::numeric_limits<int64_t>::max());
    EXPECT_GE(results.size(), 1u);
}

TEST_F(SchedulerTest, DoubleStartIsNoop) {
    auto storage = std::make_shared<SqliteStorage>(db_path);
    storage->initialize();

    Scheduler scheduler(storage, makeConfig());
    auto collector = std::make_shared<FakeCpuCollector>();
    scheduler.addCollector(collector, std::chrono::milliseconds(100));

    scheduler.start();
    scheduler.start();  // should be a no-op
    EXPECT_TRUE(scheduler.running());

    scheduler.stop();
    EXPECT_FALSE(scheduler.running());
}

TEST_F(SchedulerTest, DoubleStopIsNoop) {
    auto storage = std::make_shared<SqliteStorage>(db_path);
    storage->initialize();

    Scheduler scheduler(storage, makeConfig());
    auto collector = std::make_shared<FakeCpuCollector>();
    scheduler.addCollector(collector, std::chrono::milliseconds(100));

    scheduler.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    scheduler.stop();
    EXPECT_NO_THROW(scheduler.stop());  // should not crash
}
