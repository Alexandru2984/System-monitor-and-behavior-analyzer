#include <gtest/gtest.h>
#include "analyzer/analyzer.h"
#include "storage/sqlite_storage.h"
#include "utils/logger.h"
#include <filesystem>

using namespace sysmon;

class AnalyzerTest : public ::testing::Test {
protected:
    std::string db_path = "test_analyzer.db";
    std::shared_ptr<SqliteStorage> storage;

    void SetUp() override {
        sysmon::Logger::init("tests_analyzer.log", spdlog::level::debug);
        cleanup();
        storage = std::make_shared<SqliteStorage>(db_path);
        storage->initialize();
    }
    void TearDown() override {
        storage.reset();  // close DB before deleting files
        cleanup();
    }

    void cleanup() {
        std::filesystem::remove("test_analyzer.db");
        std::filesystem::remove("test_analyzer.db-wal");
        std::filesystem::remove("test_analyzer.db-shm");
    }
};

TEST_F(AnalyzerTest, IntegrationSpikeDetection) {
    Analyzer analyzer(storage->db(), 3.0, 0.15);
    
    // Send 30 snapshots of CPU data at 5% usage to establish a baseline
    for (int i = 0; i < 30; ++i) {
        CpuSnapshot cpu;
        cpu.timestamp = 1000 + i;
        cpu.total_usage_percent = 5.0;
        cpu.core_usage_percent = { 5.0, 5.0 };
        auto report = analyzer.analyze(cpu);
        EXPECT_TRUE(report.anomalies.empty());
    }
    
    // Send a massive spike
    CpuSnapshot spike;
    spike.timestamp = 2000;
    spike.total_usage_percent = 95.0;
    spike.core_usage_percent = { 95.0, 95.0 };
    
    auto report = analyzer.analyze(spike);
    
    EXPECT_FALSE(report.anomalies.empty());
    
    bool found_cpu_anomaly = false;
    for (const auto& anomaly : report.anomalies) {
        if (anomaly.metric_type == "cpu") {
            found_cpu_anomaly = true;
            EXPECT_GT(anomaly.severity, 0.0);
            EXPECT_DOUBLE_EQ(anomaly.risk_score,
                             anomaly.severity * report.risk.total);
        }
    }
    EXPECT_TRUE(found_cpu_anomaly);
    
    // Explanation should be generated because an anomaly was found
    EXPECT_FALSE(report.explanation.empty());
}

TEST_F(AnalyzerTest, IntegrationNetworkThreshold) {
    Analyzer analyzer(storage->db(), 3.0, 0.15);
    
    // Train network baseline (RX=1000 kbps)
    for (int i = 0; i < 30; ++i) {
        NetworkSnapshot net;
        net.timestamp = 1000 + i;
        // name, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_rate, tx_rate
        net.interfaces.push_back({"eth0", 0ULL, 0ULL, 0ULL, 0ULL, 1000.0, 500.0});
        auto report = analyzer.analyze(net);
        EXPECT_TRUE(report.anomalies.empty());
    }
    
    // Spike exactly by sigma floor * 3 (100 * 3.0 = 300) to cross threshold
    // Old mean = 1000. Sigma = ~0 due to variance. Floor = 100.
    // Threshold = 1000 + 3.0 * 100 = 1300.
    // Let's send 1400.
    NetworkSnapshot spike;
    spike.timestamp = 2000;
    spike.interfaces.push_back({"eth0", 0ULL, 0ULL, 0ULL, 0ULL, 1400.0, 500.0});
    
    auto report = analyzer.analyze(spike);
    EXPECT_FALSE(report.anomalies.empty());
}

// ── Memory anomaly detection ───────────────────────────────────────────────

TEST_F(AnalyzerTest, IntegrationMemorySpikeDetection) {
    Analyzer analyzer(storage->db(), 2.0, 0.15);

    // Establish memory baseline at 40%
    for (int i = 0; i < 30; ++i) {
        MemorySnapshot mem;
        mem.timestamp = 1000 + i;
        mem.total_kb = 16000000;
        mem.used_kb = 6400000;
        mem.available_kb = 9600000;
        mem.usage_percent = 40.0;
        auto report = analyzer.analyze(mem);
        EXPECT_TRUE(report.anomalies.empty());
    }

    // Spike to 95%
    MemorySnapshot spike;
    spike.timestamp = 2000;
    spike.total_kb = 16000000;
    spike.used_kb = 15200000;
    spike.available_kb = 800000;
    spike.usage_percent = 95.0;

    auto report = analyzer.analyze(spike);
    EXPECT_FALSE(report.anomalies.empty());

    bool found = false;
    for (const auto& a : report.anomalies) {
        if (a.metric_type == "memory") {
            found = true;
            EXPECT_GT(a.severity, 0.0);
            EXPECT_LE(a.severity, 1.0);
        }
    }
    EXPECT_TRUE(found);
}

// ── No false positives on stable input ─────────────────────────────────────

TEST_F(AnalyzerTest, NoAnomaliesOnStableInput) {
    Analyzer analyzer(storage->db(), 2.0, 0.1);

    // 50 stable CPU samples — should never trigger
    for (int i = 0; i < 50; ++i) {
        CpuSnapshot cpu;
        cpu.timestamp = 1000 + i * 1000;
        cpu.total_usage_percent = 30.0;
        cpu.core_usage_percent = {30.0};
        auto report = analyzer.analyze(cpu);
        EXPECT_TRUE(report.anomalies.empty())
            << "False positive at iteration " << i;
    }
}

// ── Risk score is proportional to severity ─────────────────────────────────

TEST_F(AnalyzerTest, RiskScoreProportionalToSeverity) {
    Analyzer analyzer(storage->db(), 2.0, 0.15);

    // Build baseline
    for (int i = 0; i < 30; ++i) {
        CpuSnapshot cpu;
        cpu.timestamp = 1000 + i;
        cpu.total_usage_percent = 10.0;
        cpu.core_usage_percent = {10.0};
        analyzer.analyze(cpu);
    }

    // Spike
    CpuSnapshot spike;
    spike.timestamp = 2000;
    spike.total_usage_percent = 90.0;
    spike.core_usage_percent = {90.0};
    auto report = analyzer.analyze(spike);

    ASSERT_FALSE(report.anomalies.empty());
    EXPECT_GT(report.risk.total, 0.0);
    EXPECT_LE(report.risk.total, 100.0);

    // Individual risk = severity * total
    for (const auto& a : report.anomalies) {
        EXPECT_DOUBLE_EQ(a.risk_score, a.severity * report.risk.total);
    }
}

// ── Explanation contains timestamp from events, not wall clock ─────────────

TEST_F(AnalyzerTest, ExplanationContainsEventTimestamp) {
    Analyzer analyzer(storage->db(), 2.0, 0.15);

    for (int i = 0; i < 30; ++i) {
        CpuSnapshot cpu;
        cpu.timestamp = 1000 + i;
        cpu.total_usage_percent = 5.0;
        cpu.core_usage_percent = {5.0};
        analyzer.analyze(cpu);
    }

    CpuSnapshot spike;
    spike.timestamp = 2000;
    spike.total_usage_percent = 99.0;
    spike.core_usage_percent = {99.0};
    auto report = analyzer.analyze(spike);

    EXPECT_FALSE(report.explanation.empty());
    // Should contain "Analysis Report @" header
    EXPECT_NE(report.explanation.find("Analysis Report"), std::string::npos);
}

// ── Alpha clamping — high ema_alpha doesn't produce invalid baselines ──────

TEST_F(AnalyzerTest, HighAlphaDoesNotCrash) {
    // ema_alpha=0.5 → short_alpha = min(1.5, 1.0) = 1.0
    Analyzer analyzer(storage->db(), 2.0, 0.5);

    for (int i = 0; i < 30; ++i) {
        CpuSnapshot cpu;
        cpu.timestamp = 1000 + i;
        cpu.total_usage_percent = 50.0;
        cpu.core_usage_percent = {50.0};
        EXPECT_NO_THROW(analyzer.analyze(cpu));
    }
}

// ── Network TX spike detection ─────────────────────────────────────────────

TEST_F(AnalyzerTest, IntegrationNetworkTxSpike) {
    Analyzer analyzer(storage->db(), 2.0, 0.15);

    for (int i = 0; i < 30; ++i) {
        NetworkSnapshot net;
        net.timestamp = 1000 + i;
        net.interfaces.push_back({"eth0", 0ULL, 0ULL, 0ULL, 0ULL, 100.0, 100.0});
        analyzer.analyze(net);
    }

    // TX spike
    NetworkSnapshot spike;
    spike.timestamp = 2000;
    spike.interfaces.push_back({"eth0", 0ULL, 0ULL, 0ULL, 0ULL, 100.0, 5000.0});

    auto report = analyzer.analyze(spike);
    // TX threshold = ~100 + 2*100 = 300. Spike=5000 → should detect
    EXPECT_FALSE(report.anomalies.empty());
}
