#include <gtest/gtest.h>
#include "analyzer/analyzer.h"
#include "utils/logger.h"
#include <filesystem>

using namespace sysmon;

class AnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override {
        sysmon::Logger::init("tests_analyzer.log", spdlog::level::debug);
        cleanup();
    }
    void TearDown() override {
        cleanup();
    }

    void cleanup() {
        std::filesystem::remove("test_analyzer.db");
        std::filesystem::remove("test_analyzer.db-wal");
        std::filesystem::remove("test_analyzer.db-shm");
    }
};

TEST_F(AnalyzerTest, IntegrationSpikeDetection) {
    Analyzer analyzer("test_analyzer.db", 3.0, 0.15);
    
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
            EXPECT_EQ(anomaly.risk_score, report.risk.total);
        }
    }
    EXPECT_TRUE(found_cpu_anomaly);
    
    // Explanation should be generated because an anomaly was found
    EXPECT_FALSE(report.explanation.empty());
}

TEST_F(AnalyzerTest, IntegrationNetworkThreshold) {
    Analyzer analyzer("test_analyzer.db", 3.0, 0.15);
    
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
