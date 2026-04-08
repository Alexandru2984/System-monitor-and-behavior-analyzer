// ─────────────────────────────────────────────────────────────────────────────
// tests/test_anomaly_detector.cpp — Unit tests for AnomalyDetector
// ─────────────────────────────────────────────────────────────────────────────

#include "analysis/anomaly_detector.h"
#include "utils/logger.h"

#include <gtest/gtest.h>

namespace sysmon::test {

class AnomalyDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        static bool logger_init = false;
        if (!logger_init) {
            sysmon::Logger::init("/tmp/sysmon_test.log", spdlog::level::warn);
            logger_init = true;
        }
    }

    // Feed N "normal" samples to build baseline
    void warmUpCpu(AnomalyDetector& detector, int n, double normal_val) {
        for (int i = 0; i < n; ++i) {
            CpuSnapshot snap;
            snap.timestamp = static_cast<int64_t>(i) * 1000;
            snap.total_usage_percent = normal_val;
            detector.process(MetricSnapshot{snap});
        }
    }

    void warmUpMemory(AnomalyDetector& detector, int n, double normal_val) {
        for (int i = 0; i < n; ++i) {
            MemorySnapshot snap;
            snap.timestamp = static_cast<int64_t>(i) * 1000;
            snap.total_kb = 16000000;
            snap.usage_percent = normal_val;
            snap.used_kb = static_cast<uint64_t>(normal_val / 100.0 * 16000000);
            snap.available_kb = 16000000 - snap.used_kb;
            detector.process(MetricSnapshot{snap});
        }
    }
};

TEST_F(AnomalyDetectorTest, NoAnomalyOnNormalCpu) {
    AnomalyDetector detector(2.0, 0.1);
    warmUpCpu(detector, 20, 25.0);

    // Feed another normal value
    CpuSnapshot snap;
    snap.timestamp = 99000;
    snap.total_usage_percent = 26.0;  // slightly above baseline, within sigma
    auto events = detector.process(MetricSnapshot{snap});

    EXPECT_TRUE(events.empty());
}

TEST_F(AnomalyDetectorTest, DetectsCpuSpike) {
    AnomalyDetector detector(2.0, 0.1);
    warmUpCpu(detector, 30, 20.0);

    // Massive spike
    CpuSnapshot snap;
    snap.timestamp = 99000;
    snap.total_usage_percent = 95.0;
    auto events = detector.process(MetricSnapshot{snap});

    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events[0].metric_type, "cpu");
    EXPECT_GT(events[0].severity, 0.0);
}

TEST_F(AnomalyDetectorTest, NoAnomalyOnNormalMemory) {
    AnomalyDetector detector(2.0, 0.1);
    warmUpMemory(detector, 20, 60.0);

    MemorySnapshot snap;
    snap.timestamp = 99000;
    snap.total_kb = 16000000;
    snap.usage_percent = 61.0;
    snap.used_kb = 9760000;
    snap.available_kb = 6240000;
    auto events = detector.process(MetricSnapshot{snap});

    EXPECT_TRUE(events.empty());
}

TEST_F(AnomalyDetectorTest, DetectsMemorySpike) {
    AnomalyDetector detector(2.0, 0.1);
    warmUpMemory(detector, 30, 50.0);

    MemorySnapshot snap;
    snap.timestamp = 99000;
    snap.total_kb = 16000000;
    snap.usage_percent = 95.0;
    snap.used_kb = 15200000;
    snap.available_kb = 800000;
    auto events = detector.process(MetricSnapshot{snap});

    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events[0].metric_type, "memory");
}

TEST_F(AnomalyDetectorTest, SeverityIsBounded) {
    AnomalyDetector detector(2.0, 0.1);
    warmUpCpu(detector, 30, 20.0);

    CpuSnapshot snap;
    snap.timestamp = 99000;
    snap.total_usage_percent = 100.0;
    auto events = detector.process(MetricSnapshot{snap});

    ASSERT_FALSE(events.empty());
    EXPECT_GE(events[0].severity, 0.0);
    EXPECT_LE(events[0].severity, 1.0);
}

TEST_F(AnomalyDetectorTest, ProcessSnapshotReturnsEmpty) {
    AnomalyDetector detector(2.0, 0.1);
    ProcessSnapshot snap;
    snap.timestamp = 1000;
    auto events = detector.process(MetricSnapshot{snap});
    EXPECT_TRUE(events.empty());
}

} // namespace sysmon::test
