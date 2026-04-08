// ─────────────────────────────────────────────────────────────────────────────
// tests/test_cpu_collector.cpp — Unit tests for CpuCollector
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/cpu_collector.h"
#include <gtest/gtest.h>
#include <thread>

namespace sysmon::test {

class CpuCollectorTest : public ::testing::Test {
protected:
    CpuCollector collector;
};

TEST_F(CpuCollectorTest, ReturnsCorrectVariantType) {
    auto snapshot = collector.collect();
    ASSERT_TRUE(std::holds_alternative<CpuSnapshot>(snapshot));
}

TEST_F(CpuCollectorTest, HasValidTimestamp) {
    auto snapshot = std::get<CpuSnapshot>(collector.collect());
    EXPECT_GT(snapshot.timestamp, 0);
}

TEST_F(CpuCollectorTest, TotalUsageInRange) {
    auto snapshot = std::get<CpuSnapshot>(collector.collect());
    EXPECT_GE(snapshot.total_usage_percent, 0.0);
    EXPECT_LE(snapshot.total_usage_percent, 100.0);
}

TEST_F(CpuCollectorTest, PerCoreUsageInRange) {
    auto snapshot = std::get<CpuSnapshot>(collector.collect());
    EXPECT_GT(snapshot.core_usage_percent.size(), 0u);

    for (size_t i = 0; i < snapshot.core_usage_percent.size(); ++i) {
        EXPECT_GE(snapshot.core_usage_percent[i], 0.0)
            << "Core " << i << " usage below 0";
        EXPECT_LE(snapshot.core_usage_percent[i], 100.0)
            << "Core " << i << " usage above 100";
    }
}

TEST_F(CpuCollectorTest, DetectsCorrectCoreCount) {
    auto snapshot = std::get<CpuSnapshot>(collector.collect());
    unsigned int hw_cores = std::thread::hardware_concurrency();
    if (hw_cores > 0) {
        EXPECT_EQ(snapshot.core_usage_percent.size(),
                  static_cast<size_t>(hw_cores));
    }
}

TEST_F(CpuCollectorTest, NameIsCorrect) {
    EXPECT_EQ(collector.name(), "CpuCollector");
}

} // namespace sysmon::test
