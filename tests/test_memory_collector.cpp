// ─────────────────────────────────────────────────────────────────────────────
// tests/test_memory_collector.cpp — Unit tests for MemoryCollector
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/memory_collector.h"
#include <gtest/gtest.h>

namespace sysmon::test {

class MemoryCollectorTest : public ::testing::Test {
protected:
    MemoryCollector collector;
};

TEST_F(MemoryCollectorTest, ReturnsCorrectVariantType) {
    auto snapshot = collector.collect();
    ASSERT_TRUE(std::holds_alternative<MemorySnapshot>(snapshot));
}

TEST_F(MemoryCollectorTest, HasValidTimestamp) {
    auto s = std::get<MemorySnapshot>(collector.collect());
    EXPECT_GT(s.timestamp, 0);
}

TEST_F(MemoryCollectorTest, TotalMemoryIsPositive) {
    auto s = std::get<MemorySnapshot>(collector.collect());
    EXPECT_GT(s.total_kb, 0u);
}

TEST_F(MemoryCollectorTest, UsedDoesNotExceedTotal) {
    auto s = std::get<MemorySnapshot>(collector.collect());
    EXPECT_LE(s.used_kb, s.total_kb);
}

TEST_F(MemoryCollectorTest, AvailableDoesNotExceedTotal) {
    auto s = std::get<MemorySnapshot>(collector.collect());
    EXPECT_LE(s.available_kb, s.total_kb);
}

TEST_F(MemoryCollectorTest, UsagePctInRange) {
    auto s = std::get<MemorySnapshot>(collector.collect());
    EXPECT_GE(s.usage_percent, 0.0);
    EXPECT_LE(s.usage_percent, 100.0);
}

TEST_F(MemoryCollectorTest, UsedPlusAvailableEqualsTotal) {
    auto s = std::get<MemorySnapshot>(collector.collect());
    EXPECT_EQ(s.used_kb + s.available_kb, s.total_kb);
}

} // namespace sysmon::test
