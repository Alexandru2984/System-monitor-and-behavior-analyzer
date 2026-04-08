// ─────────────────────────────────────────────────────────────────────────────
// tests/test_baseline_calculator.cpp — Unit tests for BaselineCalculator
// ─────────────────────────────────────────────────────────────────────────────

#include "analysis/baseline_calculator.h"
#include <gtest/gtest.h>
#include <cmath>

namespace sysmon::test {

TEST(BaselineCalculatorTest, NotReadyInitially) {
    BaselineCalculator bc(0.1);
    EXPECT_FALSE(bc.ready());
    EXPECT_EQ(bc.count(), 0);
}

TEST(BaselineCalculatorTest, ReadyAfterFirstUpdate) {
    BaselineCalculator bc(0.1);
    bc.update(50.0);
    EXPECT_TRUE(bc.ready());
    EXPECT_EQ(bc.count(), 1);
}

TEST(BaselineCalculatorTest, FirstUpdateSetsMeanDirectly) {
    BaselineCalculator bc(0.1);
    bc.update(42.0);
    EXPECT_DOUBLE_EQ(bc.mean(), 42.0);
}

TEST(BaselineCalculatorTest, SigmaIsZeroAfterFirstUpdate) {
    BaselineCalculator bc(0.1);
    bc.update(50.0);
    EXPECT_DOUBLE_EQ(bc.sigma(), 0.0);
}

TEST(BaselineCalculatorTest, ConvergesToConstantInput) {
    // If we feed the same value repeatedly, the mean should converge to it
    BaselineCalculator bc(0.3);
    for (int i = 0; i < 100; ++i) {
        bc.update(75.0);
    }
    EXPECT_NEAR(bc.mean(), 75.0, 0.01);
    EXPECT_NEAR(bc.sigma(), 0.0, 0.01);
}

TEST(BaselineCalculatorTest, MeanTracksChangingInput) {
    BaselineCalculator bc(0.5);  // fast adaptation
    for (int i = 0; i < 20; ++i) bc.update(10.0);

    // Now shift input to 90 — mean should move toward 90
    for (int i = 0; i < 20; ++i) bc.update(90.0);

    EXPECT_GT(bc.mean(), 80.0);  // should be close to 90
}

TEST(BaselineCalculatorTest, SigmaIncreasesWithVariance) {
    BaselineCalculator bc(0.2);

    // Feed alternating values → variance should be non-zero
    for (int i = 0; i < 50; ++i) {
        bc.update(i % 2 == 0 ? 10.0 : 90.0);
    }

    EXPECT_GT(bc.sigma(), 10.0);
}

TEST(BaselineCalculatorTest, AlphaOneTracksExactly) {
    // Alpha = 1.0 → mean always equals the last value
    BaselineCalculator bc(1.0);
    bc.update(10.0);
    EXPECT_DOUBLE_EQ(bc.mean(), 10.0);
    bc.update(99.0);
    EXPECT_DOUBLE_EQ(bc.mean(), 99.0);
}

TEST(BaselineCalculatorTest, CountIncrements) {
    BaselineCalculator bc(0.1);
    for (int i = 0; i < 7; ++i) bc.update(1.0);
    EXPECT_EQ(bc.count(), 7);
}

} // namespace sysmon::test
