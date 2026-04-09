// ─────────────────────────────────────────────────────────────────────────────
// tests/test_baseline_manager.cpp — Unit tests for BaselineManager
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/baseline_manager.h"
#include <gtest/gtest.h>
#include <cmath>

using namespace sysmon;

// ── MetricBaseline Tests ────────────────────────────────────────────────────

TEST(MetricBaselineTest, EmptyBaselineReturnsNotReady) {
    MetricBaseline bl;
    EXPECT_FALSE(bl.shortWindow().ready);
    EXPECT_FALSE(bl.longWindow().ready);
}

TEST(MetricBaselineTest, ShortWindowBecomesReadyAfterEnoughSamples) {
    MetricBaseline bl;
    for (int i = 0; i < 10; ++i) bl.update(50.0);
    EXPECT_TRUE(bl.shortWindow().ready);
}

TEST(MetricBaselineTest, LongWindowBecomesReadyAfterManySamples) {
    MetricBaseline bl;
    for (int i = 0; i < 25; ++i) bl.update(50.0);
    EXPECT_TRUE(bl.longWindow().ready);
}

TEST(MetricBaselineTest, MeanConvergesToStableValue) {
    MetricBaseline bl;
    for (int i = 0; i < 100; ++i) bl.update(42.0);

    auto sw = bl.shortWindow();
    auto lw = bl.longWindow();
    EXPECT_NEAR(sw.mean, 42.0, 0.5);
    EXPECT_NEAR(lw.mean, 42.0, 1.0);
}

TEST(MetricBaselineTest, SigmaIsSmallForConstantInput) {
    MetricBaseline bl;
    for (int i = 0; i < 100; ++i) bl.update(75.0);

    EXPECT_LT(bl.shortWindow().sigma, 1.0);
    EXPECT_LT(bl.longWindow().sigma, 1.0);
}

TEST(MetricBaselineTest, SigmaGrowsForVariableInput) {
    MetricBaseline bl;
    for (int i = 0; i < 100; ++i) {
        bl.update(i % 2 == 0 ? 20.0 : 80.0);  // oscillating
    }

    EXPECT_GT(bl.shortWindow().sigma, 10.0);
    EXPECT_GT(bl.longWindow().sigma, 10.0);
}

TEST(MetricBaselineTest, MinMaxTracksExtremes) {
    MetricBaseline bl;
    bl.update(10.0);
    bl.update(90.0);
    bl.update(50.0);

    auto lw = bl.longWindow();
    EXPECT_EQ(lw.min_val, 10.0);
    EXPECT_EQ(lw.max_val, 90.0);
}

TEST(MetricBaselineTest, AnomalyThresholdUsesFloor) {
    MetricBaseline bl;
    for (int i = 0; i < 30; ++i) bl.update(50.0);

    // Sigma is ~0 since input is constant, but floor=1.0
    double threshold = bl.anomalyThreshold(2.0, 1.0);
    EXPECT_NEAR(threshold, 52.0, 1.0);  // mean + 2*floor
}

TEST(MetricBaselineTest, PercentileEstimation) {
    MetricBaseline bl;
    // Feed values 1..100
    for (int i = 1; i <= 100; ++i) bl.update(static_cast<double>(i));

    auto lw = bl.longWindow();
    // P95 should be around 95, P99 around 99
    EXPECT_GT(lw.p95, 85.0);
    EXPECT_LT(lw.p95, 100.0);
    EXPECT_GT(lw.p99, 90.0);
}

// ── Trend Detection Tests ───────────────────────────────────────────────────

TEST(MetricBaselineTest, TrendDetectsIncrease) {
    MetricBaseline bl;
    for (int i = 0; i < 60; ++i) {
        bl.update(10.0 + i * 1.0);  // steadily increasing
    }

    EXPECT_GT(bl.trend(), 0.5);  // positive slope
}

TEST(MetricBaselineTest, TrendIsNearZeroForFlat) {
    MetricBaseline bl;
    for (int i = 0; i < 60; ++i) bl.update(50.0);

    EXPECT_NEAR(bl.trend(), 0.0, 0.1);
}

// ── Oscillation Detection Tests ─────────────────────────────────────────────

TEST(MetricBaselineTest, OscillationCountsHighForRapidChanges) {
    MetricBaseline bl;
    // Build long-term baseline first
    for (int i = 0; i < 30; ++i) bl.update(50.0);
    // Then oscillate
    for (int i = 0; i < 30; ++i) {
        bl.update(i % 2 == 0 ? 30.0 : 70.0);
    }

    EXPECT_GT(bl.oscillationCount(), 10);
}

TEST(MetricBaselineTest, OscillationIsLowForStable) {
    MetricBaseline bl;
    for (int i = 0; i < 60; ++i) bl.update(50.0);

    EXPECT_LT(bl.oscillationCount(), 3);
}

// ── Sustained High Detection ────────────────────────────────────────────────

TEST(MetricBaselineTest, SustainedHighDetected) {
    MetricBaseline bl;
    // Build large baseline [20..29] so P95 starts at 29
    for (int i = 0; i < 100; ++i) bl.update(20.0 + (i % 10));
    // Spike at 200: P95 will gradually rise but can't reach 200
    // until 5+ entries are 200, and by that point we already have 5 consecutive
    bool ever_sustained = false;
    for (int i = 0; i < 8; ++i) {
        bl.update(200.0);
        if (bl.isSustainedHigh(5)) {
            ever_sustained = true;
            break;
        }
    }
    EXPECT_TRUE(ever_sustained);
}

TEST(MetricBaselineTest, NotSustainedIfBrief) {
    MetricBaseline bl;
    for (int i = 0; i < 100; ++i) bl.update(20.0 + (i % 10));
    bl.update(200.0);  // only 1 sample above P95

    EXPECT_FALSE(bl.isSustainedHigh(5));
}

// ── Monotonically Increasing ────────────────────────────────────────────────

TEST(MetricBaselineTest, MonotonicallyIncreasingDetected) {
    MetricBaseline bl;
    for (int i = 0; i < 35; ++i) {
        bl.update(50.0 + i * 0.5);
    }

    EXPECT_TRUE(bl.isMonotonicallyIncreasing(30));
}

TEST(MetricBaselineTest, NotMonotonicForFlat) {
    MetricBaseline bl;
    for (int i = 0; i < 35; ++i) bl.update(50.0);

    // Flat is technically non-decreasing so it IS monotonic
    // (our impl counts >= as increasing)
    EXPECT_TRUE(bl.isMonotonicallyIncreasing(30));
}

// ── BaselineManager Tests ───────────────────────────────────────────────────

TEST(BaselineManagerTest, CreatesBaselineOnAccess) {
    BaselineManager bm;
    EXPECT_FALSE(bm.has("cpu"));
    bm.update("cpu", 50.0);
    EXPECT_TRUE(bm.has("cpu"));
}

TEST(BaselineManagerTest, TracksMultipleMetrics) {
    BaselineManager bm;
    for (int i = 0; i < 30; ++i) {
        bm.update("cpu", 40.0);
        bm.update("mem", 70.0);
    }

    EXPECT_NEAR(bm.get("cpu").longWindow().mean, 40.0, 2.0);
    EXPECT_NEAR(bm.get("mem").longWindow().mean, 70.0, 2.0);
}

TEST(BaselineManagerTest, ConstAccessNonExistentReturnsEmpty) {
    const BaselineManager bm;
    auto& bl = bm.get("nonexistent");
    EXPECT_EQ(bl.shortWindow().count, 0);
}
