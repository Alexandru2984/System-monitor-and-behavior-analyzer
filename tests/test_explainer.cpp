// ─────────────────────────────────────────────────────────────────────────────
// tests/test_explainer.cpp — Unit tests for Explainer
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/explainer.h"
#include "analyzer/baseline_manager.h"
#include "core/types.h"
#include <gtest/gtest.h>

using namespace sysmon;

class ExplainerTest : public ::testing::Test {
protected:
    Explainer explainer;
    BaselineManager baselines;

    void SetUp() override {
        // Build a CPU baseline
        for (int i = 0; i < 30; ++i) {
            baselines.update("cpu_total", 40.0);
        }
    }
};

TEST_F(ExplainerTest, ReturnsEmptyForNoEvents) {
    CpuSnapshot snap{.timestamp = 1000, .core_usage_percent = {40.0},
                     .total_usage_percent = 40.0};
    MetricSnapshot ms = snap;

    auto result = explainer.explain({}, {}, ms, baselines);
    EXPECT_TRUE(result.empty());
}

TEST_F(ExplainerTest, ContainsAnomalyDescription) {
    std::vector<AnomalyEvent> anomalies = {{
        {1000, "cpu", "CPU spike: 95.0%"}, 0.8, 30.0
    }};
    CpuSnapshot snap{.timestamp = 1000, .core_usage_percent = {95.0},
                     .total_usage_percent = 95.0};
    MetricSnapshot ms = snap;

    auto result = explainer.explain(anomalies, {}, ms, baselines);

    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("CPU spike"), std::string::npos);
    EXPECT_NE(result.find("Analysis Report"), std::string::npos);
}

TEST_F(ExplainerTest, ContainsSeverityLabel) {
    std::vector<AnomalyEvent> anomalies = {{
        {1000, "cpu", "spike"}, 0.9, 50.0
    }};
    CpuSnapshot snap{.timestamp = 1000, .core_usage_percent = {95.0},
                     .total_usage_percent = 95.0};
    MetricSnapshot ms = snap;

    auto result = explainer.explain(anomalies, {}, ms, baselines);
    EXPECT_NE(result.find("CRITICAL"), std::string::npos);
}

TEST_F(ExplainerTest, ContainsBaselineContext) {
    // Build baseline with some variance so sigma > 0
    BaselineManager bm2;
    for (int i = 0; i < 40; ++i) {
        bm2.update("cpu_total", 40.0 + (i % 5));
    }

    std::vector<AnomalyEvent> anomalies = {{
        {1000, "cpu", "spike"}, 0.5, 20.0
    }};
    CpuSnapshot snap{.timestamp = 1000, .core_usage_percent = {90.0},
                     .total_usage_percent = 90.0};
    MetricSnapshot ms = snap;

    auto result = explainer.explain(anomalies, {}, ms, bm2);

    // Should contain deviation sigma info
    EXPECT_NE(result.find("Deviation"), std::string::npos);
}

TEST_F(ExplainerTest, ContainsPatternInfo) {
    std::vector<PatternEvent> patterns = {{
        {1000, "cpu", "sustained above P95"},
        PatternType::SustainedHighLoad, 0.9
    }};
    CpuSnapshot snap{.timestamp = 1000, .core_usage_percent = {90.0},
                     .total_usage_percent = 90.0};
    MetricSnapshot ms = snap;

    auto result = explainer.explain({}, patterns, ms, baselines);

    EXPECT_NE(result.find("Patterns Detected"), std::string::npos);
    EXPECT_NE(result.find("SUSTAINED"), std::string::npos);
}

TEST_F(ExplainerTest, ShowsTopProcessConsumers) {
    ProcessSnapshot snap{.timestamp = 1000, .processes = {
        {.pid = 1, .name = "idle", .state = "S", .user = "root",
         .cpu_percent = 0.1, .mem_percent = 0.1},
        {.pid = 100, .name = "ffmpeg", .state = "R", .user = "micu",
         .cpu_percent = 75.0, .mem_percent = 5.0},
        {.pid = 200, .name = "chrome", .state = "S", .user = "micu",
         .cpu_percent = 15.0, .mem_percent = 20.0}
    }};
    MetricSnapshot ms = snap;

    std::vector<PatternEvent> patterns = {{
        {1000, "process", "new proc"},
        PatternType::NewProcess, 0.6
    }};

    auto result = explainer.explain({}, patterns, ms, baselines);

    EXPECT_NE(result.find("ffmpeg"), std::string::npos);
    EXPECT_NE(result.find("Top CPU"), std::string::npos);
}

TEST_F(ExplainerTest, ConfidenceBarRendered) {
    std::vector<PatternEvent> patterns = {{
        {1000, "cpu", "trending"},
        PatternType::Trend, 0.7
    }};
    CpuSnapshot snap{.timestamp = 1000, .core_usage_percent = {50.0},
                     .total_usage_percent = 50.0};
    MetricSnapshot ms = snap;

    auto result = explainer.explain({}, patterns, ms, baselines);

    // Should contain confidence percentage
    EXPECT_NE(result.find("70%"), std::string::npos);
}
