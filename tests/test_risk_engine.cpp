// ─────────────────────────────────────────────────────────────────────────────
// tests/test_risk_engine.cpp — Unit tests for RiskEngine
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/risk_engine.h"
#include "core/types.h"
#include <gtest/gtest.h>

using namespace sysmon;

TEST(RiskEngineTest, ZeroRiskWithNoAnomalies) {
    RiskEngine engine;
    std::vector<AnomalyEvent> anomalies;
    std::vector<PatternEvent> patterns;

    auto risk = engine.evaluate(anomalies, patterns, 1000);
    EXPECT_DOUBLE_EQ(risk.total, 0.0);
}

TEST(RiskEngineTest, SeverityScalesWithAnomaly) {
    RiskEngine engine;
    std::vector<AnomalyEvent> anomalies = {{
        .timestamp = 1000,
        .metric_type = "cpu",
        .description = "CPU spike",
        .severity = 0.8,
        .risk_score = 0.0
    }};
    std::vector<PatternEvent> patterns;

    auto risk = engine.evaluate(anomalies, patterns, 1000);
    EXPECT_GT(risk.severity_score, 50.0);
    EXPECT_GT(risk.total, 0.0);
}

TEST(RiskEngineTest, HighSeverityGivesHighRisk) {
    RiskEngine engine;
    std::vector<AnomalyEvent> anomalies = {{
        .timestamp = 1000,
        .metric_type = "cpu",
        .description = "spike",
        .severity = 1.0,
        .risk_score = 0.0
    }};

    auto risk = engine.evaluate(anomalies, {}, 1000);
    // severity=1.0 → severity_score=100, contribution = 100*0.3 = 30
    EXPECT_GE(risk.total, 25.0);
}

TEST(RiskEngineTest, BreadthIncreasesSWithMultipleMetrics) {
    RiskEngine engine;

    // First call: single metric
    std::vector<AnomalyEvent> single = {{
        .timestamp = 1000, .metric_type = "cpu",
        .description = "spike", .severity = 0.5, .risk_score = 0.0
    }};
    auto risk1 = engine.evaluate(single, {}, 1000);

    // Second call: two metrics simultaneously (reset engine)
    RiskEngine engine2;
    std::vector<AnomalyEvent> multi = {
        {.timestamp = 1000, .metric_type = "cpu",
         .description = "spike", .severity = 0.5, .risk_score = 0.0},
        {.timestamp = 1000, .metric_type = "memory",
         .description = "pressure", .severity = 0.5, .risk_score = 0.0}
    };
    auto risk2 = engine2.evaluate(multi, {}, 1000);

    // breadth_score should be higher with 2 metrics
    EXPECT_GT(risk2.breadth_score, risk1.breadth_score);
}

TEST(RiskEngineTest, PersistenceGrowsWithRepeatedAnomalies) {
    RiskEngine engine;
    std::vector<PatternEvent> patterns;

    // Feed anomalies over 30 "seconds"
    for (int i = 0; i < 30; ++i) {
        std::vector<AnomalyEvent> anomalies = {{
            .timestamp = static_cast<int64_t>(i * 1000),
            .metric_type = "cpu",
            .description = "spike",
            .severity = 0.5,
            .risk_score = 0.0
        }};
        engine.evaluate(anomalies, patterns, i * 1000);
    }

    // Last evaluation should show high persistence
    std::vector<AnomalyEvent> last = {{
        .timestamp = 30000, .metric_type = "cpu",
        .description = "spike", .severity = 0.5, .risk_score = 0.0
    }};
    auto risk = engine.evaluate(last, patterns, 30000);
    EXPECT_GT(risk.persistence_score, 30.0);
}

TEST(RiskEngineTest, FamiliarityReducesRiskOverTime) {
    RiskEngine engine;

    // First anomaly: completely new → high familiarity_score (unfamiliar)
    std::vector<AnomalyEvent> first = {{
        .timestamp = 1000, .metric_type = "cpu",
        .description = "spike", .severity = 0.5, .risk_score = 0.0
    }};
    auto risk1 = engine.evaluate(first, {}, 1000);

    // Feed many similar anomalies
    for (int i = 2; i < 25; ++i) {
        std::vector<AnomalyEvent> a = {{
            .timestamp = static_cast<int64_t>(i * 1000),
            .metric_type = "cpu",
            .description = "spike",
            .severity = 0.5,
            .risk_score = 0.0
        }};
        engine.evaluate(a, {}, i * 1000);
    }

    // Now same anomaly should be "familiar" → lower familiarity_score
    std::vector<AnomalyEvent> last = {{
        .timestamp = 25000, .metric_type = "cpu",
        .description = "spike", .severity = 0.5, .risk_score = 0.0
    }};
    auto risk2 = engine.evaluate(last, {}, 25000);
    EXPECT_LT(risk2.familiarity_score, risk1.familiarity_score);
}

TEST(RiskEngineTest, RecencyHighForVeryRecentAnomaly) {
    RiskEngine engine;
    std::vector<AnomalyEvent> anomalies = {{
        .timestamp = 10000, .metric_type = "cpu",
        .description = "spike", .severity = 0.5, .risk_score = 0.0
    }};

    // current_time = anomaly time + 1s → very recent
    auto risk = engine.evaluate(anomalies, {}, 11000);
    EXPECT_GE(risk.recency_score, 80.0);
}

TEST(RiskEngineTest, TotalRiskCappedAt100) {
    RiskEngine engine;

    // Feed extreme anomalies repeatedly
    for (int i = 0; i < 60; ++i) {
        std::vector<AnomalyEvent> a = {{
            .timestamp = static_cast<int64_t>(i * 1000),
            .metric_type = "cpu",
            .description = "extreme",
            .severity = 1.0,
            .risk_score = 0.0
        }};
        engine.evaluate(a, {}, i * 1000);
    }

    std::vector<AnomalyEvent> last = {{
        .timestamp = 60000, .metric_type = "cpu",
        .description = "extreme", .severity = 1.0, .risk_score = 0.0
    }};
    auto risk = engine.evaluate(last, {}, 60000);
    EXPECT_LE(risk.total, 100.0);
}
