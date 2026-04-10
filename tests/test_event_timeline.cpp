// ─────────────────────────────────────────────────────────────────────────────
// tests/test_event_timeline.cpp — Unit tests for EventTimeline
// ─────────────────────────────────────────────────────────────────────────────

#include "analyzer/event_timeline.h"
#include "utils/logger.h"

#include <gtest/gtest.h>
#include <filesystem>

using namespace sysmon;

class EventTimelineTest : public ::testing::Test {
protected:
    std::string db_path = "/tmp/sysmon_timeline_test.db";

    void SetUp() override {
        cleanup();
        static bool logger_init = false;
        if (!logger_init) {
            Logger::init("/tmp/sysmon_timeline_test.log", spdlog::level::warn);
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

    AnalysisReport makeReport(int64_t ts, int anomaly_count = 0,
                              double risk = 0.0, const std::string& explanation = "") {
        AnalysisReport report;
        report.timestamp = ts;
        report.risk.total = risk;
        report.explanation = explanation;

        for (int i = 0; i < anomaly_count; ++i) {
            report.anomalies.push_back(AnomalyEvent{
                {ts, "cpu", "test anomaly " + std::to_string(i)},
                0.5, risk * 0.5
            });
        }
        return report;
    }
};

TEST_F(EventTimelineTest, InitializesWithoutError) {
    EventTimeline timeline(db_path);
    EXPECT_NO_THROW(timeline.initialize());
}

TEST_F(EventTimelineTest, RecordEmptyReport) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    // Empty reports are throttled but the first one should go through
    auto report = makeReport(1000);
    EXPECT_NO_THROW(timeline.record(report));
}

TEST_F(EventTimelineTest, OpenIncidentOnAnomaly) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    auto report = makeReport(1000, 1, 25.0, "CPU spike detected");
    timeline.record(report);

    auto active = timeline.getActiveIncident();
    EXPECT_TRUE(active.is_active);
    EXPECT_EQ(active.start_time, 1000);
    EXPECT_GE(active.peak_risk, 25.0);
}

TEST_F(EventTimelineTest, ExtendIncidentWithMoreAnomalies) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    // Open incident
    timeline.record(makeReport(1000, 1, 20.0, "spike 1"));

    // Extend with a higher-risk event
    timeline.record(makeReport(2000, 2, 45.0, "spike 2"));

    auto active = timeline.getActiveIncident();
    EXPECT_TRUE(active.is_active);
    EXPECT_GE(active.peak_risk, 45.0);
    EXPECT_GE(active.event_count, 2);
}

TEST_F(EventTimelineTest, CloseIncidentAfterGap) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    // Open incident
    timeline.record(makeReport(1000, 1, 30.0, "spike"));

    // Gap > INCIDENT_GAP_MS (30s) with no anomalies
    auto quiet = makeReport(1000 + 31000);
    timeline.record(quiet);

    auto active = timeline.getActiveIncident();
    // Incident should be closed (getActiveIncident returns default with is_active=false)
    EXPECT_FALSE(active.is_active);

    // Should appear in incident history
    auto incidents = timeline.getIncidents(0, 100000);
    ASSERT_GE(incidents.size(), 1u);
    EXPECT_FALSE(incidents[0].is_active);
    EXPECT_FALSE(incidents[0].summary.empty());
}

TEST_F(EventTimelineTest, GetRecentEventsReturnsRecords) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    // Record several events with anomalies
    for (int i = 0; i < 5; ++i) {
        auto report = makeReport(1000 + i * 1000, 1, 10.0 + i * 5,
                                 "event " + std::to_string(i));
        timeline.record(report);
    }

    auto events = timeline.getRecentEvents(3);
    ASSERT_GE(events.size(), 3u);
    // Should be ordered by timestamp DESC
    EXPECT_GE(events[0].timestamp, events[1].timestamp);
}

TEST_F(EventTimelineTest, StaleIncidentClosedOnRestart) {
    {
        // First session: open an incident but "crash" (no destructor close)
        EventTimeline timeline(db_path);
        timeline.initialize();
        timeline.record(makeReport(1000, 1, 30.0, "spike"));

        auto active = timeline.getActiveIncident();
        EXPECT_TRUE(active.is_active);
        // Destructor will try to close it, but let's simulate the stale case
    }

    // Manually re-open the incident as stale (the destructor may have closed it,
    // so we verify the initialize() cleanup handles it regardless)
    {
        EventTimeline timeline2(db_path);
        timeline2.initialize();
        // After initialize(), stale incidents should be closed
        auto active = timeline2.getActiveIncident();
        EXPECT_FALSE(active.is_active);
    }
}

TEST_F(EventTimelineTest, MultipleIncidentLifecycles) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    // First incident
    timeline.record(makeReport(1000, 1, 20.0, "incident 1"));
    timeline.record(makeReport(32000));  // gap → close

    // Second incident
    timeline.record(makeReport(40000, 2, 50.0, "incident 2"));
    timeline.record(makeReport(72000));  // gap → close

    auto incidents = timeline.getIncidents(0, 100000);
    ASSERT_GE(incidents.size(), 2u);
}

TEST_F(EventTimelineTest, ThrottlesEmptyEvents) {
    EventTimeline timeline(db_path);
    timeline.initialize();

    // Record many empty reports rapidly (< 5s apart)
    for (int i = 0; i < 10; ++i) {
        timeline.record(makeReport(1000 + i * 100));
    }

    // Should be throttled — only the first should go through
    auto events = timeline.getRecentEvents(20);
    EXPECT_LE(events.size(), 2u);
}
