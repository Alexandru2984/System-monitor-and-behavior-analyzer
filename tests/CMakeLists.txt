# ── Unit Tests ────────────────────────────────────────────────────────────────

# Helper function: add a test executable linked to our lib + gtest
function(add_sysmonitor_test TEST_NAME TEST_SRC)
    add_executable(${TEST_NAME} ${TEST_SRC})
    target_link_libraries(${TEST_NAME} PRIVATE
        sysmonitor_lib
        GTest::gtest_main
    )
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endfunction()

add_sysmonitor_test(test_cpu_collector    test_cpu_collector.cpp)
add_sysmonitor_test(test_memory_collector test_memory_collector.cpp)
add_sysmonitor_test(test_baseline_calculator test_baseline_calculator.cpp)
add_sysmonitor_test(test_sqlite_storage   test_sqlite_storage.cpp)
add_sysmonitor_test(test_baseline_manager test_baseline_manager.cpp)
add_sysmonitor_test(test_pattern_detector test_pattern_detector.cpp)
add_sysmonitor_test(test_risk_engine      test_risk_engine.cpp)
add_sysmonitor_test(test_explainer        test_explainer.cpp)
add_sysmonitor_test(test_analyzer         test_analyzer.cpp)
add_sysmonitor_test(test_event_timeline   test_event_timeline.cpp)
add_sysmonitor_test(test_scheduler        test_scheduler.cpp)
