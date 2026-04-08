cmake_minimum_required(VERSION 3.20)
project(sysmonitor
    VERSION 0.1.0
    DESCRIPTION "Self-Evolving System Monitor and Behavior Analyzer"
    LANGUAGES CXX
)

# ── C++20 required ──────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Compiler warnings (treat warnings seriously) ────────────────────────────
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wshadow -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor -Woverloaded-virtual
)

# ── Third-party dependencies via FetchContent ───────────────────────────────
add_subdirectory(third_party)

# ── Find system SQLite ──────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# ── Main library (all modules compiled as a static lib for easy testing) ────
add_library(sysmonitor_lib STATIC
    src/utils/logger.cpp
    src/collectors/cpu_collector.cpp
    src/collectors/memory_collector.cpp
    src/collectors/process_collector.cpp
    src/collectors/network_collector.cpp
    src/storage/sqlite_storage.cpp
    src/analysis/baseline_calculator.cpp
    src/analysis/anomaly_detector.cpp
    src/analysis/risk_scorer.cpp
    src/core/scheduler.cpp
    src/core/config.cpp
)

target_include_directories(sysmonitor_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SQLITE3_INCLUDE_DIRS}
)

target_link_libraries(sysmonitor_lib PUBLIC
    ${SQLITE3_LIBRARIES}
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    pthread
)

# ── Main executable ─────────────────────────────────────────────────────────
add_executable(sysmonitor src/main.cpp)
target_link_libraries(sysmonitor PRIVATE sysmonitor_lib)

# ── Tests ────────────────────────────────────────────────────────────────────
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ── Dashboard (ImGui native GUI) ────────────────────────────────────────────
option(BUILD_DASHBOARD "Build ImGui dashboard" ON)
if(BUILD_DASHBOARD)
    add_executable(sysmonitor_dashboard src/dashboard/dashboard.cpp)
    target_link_libraries(sysmonitor_dashboard PRIVATE
        sysmonitor_lib
        imgui_lib
    )
    # ImGui headers use some conversions that trigger our strict warnings;
    # suppress them for this target only.
    target_compile_options(sysmonitor_dashboard PRIVATE
        -Wno-conversion -Wno-sign-conversion -Wno-old-style-cast
    )
endif()
