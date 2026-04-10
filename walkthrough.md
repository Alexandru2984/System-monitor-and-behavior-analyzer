# Walkthrough — Self-Evolving System Monitor v0.1.0

## What Was Built

A complete C++ system monitoring application with:
- **4 metric collectors** reading from `/proc/` (CPU, RAM, processes, network)
- **SQLite storage** with WAL mode, prepared statements, data pruning
- **Analyzer Module** with Baseline Learning, Heuristics, and Pattern Detection
- **Multi-threaded scheduler** using C++20 `jthread` + `stop_token`
- **39+ unit tests** across 9 test suites (100% pass)
- **Native ImGui dashboard** with real-time charts, timeline, and process table

## Project Structure

```
sysmonitor/
├── CMakeLists.txt
├── config/default.json
├── src/
│   ├── main.cpp                        # Monitor entry point
│   ├── core/{types,config,scheduler}   # Shared types, config, orchestration
│   ├── collectors/{cpu,memory,process,network}_collector
│   ├── storage/{storage_engine,sqlite_storage}
│   ├── analysis/{baseline_calculator,anomaly_detector,risk_scorer}
│   ├── analyzer/{analyzer,baseline_manager,pattern_detector,explainer,risk_engine,event_timeline}
│   ├── utils/logger
│   └── dashboard/dashboard.cpp         # ImGui native GUI
├── tests/test_{cpu,memory,baseline,sqlite,anomaly,baseline_manager,pattern_detector,risk_engine,explainer}
└── third_party/                        # spdlog, nlohmann/json, GoogleTest, ImGui, ImPlot
```

## How to Run

### 1. Build
```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### 2. Start the monitor (Terminal 1)
```bash
cd build
./sysmonitor ../config/default.json
```

### 3. Launch the dashboard (Terminal 2)
```bash
cd build
./sysmonitor_dashboard sysmonitor.db
```

### 4. Run tests
```bash
cd build && ctest --output-on-failure
```

## Verification Results

### Unit Tests — 9/9 Suites, 100% Pass
| Suite | Component Tested | Status |
|-------|------------------|--------|
| `test_cpu_collector` | CPU proc parsing | ✅ |
| `test_memory_collector` | RAM proc parsing | ✅ |
| `test_baseline_calculator` | Basic EMA & sigma | ✅ |
| `test_sqlite_storage` | DB operations | ✅ |
| `test_anomaly_detector` | Basic anomaly triggering | ✅ |
| `test_baseline_manager` | Dual-window, percentiles, trend | ✅ |
| `test_pattern_detector` | CPU loads, Mem leaks, Oscillation | ✅ |
| `test_risk_engine` | 5-factor risk scoring | ✅ |
| `test_explainer` | UI formatting & ASCII rendering | ✅ |

### Stress Test — Anomalies Detected
- CPU hit **100%** during load
- **3 memory anomalies** with risk scores (15.8–17.7) stored in DB
- Fixed sigma-floor bug discovered during testing

### Dashboard Features
| Panel | Description |
|-------|-------------|
| CPU Graph | Rolling 2-minute line chart, per-core + aggregate |
| Memory Gauge | Shaded area chart + progress bar with color thresholds |
| Network | RX/TX throughput in kbps with auto-scaling Y axis |
| Per-Core Bars | Real-time bar chart of all CPU cores |
| Risk Score | Large color-coded display (green/orange/red) |
| Analysis Reports | List of events with timestamp, severity and descriptions |
| Incident Timeline | Timeline of Active/Resolved incidents and their peak risk bar |
| Process Table | Top 50 processes, sortable by any column |

## Binary Sizes (Debug)
- `sysmonitor`: 13 MB
- `sysmonitor_dashboard`: 19 MB

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Separate dashboard executable | Dashboard reads DB independently — monitor and UI are decoupled |
| ImGui + ImPlot | Native, no browser overhead, ~60fps, 0 JS dependencies |
| Sigma floor (1.0) | Prevents false positives when baseline has zero variance |
| 500ms poll interval | Smooth UI updates without excessive DB reads |
