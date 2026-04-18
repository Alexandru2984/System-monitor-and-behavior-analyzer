# System Monitor & Behavior Analyzer

A self-evolving system monitor built in **C++20** that collects real-time metrics, detects anomalies using statistical baselines, and scores system risk through a multi-factor engine.

## Features

- **Real-time metric collection** — CPU (per-core), memory, network I/O, process table
- **Dual-window anomaly detection** — EMA-based short/long baselines with sigma thresholds
- **Pattern detection** — Sustained high load, oscillation, trend analysis, memory leaks, process lifecycle
- **Multi-factor risk scoring** — Severity × Persistence × Breadth × Recency × Familiarity
- **Incident management** — Automatic grouping of related anomalies into incidents with summaries
- **Native dashboard** — ImGui/ImPlot real-time charts, process table, anomaly log, CSV/TXT export
- **SQLite persistence** — WAL mode, prepared statements, automatic data pruning

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Scheduler                             │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ CPU      │ │ Memory   │ │ Network  │ │ Process  │       │
│  │ Collector│ │ Collector│ │ Collector│ │ Collector│       │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘       │
│       │             │            │             │             │
│       ▼             ▼            ▼             ▼             │
│  ┌─────────────────────────────────────────────────┐        │
│  │              SqliteStorage (WAL)                 │        │
│  └─────────────────────────────────────────────────┘        │
│       │             │            │             │             │
│       └─────────────┴────────────┴─────────────┘             │
│                         │                                    │
│                         ▼                                    │
│              ┌──────────────────┐                            │
│              │   MetricQueue    │  (thread-safe, bounded)    │
│              └────────┬─────────┘                            │
│                       ▼                                      │
│  ┌─────────────────────────────────────────────────┐        │
│  │           Analyzer (single thread)               │        │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐   │        │
│  │  │ Baseline   │ │  Pattern   │ │   Risk     │   │        │
│  │  │ Manager    │ │  Detector  │ │  Engine    │   │        │
│  │  └────────────┘ └────────────┘ └────────────┘   │        │
│  │  ┌────────────┐ ┌────────────┐                   │        │
│  │  │ Explainer  │ │  Event     │                   │        │
│  │  │            │ │  Timeline  │                   │        │
│  │  └────────────┘ └────────────┘                   │        │
│  └─────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│           Dashboard (separate binary, reads DB)              │
│  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐              │
│  │ CPU  │ │ MEM  │ │ NET  │ │ PROC │ │ RISK │              │
│  │Chart │ │Chart │ │Chart │ │Table │ │Score │              │
│  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘              │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- **C++20** compiler (GCC 12+, Clang 15+)
- **CMake** 3.20+
- **SQLite3** development libraries
- **GLFW3** + **OpenGL** (for dashboard only)

### Ubuntu/Debian
```bash
sudo apt install build-essential cmake libsqlite3-dev libglfw3-dev
```

### Fedora
```bash
sudo dnf install gcc-c++ cmake sqlite-devel glfw-devel
```

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

To build without the dashboard (no GLFW/OpenGL needed):
```bash
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_DASHBOARD=OFF
```

## Usage

### Monitor
```bash
# Uses default config (config/default.json)
./sysmonitor

# Custom config
./sysmonitor /path/to/config.json
```

### Dashboard
```bash
# Run in a separate terminal (reads from the same DB)
./dashboard

# Custom DB path
./dashboard /path/to/sysmonitor.db
```

### Configuration

Edit `config/default.json`:

```json
{
    "cpu_interval_ms": 1000,
    "memory_interval_ms": 1000,
    "process_interval_ms": 5000,
    "network_interval_ms": 2000,
    "db_path": "sysmonitor.db",
    "retention_hours": 24,
    "anomaly_sigma": 2.0,
    "ema_alpha": 0.1,
    "log_file": "sysmonitor.log",
    "log_level": "info"
}
```

| Parameter | Description |
|-----------|-------------|
| `*_interval_ms` | Collection frequency per metric type |
| `anomaly_sigma` | Sigma threshold for anomaly detection (lower = more sensitive) |
| `ema_alpha` | EMA smoothing factor (higher = faster adaptation to new data) |
| `retention_hours` | Auto-prune data older than this |

## Testing

```bash
cd build
ctest --output-on-failure
```

10 test suites covering collectors, storage, analysis, and scheduler lifecycle.

## Project Structure

```
src/
├── core/           # Types, config, scheduler, metric queue
├── collectors/     # CPU, memory, network, process collectors
├── storage/        # SQLite persistence layer
├── analyzer/       # Baseline manager, pattern detector, risk engine,
│                   # explainer, event timeline
├── dashboard/      # ImGui/ImPlot real-time visualization
└── utils/          # Logger wrapper (spdlog)
tests/              # GoogleTest unit tests
config/             # Default configuration
third_party/        # CMake FetchContent (spdlog, json, gtest, imgui, implot)
```

## Dependencies (auto-fetched via CMake)

- [spdlog](https://github.com/gabime/spdlog) v1.14.1 — Logging
- [nlohmann/json](https://github.com/nlohmann/json) v3.11.3 — Config parsing
- [GoogleTest](https://github.com/google/googletest) v1.14.0 — Unit tests
- [Dear ImGui](https://github.com/ocornut/imgui) v1.91.8 — Dashboard UI
- [ImPlot](https://github.com/epezent/implot) v0.16 — Charts

## License

MIT
