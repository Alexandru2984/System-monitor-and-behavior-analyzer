#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run.sh — Start the System Monitor and Dashboard together
# ─────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   ./run.sh              # Build (if needed) and run both
#   ./run.sh --no-build   # Skip build, just run
#   ./run.sh --monitor    # Run monitor only (no dashboard)
#   ./run.sh --dashboard  # Run dashboard only (monitor must be running)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
CONFIG="${SCRIPT_DIR}/config/default.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ── Parse arguments ──────────────────────────────────────────────────────────
SKIP_BUILD=false
RUN_MONITOR=true
RUN_DASHBOARD=true

for arg in "$@"; do
    case "$arg" in
        --no-build)   SKIP_BUILD=true ;;
        --monitor)    RUN_DASHBOARD=false ;;
        --dashboard)  RUN_MONITOR=false ;;
        --help|-h)
            echo "Usage: ./run.sh [--no-build] [--monitor] [--dashboard]"
            echo ""
            echo "  --no-build    Skip the build step"
            echo "  --monitor     Run the monitor only (no dashboard)"
            echo "  --dashboard   Run the dashboard only"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: ${arg}${NC}"
            echo "Run ./run.sh --help for usage"
            exit 1
            ;;
    esac
done

# ── Build ────────────────────────────────────────────────────────────────────
if [ "$SKIP_BUILD" = false ]; then
    echo -e "${CYAN}▸ Building project...${NC}"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_DASHBOARD=ON 2>&1 | tail -3
    make -j"$(nproc)" 2>&1 | tail -5
    echo -e "${GREEN}✓ Build complete${NC}"
    cd "$SCRIPT_DIR"
fi

# ── Verify binaries exist ───────────────────────────────────────────────────
MONITOR_BIN="${BUILD_DIR}/sysmonitor"
DASHBOARD_BIN="${BUILD_DIR}/dashboard"

if [ "$RUN_MONITOR" = true ] && [ ! -f "$MONITOR_BIN" ]; then
    echo -e "${RED}✗ Monitor binary not found at ${MONITOR_BIN}${NC}"
    echo "  Run without --no-build to compile first."
    exit 1
fi

if [ "$RUN_DASHBOARD" = true ] && [ ! -f "$DASHBOARD_BIN" ]; then
    echo -e "${RED}✗ Dashboard binary not found at ${DASHBOARD_BIN}${NC}"
    echo "  Make sure GLFW3 and OpenGL are installed, then rebuild."
    exit 1
fi

# ── Cleanup handler ─────────────────────────────────────────────────────────
MONITOR_PID=""
DASHBOARD_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}▸ Shutting down...${NC}"

    if [ -n "$DASHBOARD_PID" ] && kill -0 "$DASHBOARD_PID" 2>/dev/null; then
        kill "$DASHBOARD_PID" 2>/dev/null
        wait "$DASHBOARD_PID" 2>/dev/null || true
        echo -e "${GREEN}  ✓ Dashboard stopped${NC}"
    fi

    if [ -n "$MONITOR_PID" ] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        kill -SIGINT "$MONITOR_PID" 2>/dev/null  # graceful shutdown via signal handler
        wait "$MONITOR_PID" 2>/dev/null || true
        echo -e "${GREEN}  ✓ Monitor stopped${NC}"
    fi

    echo -e "${GREEN}✓ All processes stopped. Goodbye!${NC}"
}

trap cleanup EXIT INT TERM

# ── Launch ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     System Monitor & Behavior Analyzer   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

if [ "$RUN_MONITOR" = true ]; then
    echo -e "${GREEN}▸ Starting monitor...${NC}"
    "$MONITOR_BIN" "$CONFIG" &
    MONITOR_PID=$!
    echo -e "  PID: ${MONITOR_PID}"

    # Give the monitor a moment to create the DB before launching dashboard
    sleep 1
fi

if [ "$RUN_DASHBOARD" = true ]; then
    echo -e "${GREEN}▸ Starting dashboard...${NC}"
    "$DASHBOARD_BIN" &
    DASHBOARD_PID=$!
    echo -e "  PID: ${DASHBOARD_PID}"
fi

echo ""
echo -e "${YELLOW}Press Ctrl+C to stop all processes${NC}"
echo ""

# ── Wait for either process to exit ─────────────────────────────────────────
# If one exits, we shut down the other via the cleanup trap.
wait -n 2>/dev/null || true
