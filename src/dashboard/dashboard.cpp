// ─────────────────────────────────────────────────────────────────────────────
// dashboard/dashboard.cpp — Native ImGui dashboard for System Monitor
// ─────────────────────────────────────────────────────────────────────────────
//
// This is a SEPARATE executable from the monitor itself.  It reads from the
// same SQLite database and displays real-time charts and tables.
//
// Run the monitor (sysmonitor) in one terminal, and the dashboard in another.
// The dashboard polls the DB every second for new data.
// ─────────────────────────────────────────────────────────────────────────────

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"

#include "storage/sqlite_storage.h"
#include "utils/logger.h"

#include <GLFW/glfw3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <deque>
#include <string>
#include <vector>
#include <cmath>
#include <fstream>
#include <unistd.h>
#include <cmath>

// ── Color palette (dark theme accent colors) ────────────────────────────────
static const ImVec4 kAccentCyan   = ImVec4(0.0f, 0.83f, 0.95f, 1.0f);
static const ImVec4 kAccentGreen  = ImVec4(0.18f, 0.84f, 0.45f, 1.0f);
static const ImVec4 kAccentOrange = ImVec4(1.0f, 0.60f, 0.0f, 1.0f);
static const ImVec4 kAccentRed    = ImVec4(0.95f, 0.25f, 0.25f, 1.0f);
static const ImVec4 kAccentPurple = ImVec4(0.68f, 0.39f, 0.95f, 1.0f);
static const ImVec4 kAccentPink   = ImVec4(0.93f, 0.35f, 0.65f, 1.0f);
static const ImVec4 kBgPanel      = ImVec4(0.12f, 0.12f, 0.15f, 1.0f);

// ── Dashboard constants ─────────────────────────────────────────────────────
static constexpr size_t  ROLLING_BUFFER_SIZE    = 120;   // 2 min at 1s intervals
static constexpr int     POLL_INTERVAL_MS       = 500;
static constexpr int     STRESS_DURATION_SEC    = 20;
static constexpr int     STRESS_THREADS         = 4;
static constexpr int     MAX_PROCESSES_DISPLAY  = 50;
static constexpr int     MAX_ANOMALIES_DISPLAY  = 50;
static constexpr int     MAX_INCIDENTS_DISPLAY  = 20;
static constexpr int     MAX_EVENTS_DISPLAY     = 10;
static constexpr int     MAX_CORE_DISPLAY       = 8;
static constexpr double  RISK_LOW_THRESHOLD     = 10.0;
static constexpr double  RISK_MED_THRESHOLD     = 40.0;

// ── Rolling buffer for time-series data ─────────────────────────────────────
struct RollingBuffer {
    std::deque<double> data;
    size_t max_size;
    explicit RollingBuffer(size_t n = ROLLING_BUFFER_SIZE) : max_size(n) {}
    void push(double v) {
        data.push_back(v);
        while (data.size() > max_size) data.pop_front();
    }
    bool empty() const { return data.empty(); }
    double back() const { return data.empty() ? 0.0 : data.back(); }
};

// ── Stress test ─────────────────────────────────────────────────────────────
static std::atomic<bool> g_is_stressing{false};
static void startStressTest() {
    if (g_is_stressing) return;
    g_is_stressing = true;
    for (int i = 0; i < STRESS_THREADS; ++i) {
        std::thread([]{
            auto start = std::chrono::steady_clock::now();
            while (std::chrono::steady_clock::now() - start < std::chrono::seconds(STRESS_DURATION_SEC)) {
                volatile uint64_t x = 1;
                for (int j = 0; j < 10000; ++j) {
                    x = (x * 1103515245 + 12345) % 2147483648;
                }
            }
        }).detach();
    }
    std::thread([]{
        std::this_thread::sleep_for(std::chrono::seconds(STRESS_DURATION_SEC));
        g_is_stressing = false;
    }).detach();
}

// Process table uses sysmon::ProcessInfo from core/types.h
using ProcEntry = sysmon::ProcessInfo;

// ── Anomaly log entry ───────────────────────────────────────────────────────
struct AnomalyEntry {
    int64_t timestamp;
    std::string type;
    std::string description;
    double severity;
    double risk_score;
};

// ── Incident entry (from Analyzer) ──────────────────────────────────────────
struct IncidentEntry {
    int64_t id;
    int64_t start_time;
    int64_t end_time;
    std::string summary;
    double peak_risk;
    int event_count;
    bool is_active;
};

// ── Analysis event entry ────────────────────────────────────────────────────
struct AnalysisEventEntry {
    int64_t timestamp;
    int anomaly_count;
    int pattern_count;
    double risk_total;
    std::string explanation;
};

// ── Export functions ────────────────────────────────────────────────────────

// Try running a command and return its stdout (empty on failure).
static std::string runDialogCmd(const std::string& cmd) {
    std::string result;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    int status = pclose(pipe);
    if (status != 0) return {};   // user cancelled or command not found
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

// Portable save-file dialog: tries zenity → kdialog → default path fallback.
static std::string saveFileDialog(const std::string& default_name, const std::string& ext) {
    char cwd_buf[1024];
    std::string pwd;
    if (getcwd(cwd_buf, sizeof(cwd_buf))) {
        pwd = std::string(cwd_buf) + "/";
    }
    std::string filepath = pwd + default_name;

    // Try zenity (GTK desktops)
    std::string result = runDialogCmd(
        "zenity --file-selection --save --confirm-overwrite "
        "--title=\"Export Data\" "
        "--filename=\"" + filepath + "\" "
        "--file-filter=\"" + ext + " files | *." + ext + "\" 2>/dev/null");

    // Try kdialog (KDE desktops)
    if (result.empty()) {
        result = runDialogCmd(
            "kdialog --getsavefilename \"" + filepath + "\" \"*." + ext + "\" 2>/dev/null");
    }

    // Fallback: use default path directly (no GUI dialog available)
    if (result.empty()) {
        result = filepath;
    }

    // Ensure correct extension
    std::string expected_ext = "." + ext;
    if (result.size() < expected_ext.size() ||
        result.substr(result.size() - expected_ext.size()) != expected_ext) {
        result += expected_ext;
    }

    return result;
}

static std::string getCurrentTimestampString() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm_buf);
    return std::string(buf);
}

static std::string csvEscape(const std::string& field) {
    if (field.find_first_of(",\"\n") == std::string::npos) return field;
    std::string escaped = "\"";
    for (char c : field) {
        if (c == '"') escaped += "\"\"";
        else escaped += c;
    }
    escaped += '"';
    return escaped;
}

static void exportDataToCSV(std::vector<ProcEntry> procs) {
    std::thread([procs = std::move(procs)]() {
        std::string filename = "resources_" + getCurrentTimestampString() + ".csv";
        std::string filepath = saveFileDialog(filename, "csv");
        if (filepath.empty()) return;

        if (std::ofstream os{filepath}) {
            os << "PID,Name,User,State,CPU%,MEM%\n";
            for (const auto& p : procs) {
                os << p.pid << "," << csvEscape(p.name) << "," << csvEscape(p.user)
                   << "," << csvEscape(p.state) << "," << p.cpu_percent << "," << p.mem_percent << "\n";
            }
        }
    }).detach();
}

static void exportReportsToTXT(std::vector<AnalysisEventEntry> events) {
    std::thread([events = std::move(events)]() {
        std::string filename = "reports_" + getCurrentTimestampString() + ".txt";
        std::string filepath = saveFileDialog(filename, "txt");
        if (filepath.empty()) return;

        if (std::ofstream os{filepath}) {
            os << "==========================================\n";
            os << "       SYSTEM MONITOR ANALYSIS REPORTS    \n";
            os << "==========================================\n\n";
            for (const auto& ev : events) {
                std::time_t t = ev.timestamp;
                struct tm tm_buf;
                localtime_r(&t, &tm_buf);
                char time_str[32];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

                os << "Time: " << time_str << "\n";
                os << "Risk Score: " << ev.risk_total << " (" << ev.anomaly_count 
                   << " anomalies, " << ev.pattern_count << " patterns)\n";
                os << "------------------------------------------\n";
                os << ev.explanation << "\n\n";
            }
        }
    }).detach();
}

// ── Data source: polls SQLite DB ────────────────────────────────────────────
class DashboardData {
public:
    DashboardData(const std::string& db_path) : db_path_(db_path) {}

    ~DashboardData() {
        if (db_) sqlite3_close(db_);
    }

    // Non-copyable due to owning sqlite3* handle — use move semantics
    DashboardData(const DashboardData& other)
        : cpu_total(other.cpu_total), cpu_cores(other.cpu_cores)
        , mem_usage(other.mem_usage), mem_used_gb(other.mem_used_gb)
        , mem_total_gb(other.mem_total_gb), net_rx(other.net_rx), net_tx(other.net_tx)
        , processes(other.processes), anomalies(other.anomalies)
        , incidents(other.incidents), analysis_events(other.analysis_events)
        , risk_score(other.risk_score)
        , last_cpu_ts_(other.last_cpu_ts_), last_mem_ts_(other.last_mem_ts_)
        , last_net_ts_(other.last_net_ts_)
        , db_path_(other.db_path_)
    {
        // Copy does NOT share the db_ handle — only the poller's instance opens DB
    }

    DashboardData& operator=(const DashboardData& other) {
        if (this == &other) return *this;
        db_path_ = other.db_path_;
        cpu_total = other.cpu_total; cpu_cores = other.cpu_cores;
        mem_usage = other.mem_usage; mem_used_gb = other.mem_used_gb;
        mem_total_gb = other.mem_total_gb; net_rx = other.net_rx; net_tx = other.net_tx;
        processes = other.processes; anomalies = other.anomalies;
        incidents = other.incidents; analysis_events = other.analysis_events;
        risk_score = other.risk_score;
        last_cpu_ts_ = other.last_cpu_ts_; last_mem_ts_ = other.last_mem_ts_;
        last_net_ts_ = other.last_net_ts_;
        // Do NOT copy db_ — only the poller owns a connection
        return *this;
    }

    void poll() {
        if (!db_) {
            if (sqlite3_open_v2(db_path_.c_str(), &db_, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK) {
                db_ = nullptr;
                return;
            }
            sqlite3_busy_timeout(db_, 5000);
        }

        pollCpu(db_);
        pollMemory(db_);
        pollNetwork(db_);
        pollProcesses(db_);
        pollAnomalies(db_);
        pollIncidents(db_);
        pollAnalysisEvents(db_);
    }

    // Rolling buffers (120 points = 2 minutes at 1s intervals)
    RollingBuffer cpu_total;
    std::vector<RollingBuffer> cpu_cores;
    RollingBuffer mem_usage;
    RollingBuffer mem_used_gb;
    RollingBuffer mem_total_gb;
    RollingBuffer net_rx;
    RollingBuffer net_tx;

    std::vector<ProcEntry> processes;
    std::vector<AnomalyEntry> anomalies;
    std::vector<IncidentEntry> incidents;
    std::vector<AnalysisEventEntry> analysis_events;

    double risk_score = 0.0;
    int64_t last_cpu_ts_ = 0;
    int64_t last_mem_ts_ = 0;
    int64_t last_net_ts_ = 0;

private:
    std::string db_path_;
    sqlite3* db_ = nullptr;

    void pollCpu(sqlite3* db) {
        // Get latest aggregate CPU reading
        const char* sql = "SELECT timestamp, usage_pct FROM cpu_metrics "
                         "WHERE core_id = -1 AND timestamp > ? ORDER BY timestamp;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int64(stmt, 1, last_cpu_ts_);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            last_cpu_ts_ = sqlite3_column_int64(stmt, 0);
            cpu_total.push(sqlite3_column_double(stmt, 1));
        }
        sqlite3_finalize(stmt);

        // Per-core data (latest only)
        const char* core_sql = "SELECT core_id, usage_pct FROM cpu_metrics "
                               "WHERE timestamp = ? AND core_id >= 0 ORDER BY core_id;";
        if (sqlite3_prepare_v2(db, core_sql, -1, &stmt, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int64(stmt, 1, last_cpu_ts_);

        std::vector<double> core_vals;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            core_vals.push_back(sqlite3_column_double(stmt, 1));
        }
        sqlite3_finalize(stmt);

        // Resize buffers if core count changed
        if (cpu_cores.size() != core_vals.size()) {
            cpu_cores.resize(core_vals.size(), RollingBuffer(120));
        }
        for (size_t i = 0; i < core_vals.size(); ++i) {
            cpu_cores[i].push(core_vals[i]);
        }
    }

    void pollMemory(sqlite3* db) {
        const char* sql = "SELECT timestamp, total_kb, used_kb, usage_pct FROM memory_metrics "
                         "WHERE timestamp > ? ORDER BY timestamp;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int64(stmt, 1, last_mem_ts_);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            last_mem_ts_ = sqlite3_column_int64(stmt, 0);
            double total_gb = sqlite3_column_int64(stmt, 1) / 1024.0 / 1024.0;
            double used_gb = sqlite3_column_int64(stmt, 2) / 1024.0 / 1024.0;
            double pct = sqlite3_column_double(stmt, 3);
            mem_total_gb.push(total_gb);
            mem_used_gb.push(used_gb);
            mem_usage.push(pct);
        }
        sqlite3_finalize(stmt);
    }

    void pollNetwork(sqlite3* db) {
        const char* sql = "SELECT timestamp, SUM(rx_rate_kbps), SUM(tx_rate_kbps) "
                         "FROM network_metrics WHERE timestamp > ? "
                         "GROUP BY timestamp ORDER BY timestamp;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return;
        sqlite3_bind_int64(stmt, 1, last_net_ts_);

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            last_net_ts_ = sqlite3_column_int64(stmt, 0);
            net_rx.push(sqlite3_column_double(stmt, 1));
            net_tx.push(sqlite3_column_double(stmt, 2));
        }
        sqlite3_finalize(stmt);
    }

    void pollProcesses(sqlite3* db) {
        // No ORDER BY — the UI sorts client-side via ImGui sort specs.
        std::string sql = "SELECT pid, name, user, state, cpu_pct, mem_pct "
                          "FROM process_snapshots WHERE timestamp = "
                          "(SELECT MAX(timestamp) FROM process_snapshots) "
                          "LIMIT " + std::to_string(MAX_PROCESSES_DISPLAY) + ";";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;

        processes.clear();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            ProcEntry p;
            p.pid = sqlite3_column_int(stmt, 0);
            auto name_txt = sqlite3_column_text(stmt, 1);
            p.name = name_txt ? reinterpret_cast<const char*>(name_txt) : "";
            auto user_txt = sqlite3_column_text(stmt, 2);
            p.user = user_txt ? reinterpret_cast<const char*>(user_txt) : "";
            auto state_txt = sqlite3_column_text(stmt, 3);
            p.state = state_txt ? reinterpret_cast<const char*>(state_txt) : "?";
            p.cpu_percent = sqlite3_column_double(stmt, 4);
            p.mem_percent = sqlite3_column_double(stmt, 5);
            processes.push_back(p);
        }
        sqlite3_finalize(stmt);
    }

    void pollAnomalies(sqlite3* db) {
        std::string sql = "SELECT timestamp, metric_type, description, severity, risk_score "
                          "FROM anomalies ORDER BY timestamp DESC LIMIT " + std::to_string(MAX_ANOMALIES_DISPLAY) + ";";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;

        anomalies.clear();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            AnomalyEntry a;
            a.timestamp = sqlite3_column_int64(stmt, 0);
            auto type_txt = sqlite3_column_text(stmt, 1);
            a.type = type_txt ? reinterpret_cast<const char*>(type_txt) : "";
            auto desc_txt = sqlite3_column_text(stmt, 2);
            a.description = desc_txt ? reinterpret_cast<const char*>(desc_txt) : "";
            a.severity = sqlite3_column_double(stmt, 3);
            a.risk_score = sqlite3_column_double(stmt, 4);
            anomalies.push_back(a);
        }
        sqlite3_finalize(stmt);

        // Use the analyzer's multi-factor risk score from the latest analysis event
        // instead of computing a separate decay-based score here.
        // This keeps a single source of truth for risk (the Analyzer's RiskEngine).
        risk_score = 0.0;
        const char* risk_sql = "SELECT risk_total FROM analysis_events "
                               "ORDER BY timestamp DESC LIMIT 1;";
        sqlite3_stmt* risk_stmt = nullptr;
        if (sqlite3_prepare_v2(db, risk_sql, -1, &risk_stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(risk_stmt) == SQLITE_ROW) {
                risk_score = sqlite3_column_double(risk_stmt, 0);
            }
            sqlite3_finalize(risk_stmt);
        }
    }

    void pollIncidents(sqlite3* db) {
        std::string sql = "SELECT id, start_time, end_time, summary, peak_risk, "
                          "event_count, is_active FROM incidents "
                          "ORDER BY start_time DESC LIMIT " + std::to_string(MAX_INCIDENTS_DISPLAY) + ";";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;

        incidents.clear();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            IncidentEntry inc;
            inc.id = sqlite3_column_int64(stmt, 0);
            inc.start_time = sqlite3_column_int64(stmt, 1);
            inc.end_time = sqlite3_column_int64(stmt, 2);
            auto sum = sqlite3_column_text(stmt, 3);
            inc.summary = sum ? reinterpret_cast<const char*>(sum) : "";
            inc.peak_risk = sqlite3_column_double(stmt, 4);
            inc.event_count = sqlite3_column_int(stmt, 5);
            inc.is_active = sqlite3_column_int(stmt, 6) != 0;
            incidents.push_back(inc);
        }
        sqlite3_finalize(stmt);
    }

    void pollAnalysisEvents(sqlite3* db) {
        std::string sql = "SELECT timestamp, anomaly_count, pattern_count, "
                          "risk_total, explanation FROM analysis_events "
                          "WHERE explanation != '' "
                          "ORDER BY timestamp DESC LIMIT " + std::to_string(MAX_EVENTS_DISPLAY) + ";";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;

        analysis_events.clear();
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            AnalysisEventEntry e;
            e.timestamp = sqlite3_column_int64(stmt, 0);
            e.anomaly_count = sqlite3_column_int(stmt, 1);
            e.pattern_count = sqlite3_column_int(stmt, 2);
            e.risk_total = sqlite3_column_double(stmt, 3);
            auto expl = sqlite3_column_text(stmt, 4);
            e.explanation = expl ? reinterpret_cast<const char*>(expl) : "";
            analysis_events.push_back(e);
        }
        sqlite3_finalize(stmt);
    }
};

// ── Apply a premium dark theme ──────────────────────────────────────────────
static void applyDarkTheme() {
    ImGui::StyleColorsDark();
    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowRounding    = 8.0f;
    s.FrameRounding     = 6.0f;
    s.GrabRounding      = 4.0f;
    s.TabRounding       = 6.0f;
    s.ScrollbarRounding = 6.0f;
    s.WindowPadding     = ImVec2(12, 12);
    s.FramePadding      = ImVec2(8, 5);
    s.ItemSpacing       = ImVec2(10, 8);
    s.WindowBorderSize  = 0.0f;
    s.PopupBorderSize   = 1.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]         = ImVec4(0.08f, 0.08f, 0.10f, 1.0f);
    c[ImGuiCol_ChildBg]          = ImVec4(0.10f, 0.10f, 0.13f, 1.0f);
    c[ImGuiCol_PopupBg]          = ImVec4(0.10f, 0.10f, 0.14f, 0.96f);
    c[ImGuiCol_Border]           = ImVec4(0.20f, 0.20f, 0.25f, 0.50f);
    c[ImGuiCol_FrameBg]          = ImVec4(0.14f, 0.14f, 0.18f, 1.0f);
    c[ImGuiCol_FrameBgHovered]   = ImVec4(0.18f, 0.18f, 0.24f, 1.0f);
    c[ImGuiCol_FrameBgActive]    = ImVec4(0.22f, 0.22f, 0.30f, 1.0f);
    c[ImGuiCol_TitleBg]          = ImVec4(0.06f, 0.06f, 0.08f, 1.0f);
    c[ImGuiCol_TitleBgActive]    = ImVec4(0.10f, 0.10f, 0.14f, 1.0f);
    c[ImGuiCol_Tab]              = ImVec4(0.14f, 0.14f, 0.18f, 1.0f);
    c[ImGuiCol_TabHovered]       = ImVec4(0.0f, 0.65f, 0.85f, 0.80f);
    c[ImGuiCol_Header]           = ImVec4(0.15f, 0.15f, 0.20f, 1.0f);
    c[ImGuiCol_HeaderHovered]    = ImVec4(0.0f, 0.65f, 0.85f, 0.50f);
    c[ImGuiCol_HeaderActive]     = ImVec4(0.0f, 0.65f, 0.85f, 0.70f);
    c[ImGuiCol_Button]           = ImVec4(0.16f, 0.16f, 0.22f, 1.0f);
    c[ImGuiCol_ButtonHovered]    = ImVec4(0.0f, 0.65f, 0.85f, 0.80f);
    c[ImGuiCol_ButtonActive]     = ImVec4(0.0f, 0.55f, 0.75f, 1.0f);
    c[ImGuiCol_ScrollbarBg]      = ImVec4(0.06f, 0.06f, 0.08f, 0.5f);
    c[ImGuiCol_ScrollbarGrab]    = ImVec4(0.30f, 0.30f, 0.35f, 1.0f);
    c[ImGuiCol_TableHeaderBg]    = ImVec4(0.12f, 0.12f, 0.16f, 1.0f);
    c[ImGuiCol_TableBorderStrong]= ImVec4(0.20f, 0.20f, 0.25f, 1.0f);
    c[ImGuiCol_TableBorderLight] = ImVec4(0.16f, 0.16f, 0.20f, 1.0f);
    c[ImGuiCol_PlotLines]        = kAccentCyan;
    c[ImGuiCol_PlotHistogram]    = kAccentGreen;
}

// ── Helper: plot a rolling buffer with ImPlot ───────────────────────────────
static void plotRolling(const char* label, const RollingBuffer& buf,
                        float /*y_min*/, float /*y_max*/, ImVec4 color) {
    if (buf.empty()) return;
    std::vector<double> xs(buf.data.size()), ys(buf.data.begin(), buf.data.end());
    for (size_t i = 0; i < xs.size(); ++i) xs[i] = (double)i;

    ImPlot::PushStyleColor(ImPlotCol_Line, color);
    ImPlot::SetNextLineStyle(color, 2.0f);
    ImPlot::PlotLine(label, xs.data(), ys.data(), (int)xs.size());
    ImPlot::PopStyleColor();
}

// ── Helper: colored badge for severity ──────────────────────────────────────
static ImVec4 severityColor(double sev) {
    if (sev < 0.3) return kAccentGreen;
    if (sev < 0.6) return kAccentOrange;
    return kAccentRed;
}

static ImVec4 riskColor(double risk) {
    if (risk < RISK_LOW_THRESHOLD) return kAccentGreen;
    if (risk < RISK_MED_THRESHOLD) return kAccentOrange;
    return kAccentRed;
}

static const char* formatTimestamp(int64_t ts, char* buf, size_t bufsize) {
    time_t sec = ts / 1000;
    struct tm tm_buf;
    localtime_r(&sec, &tm_buf);
    strftime(buf, bufsize, "%H:%M:%S", &tm_buf);
    return buf;
}

// ── Main ────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    std::string db_path = "sysmonitor.db";
    if (argc > 1) db_path = argv[1];

    sysmon::Logger::init("/tmp/dashboard.log", spdlog::level::warn);

    // ── GLFW init ──────────────────────────────────────────────────────────
    if (!glfwInit()) {
        fprintf(stderr, "Failed to initialize GLFW\n");
        return 1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_TRUE);

    GLFWwindow* window = glfwCreateWindow(1400, 900,
        "System Monitor Dashboard", nullptr, nullptr);
    if (!window) {
        fprintf(stderr, "Failed to create GLFW window\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);  // vsync

    // ── ImGui init ─────────────────────────────────────────────────────────
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Load a nicer font (ImGui default is very plain)
    io.Fonts->AddFontFromFileTTF("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 16.0f);

    applyDarkTheme();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

    // ── Data source (double-buffer: lock-free swap between poller & renderer) ─
    // The poller owns a persistent DashboardData (with DB connection and rolling
    // buffers).  After each poll it copies the snapshot into buffers[write_idx],
    // then swaps the index atomically.  The renderer reads from the other buffer.
    // No mutex needed — single producer, single consumer.
    std::array<DashboardData, 2> buffers{DashboardData(db_path), DashboardData(db_path)};
    std::atomic<int> read_idx{0};
    std::atomic<bool> run_poller{true};
    std::atomic<bool> data_ready{false};

    std::thread poller([&]() {
        DashboardData local_data(db_path);   // persistent working copy
        int wi = 1;                           // start writing to buffer[1]
        while (run_poller) {
            local_data.poll();
            buffers[wi] = local_data;         // copy snapshot into publish buffer
            // Publish: make the freshly written buffer available to the renderer.
            read_idx.store(wi, std::memory_order_release);
            data_ready.store(true, std::memory_order_release);
            wi = 1 - wi;                      // alternate write target
            std::this_thread::sleep_for(std::chrono::milliseconds(POLL_INTERVAL_MS));
        }
    });

    const DashboardData* render_data = &buffers[0];

    // ── Main loop ──────────────────────────────────────────────────────────
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        // ── Grab fresh data if available ───────────────────────────────────
        if (data_ready.load(std::memory_order_acquire)) {
            render_data = &buffers[read_idx.load(std::memory_order_acquire)];
            data_ready.store(false, std::memory_order_relaxed);
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // Full-window dockspace
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2((float)display_w, (float)display_h));
        ImGui::Begin("##MainWindow", nullptr,
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

        // ── Header bar ─────────────────────────────────────────────────────
        {
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentCyan);
            ImGui::Text("> SYSTEM MONITOR");
            ImGui::PopStyleColor();

            ImGui::SameLine();
            if (g_is_stressing) {
                ImGui::BeginDisabled();
                ImGui::Button("Stressing CPU...");
                ImGui::EndDisabled();
            } else {
                if (ImGui::Button("Simulate CPU Load")) {
                    startStressTest();
                }
            }

            ImGui::SameLine();
            if (ImGui::Button("Export Data")) {
                exportDataToCSV(render_data->processes);
            }
            ImGui::SameLine();
            if (ImGui::Button("Export Reports")) {
                exportReportsToTXT(render_data->analysis_events);
            }

            ImGui::SameLine(ImGui::GetContentRegionAvail().x - 280);

            // Risk score badge
            ImVec4 risk_col = render_data->risk_score < RISK_LOW_THRESHOLD ? kAccentGreen :
                              render_data->risk_score < RISK_MED_THRESHOLD ? kAccentOrange : kAccentRed;
            ImGui::PushStyleColor(ImGuiCol_Text, risk_col);
            ImGui::Text("RISK: %.0f/100", render_data->risk_score);
            ImGui::PopStyleColor();

            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();

            // Quick stats
            if (!render_data->cpu_total.empty()) {
                ImGui::Text("CPU: %.0f%%", render_data->cpu_total.back());
            }
            ImGui::SameLine();
            if (!render_data->mem_usage.empty()) {
                ImGui::Text("RAM: %.0f%%", render_data->mem_usage.back());
            }

            ImGui::Separator();
        }

        ImVec2 avail = ImGui::GetContentRegionAvail();
        float panel_w = avail.x;
        float half_w = panel_w * 0.5f - 5.0f;
        float third_w = panel_w * 0.333f - 7.0f;

        // Proportional row heights (header already consumed some space)
        float row1_h = avail.y * 0.28f;
        float row2_h = avail.y * 0.25f;
        float row3_h = avail.y * 0.22f;
        // Row 4 (processes) gets all remaining space via (0)

        // ── Row 1: CPU Graph + Memory Gauge ────────────────────────────────
        {
            ImGui::BeginChild("##CPUPanel", ImVec2(half_w, row1_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentCyan);
            ImGui::Text("> CPU USAGE");
            ImGui::PopStyleColor();

            if (ImPlot::BeginPlot("##CPUPlot", ImVec2(-1, ImGui::GetContentRegionAvail().y),
                    ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText)) {
                ImPlot::SetupAxes("", "%", ImPlotAxisFlags_NoTickLabels, 0);
                ImPlot::SetupAxesLimits(0, 120, 0, 105, ImPlotCond_Always);

                plotRolling("Total", render_data->cpu_total, 0, 100, kAccentCyan);

                // Per-core lines (semi-transparent)
                ImVec4 core_colors[] = {
                    kAccentGreen, kAccentOrange, kAccentPurple, kAccentPink,
                    ImVec4(0.4f, 0.7f, 1.0f, 0.6f), ImVec4(1.0f, 1.0f, 0.4f, 0.6f),
                    ImVec4(0.6f, 1.0f, 0.6f, 0.6f), ImVec4(1.0f, 0.6f, 1.0f, 0.6f)
                };
                for (size_t i = 0; i < render_data->cpu_cores.size() && i < MAX_CORE_DISPLAY; ++i) {
                    char label[16];
                    snprintf(label, sizeof(label), "Core %zu", i);
                    ImVec4 c = core_colors[i % 8];
                    c.w = 0.4f;
                    plotRolling(label, render_data->cpu_cores[i], 0, 100, c);
                }

                ImPlot::EndPlot();
            }
            ImGui::EndChild();

            ImGui::SameLine();

            // Memory panel
            ImGui::BeginChild("##MemPanel", ImVec2(-1, row1_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentGreen);
            ImGui::Text("> MEMORY USAGE");
            ImGui::PopStyleColor();

            if (ImPlot::BeginPlot("##MemPlot", ImVec2(-1, ImGui::GetContentRegionAvail().y - 45),
                    ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText)) {
                ImPlot::SetupAxes("", "%", ImPlotAxisFlags_NoTickLabels, 0);
                ImPlot::SetupAxesLimits(0, 120, 0, 105, ImPlotCond_Always);

                // Shade under the line for visual impact
                if (!render_data->mem_usage.empty()) {
                    std::vector<double> xs(render_data->mem_usage.data.size());
                    std::vector<double> ys(render_data->mem_usage.data.begin(), render_data->mem_usage.data.end());
                    std::vector<double> zeros(xs.size(), 0.0);
                    for (size_t i = 0; i < xs.size(); ++i) xs[i] = (double)i;

                    ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(0.18f, 0.84f, 0.45f, 0.2f));
                    ImPlot::PlotShaded("##shade", xs.data(), ys.data(), zeros.data(), (int)xs.size());
                    ImPlot::PopStyleColor();

                    ImPlot::SetNextLineStyle(kAccentGreen, 2.0f);
                    ImPlot::PlotLine("RAM%", xs.data(), ys.data(), (int)xs.size());
                }

                ImPlot::EndPlot();
            }

            // Memory numbers
            if (!render_data->mem_used_gb.empty()) {
                ImGui::Text("Used: %.1f / %.1f GB  (%.1f%%)",
                    render_data->mem_used_gb.back(), render_data->mem_total_gb.back(),
                    render_data->mem_usage.back());

                // Progress bar
                float frac = (float)(render_data->mem_usage.back() / 100.0);
                ImVec4 bar_col = frac < 0.7f ? kAccentGreen :
                                 frac < 0.9f ? kAccentOrange : kAccentRed;
                ImGui::PushStyleColor(ImGuiCol_PlotHistogram, bar_col);
                ImGui::ProgressBar(frac, ImVec2(-1, 18), "");
                ImGui::PopStyleColor();
            }

            ImGui::EndChild();
        }

        // ── Row 2: Network + Per-Core Bars + Risk ──────────────────────────
        {
            // Network throughput
            ImGui::BeginChild("##NetPanel", ImVec2(third_w, row2_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentOrange);
            ImGui::Text("> NETWORK");
            ImGui::PopStyleColor();

            if (ImPlot::BeginPlot("##NetPlot", ImVec2(-1, ImGui::GetContentRegionAvail().y),
                    ImPlotFlags_NoMouseText)) {
                ImPlot::SetupAxes("", "kbps", ImPlotAxisFlags_NoTickLabels, 0);
                ImPlot::SetupAxisLimits(ImAxis_Y1, 0,
                    std::max(100.0, std::max(
                        render_data->net_rx.empty() ? 0.0 : *std::max_element(render_data->net_rx.data.begin(), render_data->net_rx.data.end()),
                        render_data->net_tx.empty() ? 0.0 : *std::max_element(render_data->net_tx.data.begin(), render_data->net_tx.data.end())
                    ) * 1.2),
                    ImPlotCond_Always);
                ImPlot::SetupAxisLimits(ImAxis_X1, 0, 120, ImPlotCond_Always);
                ImPlot::SetupLegend(ImPlotLocation_NorthEast);

                plotRolling("RX", render_data->net_rx, 0, 0, kAccentCyan);
                plotRolling("TX", render_data->net_tx, 0, 0, kAccentOrange);

                ImPlot::EndPlot();
            }
            ImGui::EndChild();

            ImGui::SameLine();

            // Per-core bar chart
            ImGui::BeginChild("##CoreBars", ImVec2(third_w, row2_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentPurple);
            ImGui::Text("> PER-CORE CPU");
            ImGui::PopStyleColor();

            if (!render_data->cpu_cores.empty() &&
                ImPlot::BeginPlot("##CoreBarPlot", ImVec2(-1, ImGui::GetContentRegionAvail().y),
                    ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText)) {
                ImPlot::SetupAxes("Core", "%", 0, 0);
                ImPlot::SetupAxesLimits(-0.5, (double)render_data->cpu_cores.size() - 0.5, 0, 105, ImPlotCond_Always);

                std::vector<double> positions(render_data->cpu_cores.size());
                std::vector<double> values(render_data->cpu_cores.size());
                for (size_t i = 0; i < render_data->cpu_cores.size(); ++i) {
                    positions[i] = (double)i;
                    values[i] = render_data->cpu_cores[i].back();
                }

                ImPlot::PushStyleColor(ImPlotCol_Fill, kAccentPurple);
                ImPlot::PlotBars("Cores", positions.data(), values.data(),
                                 (int)values.size(), 0.6);
                ImPlot::PopStyleColor();

                ImPlot::EndPlot();
            }
            ImGui::EndChild();

            ImGui::SameLine();

            // Anomaly summary
            ImGui::BeginChild("##AnomalySum", ImVec2(-1, row2_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentRed);
            ImGui::Text("> RISK & ANOMALIES");
            ImGui::PopStyleColor();

            // Big risk number
            ImVec4 risk_col = render_data->risk_score < RISK_LOW_THRESHOLD ? kAccentGreen :
                              render_data->risk_score < RISK_MED_THRESHOLD ? kAccentOrange : kAccentRed;
            ImGui::PushStyleColor(ImGuiCol_Text, risk_col);
            ImGui::SetWindowFontScale(2.5f);
            ImGui::Text("%.0f", render_data->risk_score);
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextDisabled("/ 100");

            ImGui::Spacing();
            ImGui::Text("Total anomalies: %zu", render_data->anomalies.size());

            // Recent anomalies list
            ImGui::Spacing();
            for (size_t i = 0; i < std::min(render_data->anomalies.size(), (size_t)5); ++i) {
                auto& a = render_data->anomalies[i];
                ImGui::PushStyleColor(ImGuiCol_Text, severityColor(a.severity));
                ImGui::BulletText("[%s] %.1f", a.type.c_str(), a.risk_score);
                ImGui::PopStyleColor();
            }

            ImGui::EndChild();
        }

        // ── Row 3: Analysis Explanations + Incident Timeline ───────────────
        {
            float analysis_w = panel_w * 0.55f - 5.0f;
            float r3_h = row3_h;

            // ── Analysis Explanation Panel ─────────────────────────────────
            ImGui::BeginChild("##AnalysisPanel", ImVec2(analysis_w, r3_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentCyan);
            ImGui::Text("> ANALYSIS REPORTS");
            ImGui::PopStyleColor();

            if (render_data->analysis_events.empty()) {
                ImGui::TextDisabled("No analysis events yet — waiting for anomalies...");
            } else {
                for (size_t i = 0; i < std::min(render_data->analysis_events.size(), (size_t)5); ++i) {
                    auto& ev = render_data->analysis_events[i];
                    char ts_buf[16];
                    formatTimestamp(ev.timestamp, ts_buf, sizeof(ts_buf));

                    ImGui::PushStyleColor(ImGuiCol_Text, riskColor(ev.risk_total));
                    ImGui::Text("%s  Risk: %.0f", ts_buf, ev.risk_total);
                    ImGui::PopStyleColor();

                    ImGui::SameLine();
                    ImGui::TextDisabled("(%d anomalies, %d patterns)",
                                        ev.anomaly_count, ev.pattern_count);

                    // Show explanation text (truncate long lines)
                    if (!ev.explanation.empty()) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.75f, 1.0f));
                        ImGui::Indent(12.0f);
                        // Show first 3 lines of explanation
                        std::string expl = ev.explanation;
                        int lines_shown = 0;
                        size_t pos = 0;
                        while (pos < expl.size() && lines_shown < 3) {
                            size_t nl = expl.find('\n', pos);
                            if (nl == std::string::npos) nl = expl.size();
                            std::string line = expl.substr(pos, nl - pos);
                            if (!line.empty()) {
                                ImGui::TextWrapped("%s", line.c_str());
                                lines_shown++;
                            }
                            pos = nl + 1;
                        }
                        ImGui::Unindent(12.0f);
                        ImGui::PopStyleColor();
                    }
                    ImGui::Spacing();
                    if (i < std::min(render_data->analysis_events.size(), (size_t)5) - 1) {
                        ImGui::Separator();
                    }
                }
            }
            ImGui::EndChild();

            ImGui::SameLine();

            // ── Incident Timeline Panel ───────────────────────────────────
            ImGui::BeginChild("##IncidentPanel", ImVec2(-1, r3_h), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentPink);
            ImGui::Text("> INCIDENT TIMELINE");
            ImGui::PopStyleColor();

            if (render_data->incidents.empty()) {
                ImGui::TextDisabled("No incidents recorded yet.");
            } else {
                for (auto& inc : render_data->incidents) {
                    char start_buf[16], end_buf[16];
                    formatTimestamp(inc.start_time, start_buf, sizeof(start_buf));

                    ImVec4 status_col = inc.is_active ? kAccentRed : kAccentGreen;
                    const char* status_text = inc.is_active ? "ACTIVE" : "RESOLVED";

                    ImGui::PushStyleColor(ImGuiCol_Text, status_col);
                    ImGui::Text("* %s", status_text);
                    ImGui::PopStyleColor();
                    ImGui::SameLine();

                    if (inc.is_active) {
                        ImGui::Text("#%lld  Started %s  (%d events)",
                                    (long long)inc.id, start_buf, inc.event_count);
                    } else {
                        formatTimestamp(inc.end_time, end_buf, sizeof(end_buf));
                        ImGui::Text("#%lld  %s → %s  (%d events)",
                                    (long long)inc.id, start_buf, end_buf, inc.event_count);
                    }

                    // Risk bar
                    float frac = (float)(inc.peak_risk / 100.0);
                    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, riskColor(inc.peak_risk));
                    char overlay[32];
                    snprintf(overlay, sizeof(overlay), "Peak: %.0f", inc.peak_risk);
                    ImGui::ProgressBar(frac, ImVec2(-1, 14), overlay);
                    ImGui::PopStyleColor();

                    if (!inc.summary.empty()) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.6f, 0.6f, 0.65f, 1.0f));
                        ImGui::TextWrapped("  %s", inc.summary.c_str());
                        ImGui::PopStyleColor();
                    }
                    ImGui::Spacing();
                }
            }
            ImGui::EndChild();
        }

        // ── Row 4: Process Table ───────────────────────────────────────────
        {
            ImGui::BeginChild("##ProcPanel", ImVec2(-1, 0), true);
            ImGui::PushStyleColor(ImGuiCol_Text, kAccentPink);
            ImGui::Text("> TOP PROCESSES (%zu)", render_data->processes.size());
            ImGui::PopStyleColor();

            if (ImGui::BeginTable("##ProcTable", 6,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY |
                    ImGuiTableFlags_SizingStretchProp,
                    ImVec2(-1, -1))) {

                ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_DefaultSort, 60);
                ImGui::TableSetupColumn("Name", 0, 200);
                ImGui::TableSetupColumn("User", 0, 100);
                ImGui::TableSetupColumn("State", 0, 50);
                ImGui::TableSetupColumn("CPU%", ImGuiTableColumnFlags_DefaultSort |
                    ImGuiTableColumnFlags_PreferSortDescending, 80);
                ImGui::TableSetupColumn("MEM%", 0, 80);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();

                // Handle sorting (local copy since render_data is const)
                static std::vector<ProcEntry> sorted_procs;
                sorted_procs = render_data->processes;
                if (ImGuiTableSortSpecs* sort_specs = ImGui::TableGetSortSpecs()) {
                    if (sort_specs->SpecsCount > 0) {
                        auto& spec = sort_specs->Specs[0];
                        bool ascending = (spec.SortDirection == ImGuiSortDirection_Ascending);
                        std::sort(sorted_procs.begin(), sorted_procs.end(),
                            [&](const ProcEntry& a, const ProcEntry& b) {
                                switch (spec.ColumnIndex) {
                                    case 0: return ascending ? a.pid < b.pid : a.pid > b.pid;
                                    case 1: return ascending ? a.name < b.name : a.name > b.name;
                                    case 2: return ascending ? a.user < b.user : a.user > b.user;
                                    case 3: return ascending ? a.state < b.state : a.state > b.state;
                                    case 4: return ascending ? a.cpu_percent < b.cpu_percent : a.cpu_percent > b.cpu_percent;
                                    case 5: return ascending ? a.mem_percent < b.mem_percent : a.mem_percent > b.mem_percent;
                                    default: return false;
                                }
                            });
                    }
                    sort_specs->SpecsDirty = false;
                }

                for (const auto& p : sorted_procs) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%d", p.pid);
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(p.name.c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(p.user.c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(p.state.c_str());
                    ImGui::TableSetColumnIndex(4);
                    if (p.cpu_percent > 5.0) ImGui::PushStyleColor(ImGuiCol_Text, kAccentOrange);
                    else if (p.cpu_percent > 20.0) ImGui::PushStyleColor(ImGuiCol_Text, kAccentRed);
                    else ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_Text));
                    ImGui::Text("%.1f", p.cpu_percent);
                    ImGui::PopStyleColor();
                    ImGui::TableSetColumnIndex(5);
                    ImGui::Text("%.1f", p.mem_percent);
                }

                ImGui::EndTable();
            }
            ImGui::EndChild();
        }

        ImGui::End();  // MainWindow

        // ── Render ─────────────────────────────────────────────────────────
        ImGui::Render();
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.06f, 0.06f, 0.08f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    // ── Cleanup ────────────────────────────────────────────────────────────
    run_poller = false;
    if (poller.joinable()) poller.join();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
