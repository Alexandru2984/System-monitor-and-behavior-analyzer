// ─────────────────────────────────────────────────────────────────────────────
// collectors/process_collector.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/process_collector.h"
#include "utils/logger.h"

#include <chrono>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <pwd.h>
#include <sstream>
#include <unistd.h>

namespace sysmon {

// Helper: get clock ticks per second (typically 100 on Linux)
static long clockTicksPerSec() {
    static long ticks = sysconf(_SC_CLK_TCK);
    return ticks;
}

// Helper: total system RAM in KB (for computing per-process mem%)
static uint64_t totalMemoryKb() {
    std::ifstream f("/proc/meminfo");
    std::string key;
    uint64_t val = 0;
    f >> key >> val;  // "MemTotal: NNNNN"
    return val;
}

// Helper: resolve UID to username (cached)
static std::string uidToUser(uid_t uid) {
    struct passwd* pw = getpwuid(uid);
    return pw ? pw->pw_name : std::to_string(uid);
}

MetricSnapshot ProcessCollector::collect() {
    ProcessSnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::unordered_map<int, ProcTimes> new_times;

    uint64_t total_mem_kb = totalMemoryKb();
    long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        LOG_ERROR("Cannot open /proc");
        return snap;
    }

    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Only numeric directories (PIDs)
        if (entry->d_type != DT_DIR) continue;
        char* end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0) continue;

        // ── Read /proc/[pid]/stat ──────────────────────────────────────────
        // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags
        //         minflt cminflt majflt cmajflt utime stime ...
        std::string stat_path = "/proc/" + std::string(entry->d_name) + "/stat";
        std::ifstream stat_file(stat_path);
        if (!stat_file.is_open()) continue;  // process already exited

        std::string stat_line;
        std::getline(stat_file, stat_line);

        // The comm field can contain spaces and parentheses, so we find the
        // last ')' to split reliably.
        auto comm_start = stat_line.find('(');
        auto comm_end   = stat_line.rfind(')');
        if (comm_start == std::string::npos || comm_end == std::string::npos)
            continue;

        std::string proc_name = stat_line.substr(comm_start + 1,
                                                  comm_end - comm_start - 1);

        // Fields after the closing ')': state is field index 2 (0-based after ')')
        std::istringstream after_comm(stat_line.substr(comm_end + 2));
        std::string state;
        after_comm >> state;

        // Skip fields 3–12 to reach utime (field 13) and stime (field 14)
        // (0-indexed after state; we need to skip 10 more fields)
        std::string skip;
        for (int i = 0; i < 10; ++i) after_comm >> skip;

        long utime = 0, stime = 0;
        after_comm >> utime >> stime;

        // ── Read /proc/[pid]/statm for RSS ─────────────────────────────────
        std::string statm_path = "/proc/" + std::string(entry->d_name) + "/statm";
        std::ifstream statm_file(statm_path);
        long size_pages = 0, rss_pages = 0;
        if (statm_file.is_open()) {
            statm_file >> size_pages >> rss_pages;
        }

        // Skip kernel threads: they have zero RSS (no user-space memory).
        // This filters out kthreadd, kworker/*, ksoftirqd, etc.
        if (rss_pages == 0) continue;

        // ── Read UID from /proc/[pid]/status ───────────────────────────────
        std::string status_path = "/proc/" + std::string(entry->d_name) + "/status";
        std::ifstream status_file(status_path);
        std::string user = "?";
        if (status_file.is_open()) {
            std::string line;
            while (std::getline(status_file, line)) {
                if (line.compare(0, 4, "Uid:") == 0) {
                    std::istringstream uid_ss(line.substr(4));
                    uid_t uid;
                    uid_ss >> uid;
                    user = uidToUser(uid);
                    break;
                }
            }
        }

        // ── Compute CPU% (delta from previous sample) ──────────────────────
        double cpu_pct = 0.0;
        int ipid = static_cast<int>(pid);
        auto it = prev_times_.find(ipid);
        if (it != prev_times_.end()) {
            long delta_cpu  = (utime + stime) - (it->second.utime + it->second.stime);
            long delta_time_ms = snap.timestamp - it->second.timestamp;
            if (delta_time_ms > 0) {
                // delta_cpu is in clock ticks; convert to ms, then to percent
                double delta_cpu_ms = (static_cast<double>(delta_cpu) /
                                       static_cast<double>(clockTicksPerSec())) * 1000.0;
                cpu_pct = (delta_cpu_ms / static_cast<double>(delta_time_ms)) * 100.0;
            }
        }
        new_times[ipid] = {utime, stime, snap.timestamp};

        // ── Compute memory% ────────────────────────────────────────────────
        double mem_pct = 0.0;
        if (total_mem_kb > 0) {
            uint64_t rss_kb = static_cast<uint64_t>(rss_pages) *
                              static_cast<uint64_t>(page_size_kb);
            mem_pct = (static_cast<double>(rss_kb) /
                       static_cast<double>(total_mem_kb)) * 100.0;
        }

        snap.processes.push_back(ProcessInfo{
            .pid = ipid,
            .name = std::move(proc_name),
            .state = state,
            .user = std::move(user),
            .cpu_percent = cpu_pct,
            .mem_percent = mem_pct
        });
    }

    closedir(proc_dir);
    
    prev_times_ = std::move(new_times);

    LOG_DEBUG("Processes: {} total", snap.processes.size());
    return snap;
}

} // namespace sysmon
