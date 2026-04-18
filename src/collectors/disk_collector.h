#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// collectors/disk_collector.h — Disk I/O statistics from /proc/diskstats
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"
#include <map>
#include <string>

namespace sysmon {

class DiskCollector : public ICollector {
public:
    MetricSnapshot collect() override;
    std::string name() const override { return "DiskCollector"; }

private:
    struct PrevStats {
        uint64_t reads_completed = 0;
        uint64_t writes_completed = 0;
        uint64_t sectors_read = 0;
        uint64_t sectors_written = 0;
        uint64_t io_ticks = 0;       // time doing I/O (ms)
        int64_t  timestamp = 0;
    };

    std::map<std::string, PrevStats> prev_;
    bool has_prev_ = false;

    // Skip partitions — only report whole disks (sda, nvme0n1, etc.)
    static bool isWholeDisk(const std::string& name);
};

} // namespace sysmon
