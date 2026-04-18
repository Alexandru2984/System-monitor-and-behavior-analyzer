// ─────────────────────────────────────────────────────────────────────────────
// collectors/disk_collector.cpp — Disk I/O collector from /proc/diskstats
// ─────────────────────────────────────────────────────────────────────────────
//
// /proc/diskstats format (see kernel docs):
//   major minor name reads_completed reads_merged sectors_read read_ms
//   writes_completed writes_merged sectors_written write_ms io_in_progress
//   io_ticks weighted_io_ticks ...
//
// Sector size is assumed to be 512 bytes (standard for Linux block layer).
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/disk_collector.h"
#include "utils/logger.h"

#include <chrono>
#include <fstream>
#include <sstream>

namespace sysmon {

static constexpr double SECTOR_SIZE = 512.0;  // bytes

bool DiskCollector::isWholeDisk(const std::string& name) {
    // Whole disk patterns:
    //   sd[a-z]+      (SATA/SCSI: sda, sdb, ...)
    //   nvme[0-9]+n[0-9]+  (NVMe: nvme0n1, nvme1n1, ...)
    //   vd[a-z]+      (virtio: vda, vdb, ...)
    //
    // Partition patterns (skip):
    //   sda1, sda2, ...
    //   nvme0n1p1, nvme0n1p2, ...
    //   vda1, vda2, ...
    //
    // Also skip: loop, ram, dm- devices

    if (name.find("loop") == 0 || name.find("ram") == 0 || name.find("dm-") == 0) {
        return false;
    }

    // sd* or vd*: whole disk if last char is a letter
    if ((name.find("sd") == 0 || name.find("vd") == 0) && name.size() >= 3) {
        return std::isalpha(name.back());
    }

    // nvme*: whole disk if no 'p' after 'n' (nvme0n1 vs nvme0n1p1)
    if (name.find("nvme") == 0) {
        auto pos_n = name.find('n', 4);
        if (pos_n == std::string::npos) return false;
        return name.find('p', pos_n) == std::string::npos;
    }

    return false;
}

MetricSnapshot DiskCollector::collect() {
    DiskSnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    std::ifstream file("/proc/diskstats");
    if (!file.is_open()) {
        LOG_ERROR("DiskCollector: cannot open /proc/diskstats");
        return snap;
    }

    std::map<std::string, PrevStats> new_stats;
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);

        unsigned int major, minor;
        std::string dev_name;
        uint64_t reads_completed, reads_merged, sectors_read, read_ms;
        uint64_t writes_completed, writes_merged, sectors_written, write_ms;
        uint64_t io_in_progress, io_ticks, weighted_io_ticks;

        iss >> major >> minor >> dev_name
            >> reads_completed >> reads_merged >> sectors_read >> read_ms
            >> writes_completed >> writes_merged >> sectors_written >> write_ms
            >> io_in_progress >> io_ticks >> weighted_io_ticks;

        if (iss.fail()) continue;
        if (!isWholeDisk(dev_name)) continue;

        PrevStats current;
        current.reads_completed = reads_completed;
        current.writes_completed = writes_completed;
        current.sectors_read = sectors_read;
        current.sectors_written = sectors_written;
        current.io_ticks = io_ticks;
        current.timestamp = snap.timestamp;

        new_stats[dev_name] = current;

        if (has_prev_ && prev_.count(dev_name)) {
            auto& prev = prev_[dev_name];
            double dt_sec = (snap.timestamp - prev.timestamp) / 1000.0;
            if (dt_sec <= 0.0) continue;

            double delta_sectors_read = static_cast<double>(sectors_read - prev.sectors_read);
            double delta_sectors_write = static_cast<double>(sectors_written - prev.sectors_written);
            double delta_io_ticks = static_cast<double>(io_ticks - prev.io_ticks);

            DiskDeviceStats dev;
            dev.name = dev_name;
            dev.reads_completed = reads_completed - prev.reads_completed;
            dev.writes_completed = writes_completed - prev.writes_completed;
            dev.sectors_read = sectors_read;
            dev.sectors_written = sectors_written;

            // Rate in kbps: (sectors * 512 bytes) / (dt * 1024) = sectors * 0.5 / dt
            dev.read_rate_kbps = (delta_sectors_read * SECTOR_SIZE / 1024.0) / dt_sec;
            dev.write_rate_kbps = (delta_sectors_write * SECTOR_SIZE / 1024.0) / dt_sec;

            // I/O utilization: time spent doing I/O / wall-clock time * 100
            // io_ticks is in ms, dt is in seconds → delta_io_ticks / (dt_sec * 1000) * 100
            dev.io_util_percent = std::min(100.0, (delta_io_ticks / (dt_sec * 1000.0)) * 100.0);

            snap.devices.push_back(dev);
        }
    }

    prev_ = std::move(new_stats);
    has_prev_ = true;

    LOG_DEBUG("Disk: {} devices collected", snap.devices.size());
    return snap;
}

} // namespace sysmon
