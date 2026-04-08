// ─────────────────────────────────────────────────────────────────────────────
// collectors/network_collector.cpp
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/network_collector.h"
#include "utils/logger.h"

#include <chrono>
#include <fstream>
#include <sstream>

namespace sysmon {

MetricSnapshot NetworkCollector::collect() {
    NetworkSnapshot snap;
    snap.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    std::ifstream netdev("/proc/net/dev");
    if (!netdev.is_open()) {
        LOG_ERROR("Cannot open /proc/net/dev");
        return snap;
    }

    std::string line;
    // Skip the 2 header lines
    std::getline(netdev, line);
    std::getline(netdev, line);

    while (std::getline(netdev, line)) {
        // Line looks like: "  eth0: 123456 789 0 0 0 0 0 0 654321 456 0 0 0 0 0 0"
        auto colon_pos = line.find(':');
        if (colon_pos == std::string::npos) continue;

        // Extract interface name (trim whitespace)
        std::string iface = line.substr(0, colon_pos);
        auto start = iface.find_first_not_of(" \t");
        if (start != std::string::npos) iface = iface.substr(start);

        // Parse the 16 numeric fields after the colon
        // Fields: rx_bytes rx_packets rx_errs rx_drop rx_fifo rx_frame
        //         rx_compressed rx_multicast
        //         tx_bytes tx_packets tx_errs tx_drop tx_fifo tx_colls
        //         tx_carrier tx_compressed
        std::istringstream iss(line.substr(colon_pos + 1));
        uint64_t rx_bytes, rx_packets, rx_errs, rx_drop, rx_fifo, rx_frame,
                 rx_compressed, rx_multicast;
        uint64_t tx_bytes, tx_packets;

        iss >> rx_bytes >> rx_packets >> rx_errs >> rx_drop >> rx_fifo
            >> rx_frame >> rx_compressed >> rx_multicast
            >> tx_bytes >> tx_packets;

        // Compute rates from delta
        double rx_rate = 0.0, tx_rate = 0.0;
        auto it = prev_.find(iface);
        if (it != prev_.end() && snap.timestamp > it->second.timestamp) {
            double dt_sec = static_cast<double>(snap.timestamp - it->second.timestamp) / 1000.0;
            // bytes → kilobits: (bytes * 8) / 1000 / dt_sec
            rx_rate = static_cast<double>(rx_bytes - it->second.rx_bytes) * 8.0 / 1000.0 / dt_sec;
            tx_rate = static_cast<double>(tx_bytes - it->second.tx_bytes) * 8.0 / 1000.0 / dt_sec;
        }
        prev_[iface] = {rx_bytes, tx_bytes, snap.timestamp};

        snap.interfaces.push_back(InterfaceStats{
            .name = iface,
            .rx_bytes = rx_bytes,
            .tx_bytes = tx_bytes,
            .rx_packets = rx_packets,
            .tx_packets = tx_packets,
            .rx_rate_kbps = rx_rate,
            .tx_rate_kbps = tx_rate
        });
    }

    LOG_DEBUG("Network: {} interfaces", snap.interfaces.size());
    return snap;
}

} // namespace sysmon
