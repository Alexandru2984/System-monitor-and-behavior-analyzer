#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// collectors/network_collector.h
// ─────────────────────────────────────────────────────────────────────────────
// Reads /proc/net/dev to get per-interface network statistics.
//
// /proc/net/dev format (first 2 lines are headers):
//   Inter-|   Receive                                                |  Transmit
//    face |bytes    packets errs drop fifo frame compressed multicast|bytes ...
//       lo:  123456   789 ...
//     eth0:  999999   111 ...
//
// We parse rx_bytes, tx_bytes, rx_packets, tx_packets and compute
// rates (kbps) as deltas from the previous sample.
// ─────────────────────────────────────────────────────────────────────────────

#include "collectors/collector.h"
#include <unordered_map>

namespace sysmon {

class NetworkCollector : public ICollector {
public:
    MetricSnapshot collect() override;
    std::string name() const override { return "NetworkCollector"; }

private:
    struct PrevSample {
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        int64_t  timestamp = 0;
    };
    std::unordered_map<std::string, PrevSample> prev_;
};

} // namespace sysmon
