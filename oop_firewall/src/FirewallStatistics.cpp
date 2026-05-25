#include "FirewallStatistics.h"
#include <sstream>

void FirewallStatistics::updateStatistics(bool allowed) {
    ++totalPackets;
    if (allowed) ++allowedPackets;
    else         ++blockedPackets;
}

void FirewallStatistics::reset() {
    totalPackets   = 0;
    allowedPackets = 0;
    blockedPackets = 0;
}

std::string FirewallStatistics::displayStatistics() const {
    std::ostringstream oss;
    oss << "=== Firewall Statistics ===\n"
        << "  Total   packets : " << totalPackets   << "\n"
        << "  Allowed packets : " << allowedPackets << "\n"
        << "  Blocked packets : " << blockedPackets << "\n"
        << "===========================";
    return oss.str();
}
