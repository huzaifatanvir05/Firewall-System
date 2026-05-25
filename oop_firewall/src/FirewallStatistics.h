#pragma once
#include <string>
#include <atomic>

class FirewallStatistics {
private:
    std::atomic<int> totalPackets   {0};
    std::atomic<int> allowedPackets {0};
    std::atomic<int> blockedPackets {0};

public:
    FirewallStatistics() = default;

    void updateStatistics(bool allowed);
    void reset();

    int getTotalPackets()   const { return totalPackets.load();   }
    int getAllowedPackets()  const { return allowedPackets.load(); }
    int getBlockedPackets() const { return blockedPackets.load(); }

    std::string displayStatistics() const;
};
