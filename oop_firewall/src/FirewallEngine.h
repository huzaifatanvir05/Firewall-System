#pragma once
#include "SecurityComponent.h"
#include "FirewallRule.h"
#include "StatefulFirewallRule.h"
#include "ConnectionTracker.h"
#include "FirewallStatistics.h"
#include "LogManager.h"
#include "NetworkPacket.h"
#include "WindowsFirewallManager.h"
#include <vector>
#include <memory>
#include <mutex>
#include <set>

class FirewallEngine : public SecurityComponent {
private:
    std::vector<std::shared_ptr<FirewallRule>> ruleSet;
    ConnectionTracker     connectionTracker;
    FirewallStatistics    statistics;
    LogManager&           logManager;
    WindowsFirewallManager winFirewall;
    mutable std::mutex    mtx;
    std::set<std::string> blockedIps;   // already pushed to Windows FW

public:
    explicit FirewallEngine(LogManager& lm);
    ~FirewallEngine() = default;

    // SecurityComponent
    bool initialize() override;
    void shutdown()   override;

    // Rule management
    void addRule   (std::shared_ptr<FirewallRule> rule);
    void removeRule(const std::string& ruleId);
    void sortRulesByPriority();

    // Core processing — called per packet
    bool processPacket      (const NetworkPacket& pkt);
    bool isPacketAllowed    (const NetworkPacket& pkt) const;

    // Statistics / display
    void displayStatistics  () const;
    void displayRules       () const;
    void displayConnections() const;

    // Helpers
    FirewallStatistics& getStatistics() { return statistics; }
    ConnectionTracker&  getConnectionTracker() { return connectionTracker; }

private:
    // Push block to Windows Firewall (idempotent)
    void enforceBlock(const std::string& srcIp, const std::string& ruleId);
    void logPacket   (const NetworkPacket& pkt, bool allowed, const std::string& reason);
};
