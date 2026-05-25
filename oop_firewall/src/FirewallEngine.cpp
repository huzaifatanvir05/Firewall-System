#include "FirewallEngine.h"
#include "DateTimeUtility.h"
#include <iostream>
#include <algorithm>

FirewallEngine::FirewallEngine(LogManager& lm) : logManager(lm) {}

// ── Lifecycle ─────────────────────────────────────────────────────────────────
bool FirewallEngine::initialize() {
    winFirewall.initialize();
    std::cout << "[FirewallEngine] Initialized.\n";

    // Load any persisted rules from rules/ directory (future extension)
    return true;
}

void FirewallEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mtx);
    std::cout << "[FirewallEngine] Shutdown.\n";
    statistics.displayStatistics();
    winFirewall.shutdown();
}

// ── Rule management ──────────────────────────────────────────────────────────
void FirewallEngine::addRule(std::shared_ptr<FirewallRule> rule) {
    std::lock_guard<std::mutex> lock(mtx);
    ruleSet.push_back(rule);
    sortRulesByPriority();
    std::cout << "[FirewallEngine] Rule added: " << rule->toString() << "\n";
}

void FirewallEngine::removeRule(const std::string& ruleId) {
    std::lock_guard<std::mutex> lock(mtx);
    ruleSet.erase(
        std::remove_if(ruleSet.begin(), ruleSet.end(),
            [&](const std::shared_ptr<FirewallRule>& r) {
                return r->getRuleId() == ruleId;
            }),
        ruleSet.end());
}

void FirewallEngine::sortRulesByPriority() {
    std::sort(ruleSet.begin(), ruleSet.end(),
        [](const std::shared_ptr<FirewallRule>& a,
           const std::shared_ptr<FirewallRule>& b) {
            return a->getPriority() < b->getPriority();
        });
}

// ── Packet evaluation (const, no side-effects) ───────────────────────────────
bool FirewallEngine::isPacketAllowed(const NetworkPacket& pkt) const {
    const std::string srcIp   = pkt.getSourceAddress().getIpAddress();
    const std::string dstIp   = pkt.getDestinationAddress().getIpAddress();
    const std::string proto   = pkt.getProtocolType();
    int               dstPort = pkt.getDestinationPort();

    // Check stateful: established connection always passes
    ConnectionKey ck{ srcIp, dstIp, proto,
                      pkt.getSourcePort(), dstPort };
    if (connectionTracker.isExistingConnection(ck)) return true;

    // Walk rules in priority order (first match wins)
    for (const auto& rule : ruleSet) {
        if (rule->evaluatePacket(srcIp, dstIp, proto, dstPort)) {
            return !rule->isBlock();
        }
    }
    // Default: allow if no rule matches
    return true;
}

// ── Main processing entry point ───────────────────────────────────────────────
bool FirewallEngine::processPacket(const NetworkPacket& pkt) {
    const std::string srcIp   = pkt.getSourceAddress().getIpAddress();
    const std::string dstIp   = pkt.getDestinationAddress().getIpAddress();
    const std::string proto   = pkt.getProtocolType();
    int               dstPort = pkt.getDestinationPort();

    // Stateful check
    ConnectionKey ck{ srcIp, dstIp, proto,
                      pkt.getSourcePort(), dstPort };
    if (connectionTracker.isExistingConnection(ck)) {
        statistics.updateStatistics(true);
        // Don't re-log established connections (too noisy)
        return true;
    }

    // Rule evaluation
    std::string matchedRule = "DEFAULT_ALLOW";
    bool allowed = true;

    {
        std::lock_guard<std::mutex> lock(mtx);
        for (const auto& rule : ruleSet) {
            if (rule->evaluatePacket(srcIp, dstIp, proto, dstPort)) {
                allowed     = !rule->isBlock();
                matchedRule = rule->getRuleId();
                break;
            }
        }
    }

    statistics.updateStatistics(allowed);

    if (allowed) {
        // Register new connection for stateful tracking
        connectionTracker.addConnection(ck);
        logPacket(pkt, true, matchedRule);
    } else {
        logPacket(pkt, false, matchedRule);
        enforceBlock(srcIp, matchedRule);
    }

    return allowed;
}

// ── Block enforcement → Windows Firewall ─────────────────────────────────────
void FirewallEngine::enforceBlock(const std::string& srcIp,
                                   const std::string& ruleId) {
    if (blockedIps.count(srcIp)) return;  // already blocked
    blockedIps.insert(srcIp);

    std::cout << "[FirewallEngine] Pushing BLOCK to Windows Firewall: "
              << srcIp << " (rule=" << ruleId << ")\n";
    winFirewall.blockInboundIp(srcIp, "CPP_FW_" + ruleId + "_" + srcIp);
}

// ── Logging helper ────────────────────────────────────────────────────────────
void FirewallEngine::logPacket(const NetworkPacket& pkt,
                                bool allowed,
                                const std::string& reason) {
    FirewallLogEntry entry(
        DateTimeUtility::getCurrentTimestamp(),
        pkt.getSourceAddress().getIpAddress(),
        allowed ? "ALLOWED" : "BLOCKED",
        reason);

    logManager.addLogEntry(entry);

    // Console output
    std::cout << (allowed ? "\033[32m[ALLOW]\033[0m " : "\033[31m[BLOCK]\033[0m ")
              << pkt.displayPacketInfo() << " | rule=" << reason << "\n";
}

void FirewallEngine::displayStatistics() const {
    std::cout << statistics.displayStatistics() << "\n";
}

void FirewallEngine::displayConnections() const {
    std::cout << connectionTracker.dumpConnections();
}

void FirewallEngine::displayRules() const {
    std::lock_guard<std::mutex> lock(mtx);
    std::cout << "=== Firewall Rules (" << ruleSet.size() << ") ===\n";
    for (const auto& r : ruleSet)
        std::cout << "  " << r->toString() << "\n";
    std::cout << "=========================\n";
}
