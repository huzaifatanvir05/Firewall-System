#include "FirewallRule.h"
#include <sstream>
#include <algorithm>

FirewallRule::FirewallRule()
    : ruleId(""), protocolType("ANY"), portNumber(-1),
      sourceIpAddress("*"), targetIpAddress("*"), targetMacAddress(""),
      actionType("ALLOW"), priority(100), direction(RuleDirection::BOTH) {}

FirewallRule::FirewallRule(const std::string& id,
                           const std::string& protocol,
                           int port,
                           const std::string& srcIp,
                           const std::string& dstIp,
                           RuleAction action,
                           int prio,
                           RuleDirection dir)
    : ruleId(id), protocolType(protocol), portNumber(port),
      sourceIpAddress(srcIp), targetIpAddress(dstIp), targetMacAddress(""),
      actionType(action == RuleAction::BLOCK ? "BLOCK" : "ALLOW"),
      priority(prio), direction(dir) {}

// ── Core matching ─────────────────────────────────────────────────────────────
bool FirewallRule::matchesIp(const std::string& ip) const {
    if (sourceIpAddress == "*" || sourceIpAddress == "ANY" || sourceIpAddress.empty())
        return true;
    return sourceIpAddress == ip;
}

bool FirewallRule::matchesPort(int port) const {
    if (portNumber == -1) return true;   // wildcard
    return portNumber == port;
}

bool FirewallRule::evaluatePacket(const std::string& srcIp,
                                  const std::string& dstIp,
                                  const std::string& protocol,
                                  int port) const {
    // Protocol check
    if (protocolType != "ANY" && protocolType != protocol) return false;

    // Source IP check
    if (!matchesIp(srcIp)) return false;

    // Destination IP check
    if (targetIpAddress != "*" && targetIpAddress != "ANY" &&
        !targetIpAddress.empty() && targetIpAddress != dstIp) return false;

    // Port check
    if (!matchesPort(port)) return false;

    return true;
}

std::string FirewallRule::toString() const {
    std::ostringstream oss;
    oss << "[Rule " << ruleId << "] "
        << actionType << " "
        << protocolType << " "
        << sourceIpAddress << " -> " << targetIpAddress
        << " port=" << (portNumber == -1 ? "*" : std::to_string(portNumber))
        << " prio=" << priority;
    return oss.str();
}
