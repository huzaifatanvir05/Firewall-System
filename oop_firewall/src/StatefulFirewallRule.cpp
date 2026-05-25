#include "StatefulFirewallRule.h"

StatefulFirewallRule::StatefulFirewallRule()
    : FirewallRule(), connectionTimeout(60) {}

StatefulFirewallRule::StatefulFirewallRule(const std::string& id,
                                           const std::string& protocol,
                                           int port,
                                           const std::string& srcIp,
                                           const std::string& dstIp,
                                           RuleAction action,
                                           int priority,
                                           RuleDirection dir,
                                           int connTimeout)
    : FirewallRule(id, protocol, port, srcIp, dstIp, action, priority, dir),
      connectionTimeout(connTimeout) {}

bool StatefulFirewallRule::validateConnectionState(bool isEstablished) const {
    // If connection is already established, allow reply packets regardless
    if (isEstablished) return true;
    // New connection — must pass normal rule evaluation
    return false;
}

bool StatefulFirewallRule::evaluatePacket(const std::string& srcIp,
                                          const std::string& dstIp,
                                          const std::string& protocol,
                                          int port) const {
    // Stateful: established connections always pass
    // (caller checks ConnectionTracker first and passes isEstablished)
    return FirewallRule::evaluatePacket(srcIp, dstIp, protocol, port);
}
