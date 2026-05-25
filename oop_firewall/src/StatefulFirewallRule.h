#pragma once
#include "FirewallRule.h"

class StatefulFirewallRule : public FirewallRule {
private:
    int connectionTimeout;   // seconds; 0 = no timeout

public:
    StatefulFirewallRule();
    StatefulFirewallRule(const std::string& id,
                         const std::string& protocol,
                         int port,
                         const std::string& srcIp,
                         const std::string& dstIp,
                         RuleAction action,
                         int priority       = 100,
                         RuleDirection dir  = RuleDirection::BOTH,
                         int connTimeout    = 60);

    int  getConnectionTimeout() const { return connectionTimeout; }
    void setConnectionTimeout(int t)  { connectionTimeout = t;   }

    // Override: also checks established connection state
    bool validateConnectionState(bool isEstablished) const;

    bool evaluatePacket(const std::string& srcIp,
                        const std::string& dstIp,
                        const std::string& protocol,
                        int port) const override;
};
