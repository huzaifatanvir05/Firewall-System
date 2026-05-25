#pragma once
#include <string>

// Direction of traffic the rule applies to
enum class RuleDirection { INBOUND, OUTBOUND, BOTH };
// Action taken when the rule matches
enum class RuleAction    { ALLOW, BLOCK };

class FirewallRule {
protected:
    std::string    ruleId;
    std::string    protocolType;   // TCP / UDP / ICMP / ANY
    int            portNumber;     // -1 = any
    std::string    sourceIpAddress;
    std::string    targetIpAddress;
    std::string    targetMacAddress;
    std::string    actionType;     // "ALLOW" | "BLOCK"
    int            priority;       // lower number = higher priority
    RuleDirection  direction;

public:
    FirewallRule();
    FirewallRule(const std::string& id,
                 const std::string& protocol,
                 int port,
                 const std::string& srcIp,
                 const std::string& dstIp,
                 RuleAction action,
                 int priority = 100,
                 RuleDirection dir = RuleDirection::BOTH);

    virtual ~FirewallRule() = default;

    // Getters
    std::string   getRuleId()          const { return ruleId;          }
    std::string   getProtocolType()    const { return protocolType;    }
    int           getPortNumber()      const { return portNumber;      }
    std::string   getSourceIp()        const { return sourceIpAddress; }
    std::string   getTargetIp()        const { return targetIpAddress; }
    std::string   getTargetMac()       const { return targetMacAddress;}
    std::string   getActionType()      const { return actionType;      }
    int           getPriority()        const { return priority;        }
    RuleDirection getDirection()       const { return direction;       }
    bool          isBlock()            const { return actionType == "BLOCK"; }

    // Core virtuals
    virtual bool evaluatePacket(const std::string& srcIp,
                                const std::string& dstIp,
                                const std::string& protocol,
                                int port) const;

    virtual bool matchesIp  (const std::string& ip)  const;
    virtual bool matchesPort(int port)                const;

    std::string toString() const;
};
