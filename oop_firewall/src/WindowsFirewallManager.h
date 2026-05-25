#pragma once
// ── Windows Firewall COM integration ─────────────────────────────────────────
// Requires:  netfw.h, ole32.lib, oleaut32.lib
// Run the executable as Administrator for COM firewall API to work.
// Falls back to netsh advfirewall when COM fails.
#include <string>
#include <vector>

class WindowsFirewallManager {
private:
    bool comInitialized;

    // Helper: run a netsh command as fallback
    static bool runNetsh(const std::string& cmd);

public:
    WindowsFirewallManager();
    ~WindowsFirewallManager();

    // Initialize COM; returns false if COM unavailable
    bool initialize();
    void shutdown();

    // Add an inbound BLOCK rule for the given remote IP (via COM API)
    bool blockInboundIp (const std::string& ip,
                         const std::string& ruleName = "");

    // Add an outbound BLOCK rule
    bool blockOutboundIp(const std::string& ip,
                         const std::string& ruleName = "");

    // Block a specific port (TCP or UDP)
    bool blockPort(int port,
                   const std::string& protocol  = "TCP",
                   const std::string& direction = "INBOUND");

    // Remove a rule by name
    bool removeRule(const std::string& ruleName);

    // List all rules added by this manager
    std::vector<std::string> listManagedRules() const;

    // Quick check: is WF running?
    static bool isWindowsFirewallEnabled();

private:
    std::vector<std::string> managedRuleNames;

    // COM-based helpers
    bool blockIpViaCom(const std::string& ip,
                       const std::string& ruleName,
                       int direction);  // NET_FW_RULE_DIR_IN / OUT
};
