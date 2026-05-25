#pragma once
#include <string>

class FirewallLogEntry {
private:
    std::string timestamp;
    std::string sourceIp;
    std::string actionTaken;   // "ALLOWED" | "BLOCKED"
    std::string actionReason;  // matched rule id or "NO_MATCH"

public:
    FirewallLogEntry();
    FirewallLogEntry(const std::string& ts,
                     const std::string& srcIp,
                     const std::string& action,
                     const std::string& reason);

    std::string getTimestamp()    const { return timestamp;    }
    std::string getSourceIp()     const { return sourceIp;     }
    std::string getActionTaken()  const { return actionTaken;  }
    std::string getActionReason() const { return actionReason; }

    std::string displayLogEntry() const;
    std::string toCsvLine()       const;   // for file persistence
    static FirewallLogEntry fromCsvLine(const std::string& line);
};
