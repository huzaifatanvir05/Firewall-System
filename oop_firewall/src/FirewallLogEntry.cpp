#include "FirewallLogEntry.h"
#include "DateTimeUtility.h"
#include <sstream>

FirewallLogEntry::FirewallLogEntry()
    : timestamp(DateTimeUtility::getCurrentTimestamp()),
      sourceIp(""), actionTaken(""), actionReason("") {}

FirewallLogEntry::FirewallLogEntry(const std::string& ts,
                                   const std::string& srcIp,
                                   const std::string& action,
                                   const std::string& reason)
    : timestamp(ts), sourceIp(srcIp),
      actionTaken(action), actionReason(reason) {}

std::string FirewallLogEntry::displayLogEntry() const {
    std::ostringstream oss;
    oss << "[" << timestamp << "] "
        << actionTaken << " | SRC=" << sourceIp
        << " | REASON=" << actionReason;
    return oss.str();
}

std::string FirewallLogEntry::toCsvLine() const {
    // Format: timestamp,sourceIp,actionTaken,actionReason
    return timestamp + "," + sourceIp + "," + actionTaken + "," + actionReason;
}

FirewallLogEntry FirewallLogEntry::fromCsvLine(const std::string& line) {
    std::istringstream ss(line);
    std::string ts, src, action, reason;
    std::getline(ss, ts,     ',');
    std::getline(ss, src,    ',');
    std::getline(ss, action, ',');
    std::getline(ss, reason);
    return FirewallLogEntry(ts, src, action, reason);
}
