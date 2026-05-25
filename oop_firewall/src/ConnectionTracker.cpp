#include "ConnectionTracker.h"
#include <sstream>
#include <algorithm>

std::string ConnectionKey::toString() const {
    std::ostringstream oss;
    oss << srcIp << ":" << srcPort
        << " -> " << dstIp << ":" << dstPort
        << " [" << protocol << "]";
    return oss.str();
}

void ConnectionTracker::addConnection(const ConnectionKey& key) {
    std::lock_guard<std::mutex> lock(mtx);
    if (!isExistingConnection(key))
        activeConnections.push_back(key);
}

void ConnectionTracker::removeConnection(const ConnectionKey& key) {
    std::lock_guard<std::mutex> lock(mtx);
    activeConnections.remove_if([&](const ConnectionKey& k) {
        return k == key;
    });
}

bool ConnectionTracker::isExistingConnection(const ConnectionKey& key) const {
    // NOTE: called from addConnection which already holds the lock
    for (const auto& k : activeConnections)
        if (k == key) return true;
    return false;
}

size_t ConnectionTracker::getConnectionCount() const {
    std::lock_guard<std::mutex> lock(mtx);
    return activeConnections.size();
}

std::string ConnectionTracker::dumpConnections() const {
    std::lock_guard<std::mutex> lock(mtx);
    std::ostringstream oss;
    oss << "=== Active Connections (" << activeConnections.size() << ") ===\n";
    if (activeConnections.empty()) {
        oss << "  (no active tracked connections)\n";
    } else {
        for (const auto& k : activeConnections)
            oss << "  " << k.toString() << "\n";
    }
    return oss.str();
}
