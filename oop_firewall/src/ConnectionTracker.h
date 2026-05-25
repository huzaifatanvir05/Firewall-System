#pragma once
#include <string>
#include <list>
#include <mutex>

struct ConnectionKey {
    std::string srcIp;
    std::string dstIp;
    std::string protocol;
    int         srcPort;
    int         dstPort;

    bool operator==(const ConnectionKey& o) const {
        return srcIp == o.srcIp && dstIp == o.dstIp &&
               protocol == o.protocol &&
               srcPort  == o.srcPort  && dstPort == o.dstPort;
    }
    std::string toString() const;
};

class ConnectionTracker {
private:
    std::list<ConnectionKey> activeConnections;
    mutable std::mutex       mtx;

public:
    ConnectionTracker()  = default;
    ~ConnectionTracker() = default;

    void addConnection        (const ConnectionKey& key);
    void removeConnection     (const ConnectionKey& key);
    bool isExistingConnection (const ConnectionKey& key) const;

    size_t      getConnectionCount() const;
    std::string dumpConnections()    const;
};
