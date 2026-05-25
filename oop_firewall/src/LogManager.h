#pragma once
#include <string>
#include <list>
#include <deque>
#include <mutex>
#include <vector>
#include "FirewallLogEntry.h"
#include "FileManager.h"
#include "SecurityComponent.h"

// ── Circular buffer backed by deque ──────────────────────────────────────────
class CircularLogBuffer {
private:
    std::deque<FirewallLogEntry> buffer;
    size_t capacity;

public:
    explicit CircularLogBuffer(size_t cap = 1000) : capacity(cap) {}

    void push(const FirewallLogEntry& entry) {
        if (buffer.size() >= capacity) buffer.pop_front();
        buffer.push_back(entry);
    }

    const std::deque<FirewallLogEntry>& entries() const { return buffer; }
    size_t size()  const { return buffer.size();     }
    void   clear()       { buffer.clear();           }
};

// ── LogManager ────────────────────────────────────────────────────────────────
class LogManager : public SecurityComponent {
private:
    std::list<FirewallLogEntry>  logLinkedList;      // full ordered list
    CircularLogBuffer            circularLogBuffer;  // recent 1000 entries
    FileManager                  fileManager;
    mutable std::mutex           mtx;
    bool                         running;

public:
    LogManager();
    explicit LogManager(const std::string& logFilePath,
                        size_t circularCap = 1000);

    // SecurityComponent interface
    bool initialize() override;
    void shutdown()   override;

    // Core API
    void addLogEntry     (const FirewallLogEntry& entry);
    void displayAllLogs  () const;
    bool saveLogsToFile  () const;
    bool loadLogsFromFile();

    // Query helpers
    std::vector<FirewallLogEntry> getRecentEntries(size_t n) const;
    std::vector<FirewallLogEntry> searchByIp(const std::string& ip) const;
    std::vector<FirewallLogEntry> searchByAction(const std::string& action) const;
    size_t totalEntries() const;
};

