#include "LogManager.h"
#include <iostream>
#include <algorithm>

LogManager::LogManager()
    : fileManager("logs/firewall.log"),
      circularLogBuffer(1000), running(false) {}

LogManager::LogManager(const std::string& logFilePath, size_t circularCap)
    : fileManager(logFilePath),
      circularLogBuffer(circularCap), running(false) {}

bool LogManager::initialize() {
    fileManager.createDirIfNeeded("logs");
    // Write header if new file
    if (!fileManager.fileExists()) {
        fileManager.writeToFile("timestamp,sourceIp,action,reason", false);
    } else {
        loadLogsFromFile();
    }
    running = true;
    std::cout << "[LogManager] Initialized. Log: "
              << fileManager.getFilePath() << "\n";
    return true;
}

void LogManager::shutdown() {
    saveLogsToFile();
    running = false;
    std::cout << "[LogManager] Shutdown. Total entries: "
              << logLinkedList.size() << "\n";
}

void LogManager::addLogEntry(const FirewallLogEntry& entry) {
    std::lock_guard<std::mutex> lock(mtx);
    logLinkedList.push_back(entry);
    circularLogBuffer.push(entry);
    // Append immediately to disk
    fileManager.writeToFile(entry.toCsvLine(), true);
}

void LogManager::displayAllLogs() const {
    std::lock_guard<std::mutex> lock(mtx);
    std::cout << "\n=== All Log Entries (" << logLinkedList.size() << ") ===\n";
    for (const auto& e : logLinkedList)
        std::cout << e.displayLogEntry() << "\n";
    std::cout << "=== End of Logs ===\n\n";
}

bool LogManager::saveLogsToFile() const {
    std::lock_guard<std::mutex> lock(mtx);
    // Rewrite entire file
    bool first = true;
    for (const auto& e : logLinkedList) {
        if (first) {
            fileManager.writeToFile("timestamp,sourceIp,action,reason", false);
            first = false;
        }
        fileManager.writeToFile(e.toCsvLine(), true);
    }
    return true;
}

bool LogManager::loadLogsFromFile() {
    auto lines = fileManager.readFromFile();
    bool headerSkipped = false;
    for (const auto& line : lines) {
        if (!headerSkipped) { headerSkipped = true; continue; } // skip CSV header
        try {
            auto entry = FirewallLogEntry::fromCsvLine(line);
            logLinkedList.push_back(entry);
            circularLogBuffer.push(entry);
        } catch (...) {}
    }
    return true;
}

std::vector<FirewallLogEntry> LogManager::getRecentEntries(size_t n) const {
    std::lock_guard<std::mutex> lock(mtx);
    const auto& buf = circularLogBuffer.entries();
    size_t start = buf.size() > n ? buf.size() - n : 0;
    return std::vector<FirewallLogEntry>(buf.begin() + start, buf.end());
}

std::vector<FirewallLogEntry> LogManager::searchByIp(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mtx);
    std::vector<FirewallLogEntry> result;
    for (const auto& e : logLinkedList)
        if (e.getSourceIp() == ip) result.push_back(e);
    return result;
}

std::vector<FirewallLogEntry> LogManager::searchByAction(const std::string& action) const {
    std::lock_guard<std::mutex> lock(mtx);
    std::vector<FirewallLogEntry> result;
    for (const auto& e : logLinkedList)
        if (e.getActionTaken() == action) result.push_back(e);
    return result;
}

size_t LogManager::totalEntries() const {
    std::lock_guard<std::mutex> lock(mtx);
    return logLinkedList.size();
}
