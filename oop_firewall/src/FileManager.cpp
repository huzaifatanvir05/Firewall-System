#include "FileManager.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iostream>

FileManager::FileManager() : filePath("logs/firewall.log") {}
FileManager::FileManager(const std::string& path) : filePath(path) {}

bool FileManager::writeToFile(const std::string& content, bool append) const {
    std::ofstream ofs(filePath,
        append ? (std::ios::out | std::ios::app)
               :  std::ios::out);
    if (!ofs.is_open()) {
        std::cerr << "[FileManager] Cannot open: " << filePath << "\n";
        return false;
    }
    ofs << content << "\n";
    return true;
}

std::vector<std::string> FileManager::readFromFile() const {
    std::vector<std::string> lines;
    std::ifstream ifs(filePath);
    if (!ifs.is_open()) return lines;
    std::string line;
    while (std::getline(ifs, line))
        if (!line.empty()) lines.push_back(line);
    return lines;
}

bool FileManager::fileExists() const {
    return std::filesystem::exists(filePath);
}

bool FileManager::createDirIfNeeded(const std::string& dir) const {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return !ec;
}
