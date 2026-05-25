#pragma once
#include <string>
#include <vector>

class FileManager {
private:
    std::string filePath;

public:
    FileManager();
    explicit FileManager(const std::string& path);

    std::string getFilePath() const { return filePath; }
    void setFilePath(const std::string& path) { filePath = path; }

    bool writeToFile  (const std::string& content, bool append = true) const;
    std::vector<std::string> readFromFile() const;
    bool fileExists   () const;
    bool createDirIfNeeded(const std::string& dir) const;
};
