#include "DateTimeUtility.h"
#include <sstream>
#include <iomanip>
#include <ctime>

DateTimeUtility::DateTimeUtility() {
    time_t now = ::time(nullptr);
    struct tm t;
    localtime_s(&t, &now);
    day   = t.tm_mday;
    month = t.tm_mon + 1;
    year  = t.tm_year + 1900;

    std::ostringstream oss;
    oss << std::setw(2) << std::setfill('0') << t.tm_hour << ":"
        << std::setw(2) << std::setfill('0') << t.tm_min  << ":"
        << std::setw(2) << std::setfill('0') << t.tm_sec;
    time = oss.str();
}

DateTimeUtility::DateTimeUtility(int d, int m, int y, const std::string& t)
    : day(d), month(m), year(y), time(t) {}

std::string DateTimeUtility::getCurrentTimestamp() {
    time_t now = ::time(nullptr);
    return formatTimestamp(now);
}

std::string DateTimeUtility::formatTimestamp(time_t rawTime) {
    struct tm t;
    localtime_s(&t, &rawTime);
    std::ostringstream oss;
    oss << std::setw(4) << (t.tm_year + 1900) << "-"
        << std::setw(2) << std::setfill('0') << (t.tm_mon + 1) << "-"
        << std::setw(2) << std::setfill('0') << t.tm_mday << " "
        << std::setw(2) << std::setfill('0') << t.tm_hour << ":"
        << std::setw(2) << std::setfill('0') << t.tm_min  << ":"
        << std::setw(2) << std::setfill('0') << t.tm_sec;
    return oss.str();
}

DateTimeUtility DateTimeUtility::fromCurrentTime() {
    return DateTimeUtility();
}

std::string DateTimeUtility::toString() const {
    std::ostringstream oss;
    oss << std::setw(4) << year << "-"
        << std::setw(2) << std::setfill('0') << month << "-"
        << std::setw(2) << std::setfill('0') << day   << " " << time;
    return oss.str();
}
