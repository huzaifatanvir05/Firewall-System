#pragma once
#include <string>
#include <ctime>
#include <chrono>

class DateTimeUtility {
private:
    int day;
    int month;
    int year;
    std::string time;

public:
    DateTimeUtility();
    DateTimeUtility(int d, int m, int y, const std::string& t);

    int getDay()          const { return day;   }
    int getMonth()        const { return month; }
    int getYear()         const { return year;  }
    std::string getTime() const { return time;  }

    static std::string getCurrentTimestamp();
    static std::string formatTimestamp(time_t rawTime);
    static DateTimeUtility fromCurrentTime();

    std::string toString() const;
};
