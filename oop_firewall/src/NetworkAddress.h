#pragma once
#include <string>

class NetworkAddress {
private:
    std::string ipAddress;
    std::string macAddress;
    int ipVersion;   // 4 or 6

public:
    NetworkAddress();
    NetworkAddress(const std::string& ip,
                   const std::string& mac = "",
                   int version = 4);

    // Getters
    std::string getIpAddress()  const { return ipAddress;  }
    std::string getMacAddress() const { return macAddress; }
    int         getIpVersion()  const { return ipVersion;  }

    // Setters
    void setIpAddress (const std::string& ip)  { ipAddress  = ip;  }
    void setMacAddress(const std::string& mac) { macAddress = mac; }
    void setIpVersion (int version)            { ipVersion  = version; }

    bool validateIPv4()    const;
    bool validateIPv6()    const;
    bool detectIpVersion();          // auto-sets ipVersion, returns true on success
    bool validateMacAddress() const;

    std::string toString() const;
};
