#include "NetworkAddress.h"
#include <sstream>
#include <regex>
#include <algorithm>

NetworkAddress::NetworkAddress()
    : ipAddress("0.0.0.0"), macAddress(""), ipVersion(4) {}

NetworkAddress::NetworkAddress(const std::string& ip,
                               const std::string& mac,
                               int version)
    : ipAddress(ip), macAddress(mac), ipVersion(version) {}

// ── IPv4 ─────────────────────────────────────────────────────────────────────
bool NetworkAddress::validateIPv4() const {
    std::regex re(
        R"(^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$)");
    return std::regex_match(ipAddress, re);
}

// ── IPv6 ─────────────────────────────────────────────────────────────────────
bool NetworkAddress::validateIPv6() const {
    // Accept full / compressed forms
    std::regex re(
        R"(^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$)");
    return std::regex_match(ipAddress, re);
}

bool NetworkAddress::detectIpVersion() {
    if (validateIPv4())      { ipVersion = 4; return true; }
    if (validateIPv6())      { ipVersion = 6; return true; }
    return false;
}

// ── MAC ──────────────────────────────────────────────────────────────────────
bool NetworkAddress::validateMacAddress() const {
    if (macAddress.empty()) return false;
    std::regex re(
        R"(^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$)");
    return std::regex_match(macAddress, re);
}

std::string NetworkAddress::toString() const {
    std::ostringstream oss;
    oss << "IP(v" << ipVersion << ")=" << ipAddress;
    if (!macAddress.empty())
        oss << " MAC=" << macAddress;
    return oss.str();
}
