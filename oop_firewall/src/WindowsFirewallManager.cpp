#include "WindowsFirewallManager.h"
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <algorithm>

// Windows-specific COM headers
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <netfw.h>
#include <oleauto.h>

#ifndef NET_FW_IP_PROTOCOL_ANY
#define NET_FW_IP_PROTOCOL_ANY 256
#endif

static BSTR toBstr(const std::string& text) {
    std::wstring wide(text.begin(), text.end());
    return SysAllocStringLen(wide.c_str(), static_cast<UINT>(wide.size()));
}

// NET_FW_RULE_DIR_IN  = 1
// NET_FW_RULE_DIR_OUT = 2
// NET_FW_ACTION_BLOCK = 0
// NET_FW_IP_PROTOCOL_TCP = 6
// NET_FW_IP_PROTOCOL_UDP = 17

WindowsFirewallManager::WindowsFirewallManager() : comInitialized(false) {}

WindowsFirewallManager::~WindowsFirewallManager() {
    shutdown();
}

bool WindowsFirewallManager::initialize() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    comInitialized = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    if (!comInitialized) {
        std::cerr << "[WinFW] COM init failed, will use netsh fallback.\n";
    } else {
        std::cout << "[WinFW] COM initialized successfully.\n";
    }
    return true;  // always continue – netsh fallback available
}

void WindowsFirewallManager::shutdown() {
    if (comInitialized) {
        CoUninitialize();
        comInitialized = false;
    }
}

// ── netsh fallback ────────────────────────────────────────────────────────────
bool WindowsFirewallManager::runNetsh(const std::string& cmd) {
    std::string full = "netsh " + cmd;
    std::cout << "[WinFW][netsh] " << full << "\n";
    int ret = system(full.c_str());
    return ret == 0;
}

// ── COM helper ────────────────────────────────────────────────────────────────
bool WindowsFirewallManager::blockIpViaCom(const std::string& ip,
                                            const std::string& ruleName,
                                            int direction) {
    HRESULT hr;
    INetFwPolicy2* fwPolicy = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr,
                          CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwPolicy2),
                          reinterpret_cast<void**>(&fwPolicy));
    if (FAILED(hr) || !fwPolicy) {
        std::cerr << "[WinFW] Cannot create INetFwPolicy2 (hr=" << hr << ")\n";
        return false;
    }

    INetFwRules* fwRules = nullptr;
    hr = fwPolicy->get_Rules(&fwRules);
    if (FAILED(hr) || !fwRules) {
        fwPolicy->Release();
        return false;
    }

    INetFwRule* fwRule = nullptr;
    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr,
                          CLSCTX_INPROC_SERVER,
                          __uuidof(INetFwRule),
                          reinterpret_cast<void**>(&fwRule));
    if (FAILED(hr) || !fwRule) {
        fwRules->Release();
        fwPolicy->Release();
        return false;
    }

    // Set rule name
    BSTR bName = toBstr(ruleName);
    fwRule->put_Name(bName);
    SysFreeString(bName);

    // Description
    BSTR bDesc = toBstr("Blocked by CPP Firewall: " + ip);
    fwRule->put_Description(bDesc);
    SysFreeString(bDesc);

    // Remote address
    BSTR bIp = toBstr(ip);
    fwRule->put_RemoteAddresses(bIp);
    SysFreeString(bIp);

    // Direction: 1=IN, 2=OUT
    fwRule->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(direction));

    // Action: block
    fwRule->put_Action(NET_FW_ACTION_BLOCK);

    // Protocol: ANY
    fwRule->put_Protocol(NET_FW_IP_PROTOCOL_ANY);

    // Enable
    fwRule->put_Enabled(VARIANT_TRUE);

    // Add to policy
    hr = fwRules->Add(fwRule);
    if (FAILED(hr)) {
        std::cerr << "[WinFW] Failed to add rule (hr=" << hr << "). "
                  << "Ensure running as Administrator.\n";
        fwRule->Release();
        fwRules->Release();
        fwPolicy->Release();
        return false;
    }
    std::cout << "[WinFW] COM rule added: " << ruleName << " -> BLOCK " << ip << "\n";

    fwRule->Release();
    fwRules->Release();
    fwPolicy->Release();
    return true;
}

// ── Public API ────────────────────────────────────────────────────────────────
bool WindowsFirewallManager::blockInboundIp(const std::string& ip,
                                             const std::string& ruleName) {
    std::string name = ruleName.empty()
                     ? ("CPP_FW_BLOCK_IN_" + ip)
                     : ruleName;
    managedRuleNames.push_back(name);

    if (comInitialized && blockIpViaCom(ip, name, NET_FW_RULE_DIR_IN))
        return true;

    // netsh fallback
    std::string cmd = "advfirewall firewall add rule"
                      " name=\"" + name + "\""
                      " dir=in action=block"
                      " remoteip=" + ip +
                      " enable=yes";
    return runNetsh(cmd);
}

bool WindowsFirewallManager::blockOutboundIp(const std::string& ip,
                                              const std::string& ruleName) {
    std::string name = ruleName.empty()
                     ? ("CPP_FW_BLOCK_OUT_" + ip)
                     : ruleName;
    managedRuleNames.push_back(name);

    if (comInitialized && blockIpViaCom(ip, name, NET_FW_RULE_DIR_OUT))
        return true;

    std::string cmd = "advfirewall firewall add rule"
                      " name=\"" + name + "\""
                      " dir=out action=block"
                      " remoteip=" + ip +
                      " enable=yes";
    return runNetsh(cmd);
}

bool WindowsFirewallManager::blockPort(int port,
                                        const std::string& protocol,
                                        const std::string& direction) {
    std::string name = "CPP_FW_BLOCK_PORT_" + std::to_string(port) + "_" + protocol;
    managedRuleNames.push_back(name);

    std::string dir = (direction == "OUTBOUND") ? "out" : "in";
    std::string proto = protocol;
    for (auto& c : proto) c = static_cast<char>(tolower(c));

    std::string cmd = "advfirewall firewall add rule"
                      " name=\"" + name + "\""
                      " dir=" + dir +
                      " action=block"
                      " protocol=" + proto +
                      " localport=" + std::to_string(port) +
                      " enable=yes";
    return runNetsh(cmd);
}

bool WindowsFirewallManager::removeRule(const std::string& ruleName) {
    std::string cmd = "advfirewall firewall delete rule name=\"" + ruleName + "\"";
    managedRuleNames.erase(
        std::remove(managedRuleNames.begin(), managedRuleNames.end(), ruleName),
        managedRuleNames.end());
    return runNetsh(cmd);
}

std::vector<std::string> WindowsFirewallManager::listManagedRules() const {
    return managedRuleNames;
}

bool WindowsFirewallManager::isWindowsFirewallEnabled() {
    // Query via netsh
    int ret = system("netsh advfirewall show allprofiles state | findstr /i \"ON\" >nul 2>&1");
    return ret == 0;
}
