// ═════════════════════════════════════════════════════════════════════════════
//  C++ Firewall System — main.cpp
//  Requires: Npcap SDK, Windows 10/11, Administrator privileges
// ═════════════════════════════════════════════════════════════════════════════
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <memory>
#include <csignal>
#include <thread>
#include <chrono>

#include "src/LogManager.h"
#include "src/FirewallEngine.h"
#include "src/PacketSniffer.h"
#include "src/FirewallRule.h"
#include "src/StatefulFirewallRule.h"
#include "src/DateTimeUtility.h"

// ── Global pointers for signal handler ───────────────────────────────────────
static PacketSniffer* g_sniffer  = nullptr;
static FirewallEngine* g_engine  = nullptr;
static LogManager*    g_logMgr   = nullptr;

void signalHandler(int sig) {
    std::cout << "\n[Main] Signal " << sig << " received. Shutting down...\n";
    if (g_sniffer) g_sniffer->shutdown();
    if (g_engine)  g_engine->shutdown();
    if (g_logMgr)  g_logMgr->shutdown();
    exit(0);
}

// ── Admin check ───────────────────────────────────────────────────────────────
bool isRunningAsAdmin() {
    BOOL elevated = FALSE;
    HANDLE token  = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION te;
        DWORD size = sizeof(te);
        if (GetTokenInformation(token, TokenElevation, &te, sizeof(te), &size))
            elevated = te.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

// ── Relaunch with Administrator privileges ───────────────────────────────────
bool relaunchAsAdmin() {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) {
        return false;
    }

    std::wstring params;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) {
            params += L" ";
        }
        params += L'"';
        params += argv[i];
        params += L'"';
    }
    LocalFree(argv);

    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, ARRAYSIZE(path))) {
        return false;
    }

    HINSTANCE result = ShellExecuteW(nullptr, L"runas", path,
                                      params.empty() ? nullptr : params.c_str(),
                                      nullptr, SW_NORMAL);
    return reinterpret_cast<intptr_t>(result) > 32;
}

// ── Interactive menu ──────────────────────────────────────────────────────────
void printMenu() {
    std::cout << "\n╔════════════════════════════════════════╗\n";
    std::cout << "║        C++ Firewall System v1.0        ║\n";
    std::cout << "╠════════════════════════════════════════╣\n";
    std::cout << "║ [1] Start packet capture               ║\n";
    std::cout << "║ [2] Stop  packet capture               ║\n";
    std::cout << "║ [3] Add BLOCK rule (IP)                ║\n";
    std::cout << "║ [4] Add ALLOW rule (IP)                ║\n";
    std::cout << "║ [5] Block a port                       ║\n";
    std::cout << "║ [6] Display all log entries            ║\n";
    std::cout << "║ [7] Search logs by IP                  ║\n";
    std::cout << "║ [8] Show recent 20 log entries         ║\n";
    std::cout << "║ [9] Show statistics                    ║\n";
    std::cout << "║ [10] Show active connections           ║\n";
    std::cout << "║ [11] Show firewall rules               ║\n";
    std::cout << "║ [12] List network interfaces           ║\n";
    std::cout << "║ [13] Change interface                  ║\n";
    std::cout << "║ [0] Exit                               ║\n";
    std::cout << "╚════════════════════════════════════════╝\n";
    std::cout << "Choice: ";
}

// ═════════════════════════════════════════════════════════════════════════════
int main() {
    // ── Privilege check ───────────────────────────────────────────────────────
    if (!isRunningAsAdmin()) {
        std::cerr << "[WARNING] Not running as Administrator!\n"
                  << "         Windows Firewall rules cannot be added.\n"
                  << "         Running in limited mode so capture can continue.\n\n";
    } else {
        std::cout << "[OK] Running with Administrator privileges.\n";
    }

    // ── Ctrl+C handler ────────────────────────────────────────────────────────
    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);

    // ── Core subsystem init ───────────────────────────────────────────────────
    LogManager    logMgr("logs/firewall.log", 5000);
    FirewallEngine engine(logMgr);
    PacketSniffer  sniffer(engine);

    g_logMgr  = &logMgr;
    g_engine  = &engine;
    g_sniffer = &sniffer;

    logMgr.initialize();
    engine.initialize();
    sniffer.initialize();

    // ── Default rules ─────────────────────────────────────────────────────────
    // Block common malicious ports
    engine.addRule(std::make_shared<FirewallRule>(
        "RULE_BLOCK_TELNET", "TCP", 23, "*", "*",
        RuleAction::BLOCK, 10));

    engine.addRule(std::make_shared<FirewallRule>(
        "RULE_BLOCK_SMTP_RELAY", "TCP", 25, "*", "*",
        RuleAction::BLOCK, 20));

    engine.addRule(std::make_shared<FirewallRule>(
        "RULE_BLOCK_NETBIOS", "UDP", 137, "*", "*",
        RuleAction::BLOCK, 30));

    // Allow DNS
    engine.addRule(std::make_shared<FirewallRule>(
        "RULE_ALLOW_DNS", "UDP", 53, "*", "*",
        RuleAction::ALLOW, 5));

    // Allow HTTP/HTTPS
    engine.addRule(std::make_shared<FirewallRule>(
        "RULE_ALLOW_HTTP", "TCP", 80, "*", "*",
        RuleAction::ALLOW, 6));
    engine.addRule(std::make_shared<FirewallRule>(
        "RULE_ALLOW_HTTPS", "TCP", 443, "*", "*",
        RuleAction::ALLOW, 7));

    std::cout << "\n[Main] System ready. " << DateTimeUtility::getCurrentTimestamp() << "\n";

    // ── Interactive CLI ───────────────────────────────────────────────────────
    static int ruleCounter = 100;

    while (true) {
        printMenu();

        int choice;
        std::cin >> choice;
        std::cin.ignore();

        switch (choice) {
        // ── Start capture ─────────────────────────────────────────────────────
        case 1:
            if (!sniffer.isCapturing()) {
                std::cout << "Enter BPF filter (leave blank for all traffic): ";
                std::string bpf;
                std::getline(std::cin, bpf);
                if (!bpf.empty()) sniffer.setCaptureFilter(bpf);
                sniffer.startCapture();
            } else {
                std::cout << "[!] Already capturing.\n";
            }
            break;

        // ── Stop capture ──────────────────────────────────────────────────────
        case 2:
            sniffer.stopCapture();
            break;

        // ── Add BLOCK rule ────────────────────────────────────────────────────
        case 3: {
            std::string ip, proto;
            int port;
            std::cout << "Source IP to block (* = any): ";
            std::getline(std::cin, ip);
            std::cout << "Protocol (TCP/UDP/ANY): ";
            std::getline(std::cin, proto);
            std::cout << "Port (-1 = any): ";
            std::cin >> port;
            std::cin.ignore();

            std::string id = "USER_BLOCK_" + std::to_string(++ruleCounter);
            engine.addRule(std::make_shared<FirewallRule>(
                id, proto, port, ip, "*",
                RuleAction::BLOCK, ruleCounter));

            // Also push directly to Windows Firewall if it's an IP block
            if (ip != "*" && ip != "ANY") {
                std::cout << "[Main] Also adding to Windows Firewall...\n";
                // Access winFirewall via separate WFM
                WindowsFirewallManager wfm;
                wfm.initialize();
                wfm.blockInboundIp(ip, "MANUAL_" + id);
                wfm.shutdown();
            }
            break;
        }

        // ── Add ALLOW rule ────────────────────────────────────────────────────
        case 4: {
            std::string ip, proto;
            int port;
            std::cout << "Source IP to allow (* = any): ";
            std::getline(std::cin, ip);
            std::cout << "Protocol (TCP/UDP/ANY): ";
            std::getline(std::cin, proto);
            std::cout << "Port (-1 = any): ";
            std::cin >> port;
            std::cin.ignore();

            std::string id = "USER_ALLOW_" + std::to_string(++ruleCounter);
            engine.addRule(std::make_shared<FirewallRule>(
                id, proto, port, ip, "*",
                RuleAction::ALLOW, ruleCounter));
            break;
        }

        // ── Block port ────────────────────────────────────────────────────────
        case 5: {
            int port;
            std::string proto, dir;
            std::cout << "Port number: ";
            std::cin >> port;
            std::cin.ignore();
            std::cout << "Protocol (TCP/UDP): ";
            std::getline(std::cin, proto);
            std::cout << "Direction (INBOUND/OUTBOUND): ";
            std::getline(std::cin, dir);

            WindowsFirewallManager wfm;
            wfm.initialize();
            wfm.blockPort(port, proto, dir);
            wfm.shutdown();
            break;
        }

        // ── Display all logs ──────────────────────────────────────────────────
        case 6:
            logMgr.displayAllLogs();
            break;

        // ── Search logs by IP ─────────────────────────────────────────────────
        case 7: {
            std::string ip;
            std::cout << "Enter IP to search: ";
            std::getline(std::cin, ip);
            auto entries = logMgr.searchByIp(ip);
            std::cout << "\n=== Entries for " << ip << " (" << entries.size() << ") ===\n";
            for (const auto& e : entries)
                std::cout << e.displayLogEntry() << "\n";
            break;
        }

        // ── Recent 20 ─────────────────────────────────────────────────────────
        case 8: {
            auto recent = logMgr.getRecentEntries(20);
            std::cout << "\n=== Recent " << recent.size() << " Entries ===\n";
            for (const auto& e : recent)
                std::cout << e.displayLogEntry() << "\n";
            break;
        }

        // ── Statistics ────────────────────────────────────────────────────────
        case 9:
            engine.displayStatistics();
            std::cout << "Total logged entries: " << logMgr.totalEntries() << "\n";
            break;

        // ── Active connections ────────────────────────────────────────────────
        case 10:
            std::cout << "[Main] Displaying active connections...\n";
            engine.displayConnections();
            break;

        // ── Firewall rules ────────────────────────────────────────────────────
        case 11:
            engine.displayRules();
            break;

        // ── List interfaces ───────────────────────────────────────────────────
        case 12:
            PacketSniffer::listInterfaces();
            break;

        // ── Change interface ──────────────────────────────────────────────────
        case 13: {
            if (sniffer.isCapturing()) {
                std::cout << "[!] Stop capture first.\n";
                break;
            }
            auto ifaces = PacketSniffer::listInterfaces();
            std::cout << "Enter interface number: ";
            size_t idx;
            std::cin >> idx;
            std::cin.ignore();
            if (idx < ifaces.size()) {
                sniffer.setInterface(ifaces[idx].name);
                std::cout << "[Main] Interface set to: "
                          << ifaces[idx].description << "\n";
            }
            break;
        }

        // ── Exit ──────────────────────────────────────────────────────────────
        case 0:
            sniffer.shutdown();
            engine.shutdown();
            logMgr.shutdown();
            std::cout << "[Main] Goodbye.\n";
            return 0;

        default:
            std::cout << "[!] Unknown option.\n";
            break;
        }
    }
}
