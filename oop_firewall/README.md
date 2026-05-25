# C++ Firewall System

A fully functional Windows firewall built in C++ using **Npcap** for live packet capture and the **Windows Firewall COM API** to enforce block rules in Windows Defender Firewall.

---

## Architecture (matches UML diagram)

```
SecurityComponent (abstract)
├── FirewallEngine      — rule evaluation, packet decisions, WF enforcement
├── PacketSniffer       — Npcap live capture, background thread
└── LogManager          — LinkedList + CircularBuffer, CSV persistence

Supporting classes:
  FirewallRule / StatefulFirewallRule — rule definitions
  NetworkPacket                       — parsed Ethernet/IP/TCP/UDP packets
  ConnectionTracker                   — stateful connection state
  FirewallStatistics                  — atomic counters
  FirewallLogEntry                    — one log record
  FileManager                         — CSV read/write
  NetworkAddress                      — IP/MAC with validation
  DateTimeUtility                     — timestamps
  WindowsFirewallManager              — COM + netsh firewall enforcement
```

---

## Prerequisites

| Tool | Download |
|------|----------|
| **Npcap** (driver, install first) | https://npcap.com/#download |
| **Npcap SDK** (headers + libs)    | https://npcap.com/#download → "Npcap SDK" |
| **Visual Studio 2022** (C++ workload) | https://visualstudio.microsoft.com |
| **CMake ≥ 3.16** | https://cmake.org |

---

## Build Instructions

### Step 1 — Install Npcap driver
Run the Npcap installer as Administrator. During setup, tick **"Install Npcap in WinPcap API-compatible Mode"**.

### Step 2 — Extract Npcap SDK
Extract the Npcap SDK zip to `C:\npcap-sdk`
(or pass `-DNPCAP_SDK_DIR=<your path>` to CMake).

### Step 3 — Configure & Build
Open **Developer PowerShell for VS 2022** (or x64 Native Tools Command Prompt):

```powershell
cd C:\Users\DELL\.gemini\antigravity\scratch\firewall_system

# Configure
cmake -B build -G "Visual Studio 17 2022" -A x64

# Build (Release)
cmake --build build --config Release

# The binary is output to:
# bin/Release/firewall_system.exe
```

---

## Running

> **Must run as Administrator** for Windows Firewall rules and pcap to work.

```powershell
# Right-click PowerShell → "Run as Administrator", then:
cd C:\Users\DELL\.gemini\antigravity\scratch\firewall_system
.\bin\Release\firewall_system.exe
```

---

## Features

| Feature | Details |
|---------|---------|
| **Live packet capture** | Npcap promiscuous mode, background thread |
| **Packet parsing** | Ethernet → IPv4 → TCP/UDP/ICMP |
| **Rule engine** | Priority-ordered, first-match-wins |
| **Stateful tracking** | Established connections auto-allowed |
| **Windows FW enforcement** | COM API (`INetFwPolicy2`) + `netsh` fallback |
| **Persistent logging** | CSV file in `logs/firewall.log` |
| **In-memory log** | LinkedList (all) + CircularBuffer (recent 5000) |
| **BPF filter** | Optional pcap filter expression (e.g. `tcp port 80`) |
| **Interactive CLI** | Add/remove rules, search logs, view stats live |

---

## Default Rules (loaded at startup)

| Rule | Action | Protocol | Port |
|------|--------|----------|------|
| RULE_ALLOW_DNS | ALLOW | UDP | 53 |
| RULE_ALLOW_HTTP | ALLOW | TCP | 80 |
| RULE_ALLOW_HTTPS | ALLOW | TCP | 443 |
| RULE_BLOCK_TELNET | BLOCK | TCP | 23 |
| RULE_BLOCK_SMTP_RELAY | BLOCK | TCP | 25 |
| RULE_BLOCK_NETBIOS | BLOCK | UDP | 137 |

---

## Log File

Logs are stored at `logs/firewall.log` in CSV format:

```
timestamp,sourceIp,action,reason
2026-05-19 00:15:01,192.168.1.105,BLOCKED,RULE_BLOCK_TELNET
2026-05-19 00:15:02,8.8.8.8,ALLOWED,RULE_ALLOW_DNS
```

Use **menu option [6]** to display all logs, **[7]** to search by IP, **[8]** for recent entries.

---

## Project Structure

```
firewall_system/
├── main.cpp                          ← Interactive CLI entry point
├── CMakeLists.txt
├── logs/                             ← firewall.log written here
├── rules/                            ← (reserved for rule persistence)
└── src/
    ├── SecurityComponent.h           ← Abstract base class
    ├── DateTimeUtility.h/cpp
    ├── NetworkAddress.h/cpp
    ├── FirewallRule.h/cpp
    ├── StatefulFirewallRule.h/cpp
    ├── FirewallLogEntry.h/cpp
    ├── FirewallStatistics.h/cpp
    ├── ConnectionTracker.h/cpp
    ├── FileManager.h/cpp
    ├── NetworkPacket.h/cpp           ← Raw frame parser
    ├── LogManager.h/cpp              ← Circular + linked list logs
    ├── WindowsFirewallManager.h/cpp  ← COM API + netsh
    ├── FirewallEngine.h/cpp          ← Core decision engine
    └── PacketSniffer.h/cpp           ← Npcap capture thread
```
