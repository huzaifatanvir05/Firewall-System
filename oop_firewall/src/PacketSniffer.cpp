#include "PacketSniffer.h"
#include "NetworkPacket.h"
#include <pcap.h>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <chrono>

// ── ctor / dtor ───────────────────────────────────────────────────────────────
PacketSniffer::PacketSniffer(FirewallEngine& eng)
    : handle(nullptr), engine(eng), capturing(false),
      networkInterface(""), captureFilter("") {}

PacketSniffer::~PacketSniffer() {
    if (capturing) stopCapture();
}

// ── SecurityComponent ─────────────────────────────────────────────────────────
static bool isUsableInterface(const std::string& description) {
    std::string desc = description;
    std::transform(desc.begin(), desc.end(), desc.begin(), ::tolower);
    if (desc.find("loopback") != std::string::npos) return false;
    if (desc.find("network monitor") != std::string::npos) return false;
    if (desc.find("miniport") != std::string::npos) return false;
    if (desc.find("tap") != std::string::npos) return false;
    if (desc.find("virtual") != std::string::npos) return false;
    return true;
}

bool PacketSniffer::initialize() {
    // Auto-select a usable interface if none specified
    if (networkInterface.empty()) {
        auto ifaces = listInterfaces();
        if (ifaces.empty()) {
            std::cerr << "[PacketSniffer] No network interfaces found.\n";
            return false;
        }

        for (const auto& iface : ifaces) {
            if (!iface.description.empty() && isUsableInterface(iface.description)) {
                networkInterface = iface.name;
                std::cout << "[PacketSniffer] Auto-selected interface: "
                          << iface.description << "\n";
                break;
            }
        }

        if (networkInterface.empty()) {
            networkInterface = ifaces[0].name;
            std::cout << "[PacketSniffer] Auto-selected interface: "
                      << ifaces[0].description << "\n";
        }
    }
    std::cout << "[PacketSniffer] Initialized on interface: "
              << networkInterface << "\n";
    return true;
}

void PacketSniffer::shutdown() {
    stopCapture();
    std::cout << "[PacketSniffer] Shutdown.\n";
}

// ── Interface listing ─────────────────────────────────────────────────────────
std::vector<PacketSniffer::InterfaceInfo> PacketSniffer::listInterfaces() {
    std::vector<PacketSniffer::InterfaceInfo> result;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "[PacketSniffer] pcap_findalldevs error: " << errbuf << "\n";
        return result;
    }

    std::cout << "\n=== Available Network Interfaces ===\n";
    int idx = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next, ++idx) {
        std::string desc = d->description ? d->description : "";
        std::cout << "  [" << idx << "] " << d->name;
        if (!desc.empty())
            std::cout << " (" << desc << ")";
        std::cout << "\n";
        result.push_back({d->name, desc});
    }
    std::cout << "====================================\n\n";

    pcap_freealldevs(alldevs);
    return result;
}

// ── Capture start/stop ────────────────────────────────────────────────────────
bool PacketSniffer::startCapture() {
    if (capturing) {
        std::cerr << "[PacketSniffer] Already capturing.\n";
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    // Open interface in promiscuous mode, 65535-byte snaplen, 1000ms timeout
    handle = pcap_open_live(networkInterface.c_str(),
                            65535,   // snaplen
                            1,       // promiscuous
                            1000,    // read timeout ms
                            errbuf);
    if (!handle) {
        std::cerr << "[PacketSniffer] pcap_open_live failed: " << errbuf << "\n";
        return false;
    }

    // Apply BPF filter if set
    if (!captureFilter.empty()) {
        struct bpf_program fp;
        bpf_u_int32 netmask = 0;

        if (pcap_compile(handle, &fp, captureFilter.c_str(), 0, netmask) == -1) {
            std::cerr << "[PacketSniffer] Filter compile error: "
                      << pcap_geterr(handle) << "\n";
        } else {
            if (pcap_setfilter(handle, &fp) == -1) {
                std::cerr << "[PacketSniffer] Filter set error: "
                          << pcap_geterr(handle) << "\n";
            } else {
                std::cout << "[PacketSniffer] BPF filter applied: "
                          << captureFilter << "\n";
            }
            pcap_freecode(&fp);
        }
    }

    capturing = true;
    captureThread = std::thread(&PacketSniffer::captureLoop, this);
    std::cout << "[PacketSniffer] Capture started on " << networkInterface
              << " (waiting for packets...)\n";
    return true;
}

void PacketSniffer::stopCapture() {
    if (!capturing) return;
    capturing = false;
    if (handle) {
        pcap_breakloop(handle);
    }
    if (captureThread.joinable()) {
        captureThread.join();
    }
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
    std::cout << "[PacketSniffer] Capture stopped.\n";
}

// ── Capture loop (runs in background thread) ──────────────────────────────────
void PacketSniffer::captureLoop() {
    // pcap_loop runs until pcap_breakloop() is called or error
    int res = pcap_loop(handle,
              0,                        // 0 = loop forever
              PacketSniffer::pcapCallback,
              reinterpret_cast<unsigned char*>(&engine));
    if (res == -1) {
        std::cerr << "[PacketSniffer] Capture loop error: "
                  << pcap_geterr(handle) << "\n";
    } else if (res == -2) {
        std::cout << "[PacketSniffer] Capture stopped by user.\n";
    } else {
        std::cout << "[PacketSniffer] Capture loop exited (code=" << res << ").\n";
    }
}

// ── pcap static callback ──────────────────────────────────────────────────────
void PacketSniffer::pcapCallback(unsigned char*           userData,
                                  const struct pcap_pkthdr* header,
                                  const unsigned char*      pktData) {
    if (!userData || !header || !pktData) return;

    FirewallEngine* eng = reinterpret_cast<FirewallEngine*>(userData);

    // Parse raw bytes into NetworkPacket
    NetworkPacket pkt = NetworkPacket::fromRawBytes(
        reinterpret_cast<const uint8_t*>(pktData),
        static_cast<size_t>(header->caplen));

    // Skip non-IP noise
    if (pkt.getProtocolType() == "OTHER" &&
        pkt.getSourceAddress().getIpAddress() == "0.0.0.0")
        return;

    // Hand packet to firewall engine
    bool processed = eng->processPacket(pkt);
    if (processed) {
        std::cout << "[PacketSniffer] Packet captured: "
                  << pkt.displayPacketInfo() << "\n";
    }
}

void PacketSniffer::capturePacket() {
    if (!handle) return;
    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle, &header, &data);
    if (res == 1) {
        NetworkPacket pkt = NetworkPacket::fromRawBytes(
            reinterpret_cast<const uint8_t*>(data),
            static_cast<size_t>(header->caplen));
        engine.processPacket(pkt);
    }
}
