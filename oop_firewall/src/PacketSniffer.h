#pragma once
#include "SecurityComponent.h"
#include "FirewallEngine.h"
#include <string>
#include <atomic>
#include <thread>
#include <functional>

// Forward-declare pcap types to avoid header collisions
struct pcap;
typedef pcap pcap_t;
struct pcap_if;
typedef pcap_if pcap_if_t;

class PacketSniffer : public SecurityComponent {
public:
    struct InterfaceInfo {
        std::string name;
        std::string description;
    };

private:
    std::string              networkInterface;
    pcap_t*                  handle;
    std::vector<uint8_t>     packetBuffer;
    FirewallEngine&          engine;
    std::atomic<bool>        capturing;
    std::thread              captureThread;
    std::string              captureFilter;  // BPF filter expression

public:
    explicit PacketSniffer(FirewallEngine& eng);
    ~PacketSniffer();

    // SecurityComponent
    bool initialize() override;
    void shutdown()   override;

    // Configuration
    void setInterface    (const std::string& iface) { networkInterface = iface; }
    void setCaptureFilter(const std::string& bpf)   { captureFilter = bpf;     }
    std::string getInterface() const { return networkInterface; }

    // Capture control
    bool startCapture();
    void stopCapture ();
    bool isCapturing () const { return capturing.load(); }

    // List all available interfaces
    static std::vector<InterfaceInfo> listInterfaces();

    // Single-packet capture (for manual/testing use)
    void capturePacket();

private:
    // Thread loop
    void captureLoop();

    // pcap callback (static, dispatched to engine)
    static void pcapCallback(unsigned char* userData,
                             const struct pcap_pkthdr* header,
                             const unsigned char* pktData);
};
