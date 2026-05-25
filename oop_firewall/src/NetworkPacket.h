#pragma once
#include <string>
#include <vector>
#include <mutex>
#include "NetworkAddress.h"

// ── Raw packet structures (parsed from pcap frames) ───────────────────────────
#pragma pack(push, 1)
struct EthernetHeader {
    uint8_t  dstMac[6];
    uint8_t  srcMac[6];
    uint16_t etherType;
};

struct IPv4Header {
    uint8_t  versionIHL;
    uint8_t  dscp;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsFragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t srcAddr;
    uint32_t dstAddr;
};

struct TcpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t  dataOffset;
    uint8_t  flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPtr;
};

struct UdpHeader {
    uint16_t srcPort;
    uint16_t dstPort;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

// ── High-level packet representation ─────────────────────────────────────────
class NetworkPacket {
private:
    NetworkAddress sourceAddress;
    NetworkAddress destinationAddress;
    std::string    protocolType;     // "TCP" / "UDP" / "ICMP" / "OTHER"
    int            destinationPort;
    int            sourcePort;
    int            checksumValue;
    std::vector<uint8_t> payloadData;

public:
    NetworkPacket();
    NetworkPacket(const NetworkAddress& src,
                  const NetworkAddress& dst,
                  const std::string& proto,
                  int srcPort,
                  int dstPort);

    // Factory: parse from raw pcap frame
    static NetworkPacket fromRawBytes(const uint8_t* data, size_t length);

    // Getters
    NetworkAddress getSourceAddress()      const { return sourceAddress;      }
    NetworkAddress getDestinationAddress() const { return destinationAddress; }
    std::string    getProtocolType()       const { return protocolType;       }
    int            getDestinationPort()    const { return destinationPort;    }
    int            getSourcePort()         const { return sourcePort;         }
    int            getChecksumValue()      const { return checksumValue;      }
    const std::vector<uint8_t>& getPayload() const { return payloadData;     }

    bool validateChecksum() const;
    std::string displayPacketInfo() const;

private:
    static std::string macToString(const uint8_t mac[6]);
    static uint16_t ntohs_local(uint16_t v);
    static uint32_t ntohl_local(uint32_t v);
};
