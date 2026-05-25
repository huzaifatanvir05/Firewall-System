#include "NetworkPacket.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <iostream>

// ── byte-order helpers (avoid winsock conflicts) ──────────────────────────────
uint16_t NetworkPacket::ntohs_local(uint16_t v) {
    return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF);
}
uint32_t NetworkPacket::ntohl_local(uint32_t v) {
    return ((v & 0xFF)       << 24) |
           (((v >> 8)  & 0xFF) << 16) |
           (((v >> 16) & 0xFF) <<  8) |
           ((v >> 24) & 0xFF);
}

std::string NetworkPacket::macToString(const uint8_t mac[6]) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i) oss << ":";
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

NetworkPacket::NetworkPacket()
    : protocolType("OTHER"), destinationPort(0), sourcePort(0), checksumValue(0) {}

NetworkPacket::NetworkPacket(const NetworkAddress& src,
                             const NetworkAddress& dst,
                             const std::string& proto,
                             int srcPort,
                             int dstPort)
    : sourceAddress(src), destinationAddress(dst),
      protocolType(proto), destinationPort(dstPort),
      sourcePort(srcPort), checksumValue(0) {}

// ── Main parser from raw bytes ────────────────────────────────────────────────
NetworkPacket NetworkPacket::fromRawBytes(const uint8_t* data, size_t length) {
    NetworkPacket pkt;

    if (length < sizeof(EthernetHeader)) return pkt;

    const auto* eth = reinterpret_cast<const EthernetHeader*>(data);
    uint16_t etherType = ntohs_local(eth->etherType);

    std::string srcMac = macToString(eth->srcMac);
    std::string dstMac = macToString(eth->dstMac);

    // Only handle IPv4 (0x0800) for now
    if (etherType != 0x0800) {
        pkt.protocolType = "OTHER";
        return pkt;
    }

    if (length < sizeof(EthernetHeader) + sizeof(IPv4Header)) return pkt;

    const auto* ip = reinterpret_cast<const IPv4Header*>(data + sizeof(EthernetHeader));
    int ihl = (ip->versionIHL & 0x0F) * 4;

    // Build IP strings
    auto ipToStr = [](uint32_t addr) -> std::string {
        uint8_t* b = reinterpret_cast<uint8_t*>(&addr);
        return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
               std::to_string(b[2]) + "." + std::to_string(b[3]);
    };

    std::string srcIp = ipToStr(ip->srcAddr);
    std::string dstIp = ipToStr(ip->dstAddr);

    pkt.sourceAddress      = NetworkAddress(srcIp, srcMac, 4);
    pkt.destinationAddress = NetworkAddress(dstIp, dstMac, 4);
    pkt.checksumValue      = ntohs_local(ip->checksum);

    size_t ipPayloadOffset = sizeof(EthernetHeader) + ihl;

    switch (ip->protocol) {
        case 6: {  // TCP
            pkt.protocolType = "TCP";
            if (length >= ipPayloadOffset + sizeof(TcpHeader)) {
                const auto* tcp = reinterpret_cast<const TcpHeader*>(data + ipPayloadOffset);
                pkt.sourcePort      = ntohs_local(tcp->srcPort);
                pkt.destinationPort = ntohs_local(tcp->dstPort);

                // Copy payload
                size_t tcpHdrLen = ((tcp->dataOffset >> 4) & 0xF) * 4;
                size_t payloadStart = ipPayloadOffset + tcpHdrLen;
                if (payloadStart < length)
                    pkt.payloadData.assign(data + payloadStart, data + length);
            }
            break;
        }
        case 17: { // UDP
            pkt.protocolType = "UDP";
            if (length >= ipPayloadOffset + sizeof(UdpHeader)) {
                const auto* udp = reinterpret_cast<const UdpHeader*>(data + ipPayloadOffset);
                pkt.sourcePort      = ntohs_local(udp->srcPort);
                pkt.destinationPort = ntohs_local(udp->dstPort);

                size_t payloadStart = ipPayloadOffset + sizeof(UdpHeader);
                if (payloadStart < length)
                    pkt.payloadData.assign(data + payloadStart, data + length);
            }
            break;
        }
        case 1:  // ICMP
            pkt.protocolType = "ICMP";
            break;
        default:
            pkt.protocolType = "OTHER";
            break;
    }

    return pkt;
}

bool NetworkPacket::validateChecksum() const {
    // Basic non-zero check; full IP checksum validation would be done inline
    return checksumValue != 0;
}

std::string NetworkPacket::displayPacketInfo() const {
    std::ostringstream oss;
    oss << "[PKT] " << protocolType
        << " | " << sourceAddress.getIpAddress() << ":" << sourcePort
        << " -> " << destinationAddress.getIpAddress() << ":" << destinationPort
        << " | len=" << payloadData.size() << "B";
    return oss.str();
}
