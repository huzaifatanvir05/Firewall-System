#include <pcap.h>
#include <iostream>
#include <cstring>

struct ip_header {
    unsigned char  ver_ihl;
    unsigned char  tos;
    unsigned short total_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short checksum;
    unsigned int   src_ip;
    unsigned int   dst_ip;
};

void print_ip(unsigned int ip) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    std::cout << (int)bytes[3] << "."
              << (int)bytes[2] << "."
              << (int)bytes[1] << "."
              << (int)bytes[0];
}

int main() {
    pcap_if_t *allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        std::cerr << "Error: " << errbuf << std::endl;
        return 1;
    }

    // Show adapters
    std::cout << "Available adapters:\n";
    pcap_if_t *devices[100];
    int count = 0;
    for (pcap_if_t *dev = allDevs; dev != nullptr; dev = dev->next) {
        if (count < 100) devices[count] = dev;
        std::cout << ++count << ". " << dev->name;
        if (dev->description)
            std::cout << " (" << dev->description << ")";
        std::cout << std::endl;
    }

    // Ask user to pick
    std::cout << "\nPick your active adapter (e.g., 4 for Intel WiFi, 9 for Intel Ethernet): ";
    int choice;
    std::cin >> choice;

    if (choice < 1 || choice > count) {
        std::cerr << "Invalid choice.\n";
        pcap_freealldevs(allDevs);
        return 1;
    }

    pcap_if_t *chosen = devices[choice - 1];
    std::cout << "Using: " << chosen->name
              << " (" << (chosen->description ? chosen->description : "") << ")\n";

    // Open adapter
    pcap_t *handle = pcap_open_live(chosen->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "Could not open: " << errbuf << std::endl;
        pcap_freealldevs(allDevs);
        return 1;
    }

    std::cout << "\nCapturing 50 packets... (open a website to generate traffic)\n\n";

    int packet_count = 0;
    struct pcap_pkthdr *header;
    const unsigned char *packet;

    while (packet_count < 50) {
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;

        unsigned short eth_type = (packet[12] << 8) | packet[13];
        if (eth_type == 0x0800) {  // IPv4
            ip_header *ip = (ip_header*)(packet + 14);
            ++packet_count;
            std::cout << "#" << packet_count << " | SRC: ";
            print_ip(ip->src_ip);
            std::cout << " | DST: ";
            print_ip(ip->dst_ip);
            std::cout << " | Proto: ";
            switch(ip->protocol) {
                case 6:  std::cout << "TCP"; break;
                case 17: std::cout << "UDP"; break;
                case 1:  std::cout << "ICMP"; break;
                default: std::cout << (int)ip->protocol; break;
            }
            std::cout << " | Len: " << ntohs(ip->total_len) << " bytes\n";
        }
    }

    std::cout << "\nDone.\n";
    pcap_close(handle);
    pcap_freealldevs(allDevs);
    return 0;
}