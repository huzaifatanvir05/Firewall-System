#include <iostream>
#include <pcap.h>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

int main()
{
    // Initialize Winsock
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        cout << "Winsock initialization failed."
             << endl;

        return 1;
    }

    pcap_if_t* alldevs;
    pcap_if_t* device;

    char errbuf[PCAP_ERRBUF_SIZE];

    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cout << "Error finding devices: "
             << errbuf << endl;

        return 1;
    }

    // ================= SELECT REAL NETWORK ADAPTER =================
    device = alldevs;

    while (device != NULL)
    {
        if (device->description)
        {
            if (strstr(device->description, "Wi-Fi") ||
                strstr(device->description, "Intel") ||
                strstr(device->description, "Realtek"))
            {
                break;
            }
        }

        device = device->next;
    }

    // If no suitable adapter found
    if (device == NULL)
    {
        cout << "No suitable adapter found."
             << endl;

        pcap_freealldevs(alldevs);

        return 1;
    }

    cout << "Capturing on: "
         << device->name << endl;

    cout << "Description: "
         << device->description
         << endl;

    // ================= OPEN ADAPTER =================
    pcap_t* handle = pcap_open_live(
        device->name,
        65536,
        1,
        1000,
        errbuf
    );

    if (handle == NULL)
    {
        cout << "Unable to open adapter: "
             << errbuf << endl;

        pcap_freealldevs(alldevs);

        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* data;

    // ================= CAPTURE 20 PACKETS =================
    for (int packetNo = 1;
         packetNo <= 20;
         packetNo++)
    {
        int result = pcap_next_ex(
            handle,
            &header,
            &data
        );

        if (result == 1)
        {
            cout << "\n========================";
            cout << "\nPacket #"
                 << packetNo << endl;

            cout << "Length: "
                 << header->len
                 << " bytes" << endl;

            // Ethernet Type
            uint16_t ethType =
                (data[12] << 8) | data[13];

            // ================= IPv4 =================
            if (ethType == 0x0800)
            {
                cout << "IP Version: IPv4"
                     << endl;

                struct in_addr srcIP;
                struct in_addr dstIP;

                memcpy(
                    &srcIP,
                    data + 26,
                    4
                );

                memcpy(
                    &dstIP,
                    data + 30,
                    4
                );

                char srcBuffer[INET_ADDRSTRLEN];
                char dstBuffer[INET_ADDRSTRLEN];

                inet_ntop(
                    AF_INET,
                    &srcIP,
                    srcBuffer,
                    INET_ADDRSTRLEN
                );

                inet_ntop(
                    AF_INET,
                    &dstIP,
                    dstBuffer,
                    INET_ADDRSTRLEN
                );

                cout << "Source IP: "
                     << srcBuffer << endl;

                cout << "Destination IP: "
                     << dstBuffer << endl;

                // IPv4 Protocol
                unsigned char protocol =
                    data[23];

                if (protocol == 6)
                {
                    cout << "Protocol: TCP"
                         << endl;
                }
                else if (protocol == 17)
                {
                    cout << "Protocol: UDP"
                         << endl;
                }
                else if (protocol == 1)
                {
                    cout << "Protocol: ICMP"
                         << endl;
                }
                else
                {
                    cout << "Protocol: Other"
                         << endl;
                }
            }

            // ================= IPv6 =================
            else if (ethType == 0x86DD)
            {
                cout << "IP Version: IPv6"
                     << endl;

                char srcIPv6[INET6_ADDRSTRLEN];
                char dstIPv6[INET6_ADDRSTRLEN];

                inet_ntop(
                    AF_INET6,
                    data + 22,
                    srcIPv6,
                    sizeof(srcIPv6)
                );

                inet_ntop(
                    AF_INET6,
                    data + 38,
                    dstIPv6,
                    sizeof(dstIPv6)
                );

                cout << "Source IPv6: "
                     << srcIPv6 << endl;

                cout << "Destination IPv6: "
                     << dstIPv6 << endl;

                // IPv6 Next Header
                unsigned char protocol =
                    data[20];

                if (protocol == 6)
                {
                    cout << "Protocol: TCP"
                         << endl;
                }
                else if (protocol == 17)
                {
                    cout << "Protocol: UDP"
                         << endl;
                }
                else if (protocol == 58)
                {
                    cout << "Protocol: ICMPv6"
                         << endl;
                }
                else
                {
                    cout << "Protocol: Other"
                         << endl;
                }
            }

            else
            {
                cout << "Non-IP Packet"
                     << endl;
            }

            // ================= RAW DATA =================
            cout << "Data: ";

            for (unsigned int i = 0;
                 i < 32 && i < header->len;
                 i++)
            {
                printf("%02x ",
                       data[i]);
            }

            cout << endl;
        }

        else if (result == 0)
        {
            // timeout
            packetNo--;
        }

        else
        {
            cout << "Packet capture error."
                 << endl;

            break;
        }
    }

    // ================= CLEANUP =================
    pcap_close(handle);

    pcap_freealldevs(alldevs);

    WSACleanup();

    return 0;
}