#include "PacketParser.hpp"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

std::string PacketParser::macToString(const uint8_t* mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(2) << (int)mac[0] << ":"
        << std::setw(2) << (int)mac[1] << ":"
        << std::setw(2) << (int)mac[2] << ":"
        << std::setw(2) << (int)mac[3] << ":"
        << std::setw(2) << (int)mac[4] << ":"
        << std::setw(2) << (int)mac[5];
    return oss.str();
}

std::string PacketParser::ipToString(uint32_t ip_be) {
    struct in_addr addr;
    addr.s_addr = ip_be;
    return std::string(inet_ntoa(addr));
}

void PacketParser::parseAndPrint(const RawPacket& pkt) {
    if (pkt.data.size() < sizeof(ether_header)) return;

    const ether_header* eth = reinterpret_cast<const ether_header*>(pkt.data.data());
    uint16_t eth_type = ntohs(eth->ether_type);

    // Ethernet summary
    std::cout << "[ETH] " << macToString(eth->ether_shost)
              << " -> " << macToString(eth->ether_dhost) << " | ";

    if (eth_type == ETHERTYPE_IP) {
        const uint8_t* ip_start = pkt.data.data() + sizeof(ether_header);
        if (pkt.data.size() < sizeof(ether_header) + sizeof(iphdr)) {
            std::cout << "Truncated IPv4\n";
            return;
        }
        const iphdr* ip = reinterpret_cast<const iphdr*>(ip_start);
        size_t ip_hdr_len = ip->ihl * 4;
        if (pkt.data.size() < sizeof(ether_header) + ip_hdr_len) {
            std::cout << "Truncated IPv4 (ihl)\n";
            return;
        }

        std::string s = ipToString(ip->saddr);
        std::string d = ipToString(ip->daddr);

        if (ip->protocol == IPPROTO_TCP) {
            const uint8_t* tcp_start = ip_start + ip_hdr_len;
            if (pkt.data.size() < sizeof(ether_header) + ip_hdr_len + sizeof(tcphdr)) {
                std::cout << "IPv4 TCP (truncated)\n";
                return;
            }
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(tcp_start);
            std::cout << "[TCP] " << s << ":" << ntohs(tcp->source)
                      << " -> " << d << ":" << ntohs(tcp->dest)
                      << " | Len: " << pkt.data.size() << "\n";
        } else if (ip->protocol == IPPROTO_UDP) {
            const uint8_t* udp_start = ip_start + ip_hdr_len;
            if (pkt.data.size() < sizeof(ether_header) + ip_hdr_len + sizeof(udphdr)) {
                std::cout << "IPv4 UDP (truncated)\n";
                return;
            }
            const udphdr* udp = reinterpret_cast<const udphdr*>(udp_start);
            std::cout << "[UDP] " << s << ":" << ntohs(udp->source)
                      << " -> " << d << ":" << ntohs(udp->dest)
                      << " | Len: " << pkt.data.size() << "\n";
        } else {
            std::cout << "[IPv4 proto=" << (int)ip->protocol << "] "
                      << s << " -> " << d
                      << " | Len: " << pkt.data.size() << "\n";
        }
    } else {
        std::cout << "Ethertype=0x" << std::hex << eth_type << std::dec
                  << " | Len: " << pkt.data.size() << "\n";
    }
}
