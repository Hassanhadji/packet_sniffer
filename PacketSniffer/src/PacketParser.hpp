#pragma once
#include "Packet.hpp"
#include <cstdint>
#include <string>

class PacketParser {
public:
    void parseAndPrint(const RawPacket& pkt);
private:
    std::string macToString(const uint8_t* mac);
    std::string ipToString(uint32_t ip_be);
};
