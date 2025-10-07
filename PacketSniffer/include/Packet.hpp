#pragma once
#include <vector>
#include <cstdint>
#include <sys/time.h>

struct RawPacket {
    timeval ts{};                 // timestamp
    std::vector<uint8_t> data;    // raw bytes
};
