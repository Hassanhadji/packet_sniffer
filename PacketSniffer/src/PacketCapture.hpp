#pragma once
#include <string>
#include <atomic>
#include <pcap.h>
#include "ThreadSafeQueue.hpp"
#include "Packet.hpp"

class PacketCapture {
public:
    PacketCapture(const std::string& iface, const std::string& bpf_filter, ThreadSafeQueue<RawPacket>& outQ);
    ~PacketCapture();

    bool open();
    void run();
    void stop();

private:
    std::string iface_;
    std::string filter_;
    ThreadSafeQueue<RawPacket>& outQ_;
    pcap_t* handle_ = nullptr;
    std::atomic<bool> running_{false};
};
