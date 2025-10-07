#include "PacketCapture.hpp"
#include <iostream>
#include <vector>

PacketCapture::PacketCapture(const std::string& iface, const std::string& bpf_filter, ThreadSafeQueue<RawPacket>& outQ)
    : iface_(iface), filter_(bpf_filter), outQ_(outQ) {}

PacketCapture::~PacketCapture() {
    stop();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketCapture::open() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    // snapshot length 65535, promiscuous 1, timeout 1000ms
    handle_ = pcap_open_live(iface_.c_str(), 65535, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return false;
    }

    // Apply BPF filter if provided
    if (!filter_.empty()) {
        bpf_program prog{};
        if (pcap_compile(handle_, &prog, filter_.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "pcap_compile failed: " << pcap_geterr(handle_) << std::endl;
            return false;
        }
        if (pcap_setfilter(handle_, &prog) == -1) {
            std::cerr << "pcap_setfilter failed: " << pcap_geterr(handle_) << std::endl;
            pcap_freecode(&prog);
            return false;
        }
        pcap_freecode(&prog);
    }

    return true;
}

void PacketCapture::run() {
    if (!handle_) {
        std::cerr << "Handle not opened.\n";
        return;
    }
    running_ = true;

    while (running_) {
        pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle_, &header, &packet);
        if (res == 0) continue; // timeout
        if (res == -1) {
            std::cerr << "pcap_next_ex error: " << pcap_geterr(handle_) << std::endl;
            break;
        }
        if (res == -2) break; // EOF (offline capture)

        RawPacket rp;
        rp.ts = header->ts;
        rp.data.assign(packet, packet + header->caplen);
        outQ_.push(std::move(rp));
    }
}

void PacketCapture::stop() {
    running_ = false;
}
