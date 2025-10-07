#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <csignal>
#include <getopt.h>

#include "ThreadSafeQueue.hpp"
#include "Packet.hpp"
#include "PacketCapture.hpp"
#include "PacketParser.hpp"

static std::atomic<bool> g_stop(false);

void signal_handler(int) {
    g_stop = true;
    std::cerr << "\n[Signal] Stopping...\n";
}

int main(int argc, char** argv) {
    std::string iface;
    std::string filter;
    int threads = 2;

    int opt;
    while ((opt = getopt(argc, argv, "i:f:t:h")) != -1) {
        switch (opt) {
            case 'i': iface = optarg; break;
            case 'f': filter = optarg; break;
            case 't': threads = std::max(1, atoi(optarg)); break;
            case 'h':
            default:
                std::cout << "Usage: " << argv[0] << " -i <iface> [-f <bpf_filter>] [-t <threads>]\n";
                return 0;
        }
    }

    if (iface.empty()) {
        std::cerr << "Error: network interface required (use -i).\n";
        return 1;
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    ThreadSafeQueue<RawPacket> queue;
    PacketCapture capt(iface, filter, queue);
    if (!capt.open()) return 2;

    std::thread capThread([&]{
        capt.run();
        g_stop = true; // ensure parsers exit if capture ends
    });

    std::vector<std::thread> workers;
    PacketParser parser;
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&]{
            while (!g_stop) {
                auto item = queue.pop_blocking(reinterpret_cast<bool&>(g_stop));
                if (!item.has_value()) continue;
                parser.parseAndPrint(item.value());
            }
        });
    }

    // Wait for signal
    while (!g_stop) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    capt.stop();
    if (capThread.joinable()) capThread.join();
    for (auto& w : workers) if (w.joinable()) w.join();

    std::cerr << "[OK] Clean exit.\n";
    return 0;
}
