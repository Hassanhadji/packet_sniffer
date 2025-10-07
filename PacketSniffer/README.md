# PacketSniffer (C++ / libpcap)
A simple **multithreaded network packet sniffer** written in **C++17** for Linux.  
It captures packets using **libpcap**, parses Ethernet/IP/TCP/UDP headers in worker threads, and prints a concise summary.

> ⚠️ **Ethical & Legal Notice:** Capture only traffic you are authorized to inspect. Sniffing networks without consent may be illegal.

## Features
- Producer/consumer design: **1 capture thread** + **N parser threads**
- **BPF filter** support (e.g., `tcp`, `udp`, `tcp port 443`, `host 8.8.8.8`)
- Parses **Ethernet**, **IPv4**, **TCP/UDP** headers and prints summaries
- Graceful shutdown on **Ctrl-C**
- Build with **CMake**; runs on Linux with **libpcap**

## Prerequisites
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev

# (Optional) Run without sudo by granting raw socket capability:
# After building, from project root:
sudo setcap cap_net_raw,cap_net_admin=eip build/packetsniffer
```

## Build
```bash
mkdir -p build
cd build
cmake ..
make -j
```

## Usage
```bash
# Basic (requires sudo unless you granted capabilities)
sudo ./packetsniffer -i eth0

# With filter (only TCP or UDP)
sudo ./packetsniffer -i eth0 -f "tcp or udp"

# Increase parser threads
sudo ./packetsniffer -i eth0 -t 4
```

**Find your interface name** with:
```bash
ip -br link    # or: ip link, ifconfig -a
```

## Project Structure
```
PacketSniffer/
├─ include/
│  ├─ ThreadSafeQueue.hpp
│  └─ Packet.hpp
├─ src/
│  ├─ PacketCapture.hpp
│  ├─ PacketCapture.cpp
│  ├─ PacketParser.hpp
│  └─ PacketParser.cpp
├─ src/main.cpp
└─ CMakeLists.txt
```

## Roadmap
- [ ] Output to `.pcap` file
- [ ] IPv6 parsing
- [ ] Colored output & JSON logs
- [ ] Unit tests (Catch2)
- [ ] Perf counters (packets/sec, drops)

## License
MIT
