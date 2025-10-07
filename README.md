Capture live packets from a selected network interface

Display basic packet metadata: timestamp, source/destination IP, ports, protocol, length

Apply BPF-style capture filters (e.g., udp port 137, arp, icmp, tcp port 80)

Optional: decode common protocols (HTTP summary, DNS names, NetBIOS name queries)

Save captures to pcap files for later analysis in Wireshark

Cross-platform guidance for Linux/macOS/Windows (where supported)

Build & install instructions:
# deps (Ubuntu/Debian)
navigate to file path
sudo apt update
sudo apt install -y build-essential cmake libpcap-dev
 Build
bash
Copy code 
mkdir -p build
cd build
cmake ..
make -j
# find your interface (examples: eth0, enp3s0, wlp2s0)
ip -br link



# run (show all traffic)
sudo ./packetsniffer -i eth0

# filter by protocol (BPF filter)
sudo ./packetsniffer -i eth0 -f "tcp or udp"

# use more parser threads
sudo ./packetsniffer -i eth0 -t 4

Saving & reading captures (.pcap)

Save live captures with -w output.pcap.

