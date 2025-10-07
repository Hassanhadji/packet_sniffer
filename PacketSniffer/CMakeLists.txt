cmake_minimum_required(VERSION 3.10)
project(PacketSniffer CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(packetsniffer
    src/main.cpp
    src/PacketCapture.cpp
    src/PacketParser.cpp
)

target_include_directories(packetsniffer PRIVATE include src)

find_package(Threads REQUIRED)
find_library(PCAP_LIB pcap)

if(NOT PCAP_LIB)
    message(FATAL_ERROR "libpcap not found. Install libpcap-dev.")
endif()

target_link_libraries(packetsniffer PRIVATE Threads::Threads ${PCAP_LIB})
