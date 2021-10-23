// Constants

#define CPU_PORT        509
#define DROP_PORT       510
#define BROADCAST_PORT  511

#define TABLE_SIZE      1024

// Headers

header ethernet_t {
    mac_addr_t  dstAddr;
    mac_addr_t  srcAddr;
    bit<16>     etherType;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ipv4_addr_t srcAddr;
    ipv4_addr_t dstAddr;
}

header tcp_udp_t {
    tcp_udp_port_t  srcPort;
    tcp_udp_port_t  dstPort;
}

header tcp_t {
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum; // Includes Pseudo Hdr + TCP segment (hdr + payload)
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

// Structs

struct headers {
    packet_in_t     packet_in;
    packet_out_t    packet_out;
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_udp_t       tcp_udp;
    tcp_t           tcp;
    udp_t           udp;
    icmp_t          icmp;
}