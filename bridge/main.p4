// P4-16

#include <core.p4>
#include <v1model.p4>

#include "../p4_include/typedefs.p4"

// Headers

@controller_header("packet_in")
header packet_in_t {
    port_t  ingress_port;
    bit<7>  padding;
}

@controller_header("packet_out")
header packet_out_t {
    port_t  ingress_port;
    bit<7>  padding;
}

struct metadata {
    bit<16> tcpLen;
}

#include "../p4_include/headers.p4"
#include "../p4_include/parsers.p4"

// Ingress processing

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action send_to_controller() {
        standard_metadata.egress_spec = CPU_PORT;

        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    table mac_src {
        key = {
            hdr.ethernet.srcAddr:   exact;
        }

        actions = {
            send_to_controller;
            NoAction;
        }

        support_timeout = true;
        size = 65536;
        default_action = send_to_controller;
    }

    action flood() {
        standard_metadata.mcast_grp = (mcast_group_t) 1;
    }

    action forward(port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table mac_dst {
        key = {
            hdr.ethernet.dstAddr:   exact;
        }

        actions = {
            flood;
            forward;
        }

        support_timeout = true;
        size = 65536;
        default_action = flood;
    }

    apply {
        if (CPU_PORT == standard_metadata.ingress_port) {
            mac_dst.apply();
        
        } else {
            if (mac_src.apply().hit) {
                mac_dst.apply();
            }
        }
    }
}

// Egress processing

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (CPU_PORT == standard_metadata.ingress_port) {
            if (hdr.packet_out.isValid() &&
                hdr.packet_out.ingress_port == standard_metadata.egress_port) {
                
                drop();
            }

        } else {
            if (standard_metadata.ingress_port == standard_metadata.egress_port) {
                drop();
            }

        }
    }
}

// Switch architecture

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()

) main;