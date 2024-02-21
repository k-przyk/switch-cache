/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// Protocol Header Constants
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 0x11; 

// Response/Request Constants
const bit<16> PORT_UDP = 0x4D2; // ie. port 1234

typedef bit<9>  egressSpec_t;
typedef bit<16> portAddr_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    portAddr_t srcPort;
    portAddr_t dstPort;
    bit<16>    length;
    bit<16>    checksum;
}

header request_t {
    bit<8>     key;
}

header response_t {
    bit<8>     key;
    bit<8>     is_valid;
    bit<32>    value;
}

struct metadata { }

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;

    // UDP protocol
    udp_t        udp;

    // One or the other
    request_t    request;
    response_t   response;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp_request;
            default: accept;
        }
    }

    // Determine if destination port matches -> request
    state parse_udp_request {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            PORT_UDP: parse_request;
            default: parse_udp_response;
        }
    }

    // Determine if source port matches -> response
    state parse_udp_response {
        transition select(hdr.udp.srcPort) {
            PORT_UDP: parse_response;
            default: accept; // Matches neither
        }
    }

    state parse_request {
        packet.extract(hdr.request);
        transition accept;
    }

    state parse_response {
        packet.extract(hdr.response);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   **********{
    default_action = set_default_value;
}*********
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<32>>(256) cache_key;
    register<bit<32>>(256) cache_value;

    action drop() {
        mark_to_drop(standard_metadata);
    }
 
    action cache_hit(bit<32> value) {

        ip4Addr_t tmpDstIp = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = tmpDstIp;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5;

        bit<16> tmpDstPort = hdr.udp.dstPort;
        hdr.udp.dstPort = hdr.udp.srcPort;
        hdr.udp.srcPort = tmpDstPort; // PORT_UDP;
        hdr.udp.length = hdr.udp.length + 5;
        hdr.udp.checksum = 0;

        hdr.response.setValid();
        hdr.response.key = hdr.request.key;
        hdr.response.is_valid = 1;
        hdr.response.value = value;
        hdr.request.setInvalid();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // IPV4 table
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    // Cache table
    table cache {
        key = {
            hdr.request.key: exact;
        }
        actions = {
            cache_hit; 
            NoAction;  // Cache miss
        }
        size = 1024; 
        default_action = NoAction;
    }

    apply {
        if (!hdr.ipv4.isValid()) { return; }

        // if request
        if (hdr.request.isValid()) {
            if (!cache.apply().hit) { 

                // Check that key is valid 
                bit<32> valid_key; 
                cache_key.read(valid_key, (bit<32>) hdr.request.key); 

                if(valid_key == 0x1) { // Key is valid

                    // Retrieve value
                    bit<32> value; 
                    cache_value.read(value, (bit<32>) hdr.request.key); 
                    cache_hit(value); 
                }
            }
        }
        // if response
        else if (hdr.response.isValid()) {
            if (hdr.response.is_valid != 0) {
                cache_key.write((bit<32>) hdr.response.key, (bit<32>) hdr.response.is_valid);
                cache_value.write((bit<32>) hdr.response.key, hdr.response.value); 
            }
        }

        ipv4_lpm.apply();
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp); 
        packet.emit(hdr.request);
        packet.emit(hdr.response);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
