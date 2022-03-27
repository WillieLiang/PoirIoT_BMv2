#include <core.p4>
#include <v1model.p4>

// Constants

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 0x06;

#define REGESTER_ZISE 4096
#define TIMEOUT 91552
#define CONNECTIONS 65535
#define DEVICES 256
#define DEV_WIDTH 32
#define CONNECTIONS 65535

// Header

typedef bit<9>  egressSpec_t;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header update_t {
    bit<32> next_state;
    bit<(DEV_WIDTH)> device_id;
}

//struct state_hdr {
//    update_t update_hdr;
//}

struct metadata {
    // empty
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    update_t     update;
}



// Parser

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
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
}

// Checksum verification

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

// Ingress

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    // set variables
    bit<32> curr_state = 0;
    bit<32> check_state;
    bit<32> update_state;
    bit<32> state_size;

    ip4Addr_t hash_key;
    bit<32> hash_index;
    bit<32> storage_index;

    bit<8> direction = 0;
    bit<8> result = 0;

    bit<48> time_check;
    bit<48> curr_time;
    bit<48> elapsed_time;

//    bit<32> dev_id;
//    bit<32> next_state;

    bit<32> timeout_update;
    bit<32> event_update;
    bit<32> device_update;

    bit<2> timeout_index = 0;


    register<bit<32>>(DEVICES) device_counter;
    register<bit<32>>(DEVICES) event_counter;
    counter(DEVICES, CounterType.packets) timeout_counter;

    register<bit<48>>(CONNECTIONS) timer;
    register<bit<32>>(CONNECTIONS) reg_state;

    action set_state(bit<32> new_state, bit<8> dev_id){
        hdr.update.next_state = new_state;
        hdr.update.device_id = (bit<32>) dev_id;
//        state_md.update_hdr.next_state = new_state;
//        state_md.update_hdr.device_id = dev_id;
    }

    action set_direction(bit<8> dir) {
        direction = dir;
    }

    action count_event(inout bit<32> event_index){
        event_counter.read(event_update, event_index);
        event_update = event_update + 1;
        event_counter.write(event_index, event_update);
    }

    action count_device(inout bit<32> device_index){
        event_counter.read(event_update, device_index);
        device_counter.read(device_update, device_index);
        if (event_update == 1){
            device_update = device_update + 1;
        }
        device_counter.write(device_index, device_update);
    }

//    action count_timeout(bit<2> index){
//        timeout_counter.count(index);
//    }

    action reset_timer(bit<32> index){
        curr_time = standard_metadata.ingress_global_timestamp;
        timer.write(index, curr_time);
    }

    action time_compute(bit<32> index){
        timer.read(time_check, index);
        curr_time = standard_metadata.ingress_global_timestamp;
        elapsed_time = curr_time - time_check;
    }



    table length_filter {
        key = {
            hdr.ipv4.totalLen: exact;
        }
        actions = {
            NoAction;
        }
        size = 2048;
    }

    table check_direction {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            set_direction;
        }
        size = 2;
    }

    table signature_transition {
        key = {
            hdr.ipv4.totalLen: exact;
            curr_state: exact;
            direction: exact;
        }
        actions = {
            set_state;
            NoAction;
        }
        size = 16384;
        default_action = NoAction();
    }


    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid()) {
                if (length_filter.apply().hit) {

                    check_direction.apply();

                    if (direction == 1) {
                        hash_key = hdr.ipv4.dstAddr;
                    }
                    else {
                        hash_key = hdr.ipv4.srcAddr;
                    }

                    hash(hash_index, HashAlgorithm.crc16, (bit<32>)0, {hash_key}, (bit<32>)REGESTER_ZISE);


                    reset_timer(hash_index);



                    reg_state.read(curr_state, hash_index);
                    if (signature_transition.apply().hit){
//                        if (state_md.update_hdr.next_state == 0){
                        if (hdr.update.next_state == 0){
                            reg_state.write(hash_index, 0);
                            result = 1;
                        }
                    }


                    if (result == 1){
                        count_event(hdr.update.device_id);
                        count_device(hdr.update.device_id);
//                        count_event(hash_index);
//                        count_device(hash_index);
                    }
                    else {
                        time_compute(hash_index);
                        if (elapsed_time > TIMEOUT){
                            reg_state.write(hash_index, 0);
//                            set_state(0, 0);
//                            timeout_counter(timeout_index);
                            timeout_counter.count(0);
                        }
                        reset_timer(hash_index);
                    }
                }
            }
        }
    }



}

// Egress

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        
    }
}

// Checksum computation

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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

// Deparser

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

// Switch

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;