#include <core.p4>
#include <tna.p4>

enum bit<16> ether_type_t {
    TPID = 0x8100,
    IPV4 = 0x0800,
    ARP  = 0x0806,
    IPV6 = 0x86DD,
    MPLS = 0x8847
}

enum bit<8> ip_protocol_t {
    ICMP = 1,
    IGMP = 2,
    TCP  = 6,
    UDP  = 17
}

enum bit<8> icmp_type_t {
    ECHO_REPLY   = 0,
    ECHO_REQUEST = 8
}

enum bit<16> arp_opcode_t {
    REQUEST = 1,
    REPLY   = 2
}
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header ipv4_h {
    bit<4>          version;
    bit<4>          ihl;
    bit<8>          diffserv;
    bit<16>         total_len;
    bit<16>         identification;
    bit<3>          flags;
    bit<13>         frag_offset;
    bit<8>          ttl;
    ip_protocol_t   protocol;   
    bit<16>         hdr_checksum;
    ipv4_addr_t     src_addr;
    ipv4_addr_t     dst_addr;
}

header ipv4_options_h {
    varbit<320> data;
}


header icmp_h {
    icmp_type_t msg_type;  
    bit<8>      msg_code;
    bit<16>     checksum;
}

header arp_h {
    bit<16>       hw_type;
    ether_type_t  proto_type;
    bit<8>        hw_addr_len;
    bit<8>        proto_addr_len;
    arp_opcode_t  opcode;
} 

header arp_ipv4_h {
    mac_addr_t   src_hw_addr;
    ipv4_addr_t  src_proto_addr;
    mac_addr_t   dst_hw_addr;
    ipv4_addr_t  dst_proto_addr;
}

struct my_ingress_header_t{
    ethernet_h ethernet;
    arp_h arp;
    arp_ipv4_h arp_ipv4;
    ipv4_h ipv4;
    ipv4_options_h ipv4_option;
    icmp_h icmp;
}

struct my_Ingress_Metadata{
    ipv4_addr_t dst_ipv4;
}

parser myingressparser(packet_in pkt,
    out my_ingress_header_t hdr,
    out my_Ingress_Metadata meta,
    out ingress_intrinsic_metadata_t igmd)
{
    state start{
        pkt.extract(igmd);
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.ethernet);
        meta.dst_ipv4=0;
        transition select(hdr.ethernet.ether_type)
        {
            ether_type_t.IPV4: parserIPv4;
            ether_type_t.ARP : parserARP;
            default :accept;
        }
    }
    state parserIPv4{
        pkt.extract(hdr.ipv4);
        meta.dst_ipv4=hdr.ipv4.dst_addr;
        transition select(hdr.ipv4.ihl) {
            0x5 : parse_ipv4_no_options;
            0x6 &&& 0xE : parse_ipv4_options;
            0x8 &&& 0x8 : parse_ipv4_options;
            default: reject;
        }
    }
    
    state parse_ipv4_options{
        pkt.extract(hdr.ipv4_option,((bit<32>)hdr.ipv4.ihl - 32w5) * 32);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options{
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            ( 0, ip_protocol_t.ICMP ) : parse_icmp;        
            default     : accept;
        }
    }

    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parserARP{
        pkt.extract(hdr.arp);
        transition select(hdr.arp.hw_type,hdr.arp.proto_type)
        {
            (0x0001,ether_type_t.IPV4) :parser_ARP_IPV4;
            default: accept;
        }
    }

    state parser_ARP_IPV4 {
        pkt.extract(hdr.arp_ipv4);
        meta.dst_ipv4=hdr.arp_ipv4.dst_proto_addr;
        transition accept;
    }
}

control Ingress(inout my_ingress_header_t hdr,
    inout my_Ingress_Metadata myigmd,
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    action drop()
    {
        ig_dprsr_md.drop_ctl = 1;
    }

    action forward(PortId_t port)
    {
        ig_tm_md.ucast_egress_port=port;
    }

    action route(mac_addr_t next_dst_mac,PortId_t port)
    {
        hdr.ethernet.src_addr=hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr=next_dst_mac;
        ig_tm_md.ucast_egress_port=port;
    }

    action send_arp_reply(mac_addr_t mac_da) {
        hdr.ethernet.dst_addr = hdr.arp_ipv4.src_hw_addr;
        hdr.ethernet.src_addr = mac_da;
      
        hdr.arp.opcode = arp_opcode_t.REPLY;
        hdr.arp_ipv4.dst_hw_addr    = hdr.arp_ipv4.src_hw_addr;
        hdr.arp_ipv4.dst_proto_addr = hdr.arp_ipv4.src_proto_addr;
        hdr.arp_ipv4.src_hw_addr    = mac_da;
        hdr.arp_ipv4.src_proto_addr = myigmd.dst_ipv4;

        ig_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    table l2_forward{
        key = {
            hdr.ethernet.dst_addr : exact;
        }
        actions={
            forward;
            route;
        }
        size=1024;
    }

    table l3_host_route{
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions={
            route;
            drop;
        }
        size=1024;
    }

    table l3_lpm_route{
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions ={
            route;
            drop;
        }
        size=1024;
    }

    action not_action()
    {

    }
    table mac_table{
        key = {
            hdr.ethernet.dst_addr :exact;
        }
        actions ={
            not_action;
        }
        const entries = {
            0x112233445566 : not_action;
        }
        default_action = not_action();
        size=1024;
    }

    table arp_response{
        key ={
            myigmd.dst_ipv4 :exact;
        }
        actions={
            send_arp_reply;
        }
        size=1024;
    }

    apply{

        if(hdr.arp.isValid()&&hdr.arp.opcode==arp_opcode_t.REQUEST){
                if(arp_response.apply().hit){
                    exit;
                }
        }

        if(!mac_table.apply().hit)
        {
            l2_forward.apply();
        }

        if(hdr.ipv4.isValid()){
                if(!l3_host_route.apply().hit)
                {
                    l3_lpm_route.apply();
                }
        }
    }
}

control ingressDeparser(packet_out pkt,
    inout my_ingress_header_t                       hdr,
    in    my_Ingress_Metadata                      meta,
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply{
        pkt.emit(hdr);
    }
}


struct my_egress_headers_t {
}

struct my_egress_metadata_t {
}

parser EgressParser(packet_in        pkt,
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}


control Egress(
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {

    }
}

control EgressDeparser(packet_out pkt,
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


Pipeline(
    myingressparser(),
    Ingress(),
    ingressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
