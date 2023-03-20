#include <core.p4>
#include <tna.p4>


/* Ethertypes */
const bit<16> ETHERTYPE_BF_FABRIC =  0x9000;
const bit<16> ETHERTYPE_VLAN      =  0x8100;
const bit<16> ETHERTYPE_QINQ      =  0x9100;
const bit<16> ETHERTYPE_MPLS      =  0x8847;
const bit<16> ETHERTYPE_IPV4      =  0x0800;
const bit<16> ETHERTYPE_IPV6      =  0x86dd;
const bit<16> ETHERTYPE_ARP       =  0x0806;
const bit<16> ETHERTYPE_RARP      =  0x8035;
const bit<16> ETHERTYPE_NSH       =  0x894f;
const bit<16> ETHERTYPE_ETHERNET  =  0x6558;
const bit<16> ETHERTYPE_ROCE      =  0x8915;
const bit<16> ETHERTYPE_FCOE      =  0x8906;
const bit<16> ETHERTYPE_TRILL     =  0x22f3;
const bit<16> ETHERTYPE_VNTAG     =  0x8926;
const bit<16> ETHERTYPE_LLDP      =  0x88cc;
const bit<16> ETHERTYPE_LACP      =  0x8809;

/* IP protocols */
const bit<8> IP_PROTOCOLS_ICMP       =   1;
const bit<8> IP_PROTOCOLS_IGMP       =   2;
const bit<8> IP_PROTOCOLS_IPV4       =   4;
const bit<8> IP_PROTOCOLS_TCP        =   6;
const bit<8> IP_PROTOCOLS_UDP        =  17;
const bit<8> IP_PROTOCOLS_IPV6       =  41;
const bit<8> IP_PROTOCOLS_GRE        =  47;
const bit<8> IP_PROTOCOLS_IPSEC_ESP  =  50;
const bit<8> IP_PROTOCOLS_IPSEC_AH   =  51;
const bit<8> IP_PROTOCOLS_ICMPV6     =  58;
const bit<8> IP_PROTOCOLS_EIGRP      =  88;
const bit<8> IP_PROTOCOLS_OSPF       =  89;
const bit<8> IP_PROTOCOLS_PIM        = 103;
const bit<8> IP_PROTOCOLS_VRRP       = 112;

/* Tunnel types - not from standards, just internal implementation constants */
const bit<5> INGRESS_TUNNEL_TYPE_NONE       =  0;
const bit<5> INGRESS_TUNNEL_TYPE_VXLAN      =  1;
const bit<5> INGRESS_TUNNEL_TYPE_GRE        =  2;
const bit<5> INGRESS_TUNNEL_TYPE_IP_IN_IP   =  3;
const bit<5> INGRESS_TUNNEL_TYPE_GENEVE     =  4;
const bit<5> INGRESS_TUNNEL_TYPE_NVGRE      =  5;
const bit<5> INGRESS_TUNNEL_TYPE_MPLS_L2VPN =  6;
const bit<5> INGRESS_TUNNEL_TYPE_MPLS_L3VPN =  9;
const bit<5> INGRESS_TUNNEL_TYPE_VXLAN_GPE  = 12;

/* Egress tunnel types */
const bit<5> EGRESS_TUNNEL_TYPE_NONE           =  0;
const bit<5> EGRESS_TUNNEL_TYPE_IPV4_VXLAN     =  1;
const bit<5> EGRESS_TUNNEL_TYPE_IPV6_VXLAN     =  2;
const bit<5> EGRESS_TUNNEL_TYPE_IPV4_GENEVE    =  3;
const bit<5> EGRESS_TUNNEL_TYPE_IPV6_GENEVE    =  4;
const bit<5> EGRESS_TUNNEL_TYPE_IPV4_NVGRE     =  5;
const bit<5> EGRESS_TUNNEL_TYPE_IPV6_NVGRE     =  6;
const bit<5> EGRESS_TUNNEL_TYPE_IPV4_ERSPAN_T3 =  7;
const bit<5> EGRESS_TUNNEL_TYPE_IPV6_ERSPAN_T3 =  8;
const bit<5> EGRESS_TUNNEL_TYPE_IPV4_GRE       =  9;
const bit<5> EGRESS_TUNNEL_TYPE_IPV6_GRE       = 10;
const bit<5> EGRESS_TUNNEL_TYPE_IPV4_IP        = 11;
const bit<5> EGRESS_TUNNEL_TYPE_IPV6_IP        = 12;
const bit<5> EGRESS_TUNNEL_TYPE_MPLS_L2VPN     = 13;
const bit<5> EGRESS_TUNNEL_TYPE_MPLS_L3VPN     = 14;
const bit<5> EGRESS_TUNNEL_TYPE_FABRIC         = 15;
const bit<5> EGRESS_TUNNEL_TYPE_CPU            = 16;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

header gre_t {
    bit<1>  C;
    bit<1>  R;
    bit<1>  K;
    bit<1>  S;
    bit<1>  s;
    bit<3>  recurse;
    bit<5>  flags;
    bit<3>  ver;
    bit<16> proto;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header generic_20_byte_hdr_t {
    bit<32> word0;
    bit<32> word1;
    bit<32> word2;
    bit<32> word3;
    bit<32> word4;
}

header generic_28_byte_hdr_t {
    bit<32> word0;
    bit<32> word1;
    bit<32> word2;
    bit<32> word3;
    bit<32> word4;
    bit<32> word5;
    bit<32> word6;
}

header generic_40_byte_hdr_t {
    bit<32> word0;
    bit<32> word1;
    bit<32> word2;
    bit<32> word3;
    bit<32> word4;
    bit<32> word5;
    bit<32> word6;
    bit<32> word7;
    bit<32> word8;
    bit<32> word9;
}

struct headers {
    ethernet_t    outer_ethernet;
    vlan_tag_t[2] outer_vlan_tag;
    ipv4_t        outer_ipv4;
    ipv6_t        outer_ipv6;
    tcp_t         outer_tcp;
    udp_t         outer_udp;
    gre_t         outer_gre;
    generic_20_byte_hdr_t generic_20_byte_hdr;
    generic_28_byte_hdr_t generic_28_byte_hdr;
    generic_40_byte_hdr_t generic_40_byte_hdr;

    ethernet_t    ethernet;
    vlan_tag_t[2] vlan_tag;
    ipv4_t        ipv4;
    ipv6_t        ipv6;
    tcp_t         tcp;
    udp_t         udp;
    gre_t         gre;

    ipv4_t        inner_ipv4;
    tcp_t         inner_tcp;
    udp_t         inner_udp;
}

struct l3_metadata_t {
    bit<16> nexthop_index;
    bit<16> payload_length;
}


struct tunnel_metadata_t {
    bit<5>  ingress_tunnel_type;
    bit<5>  egress_tunnel_type;
    bit<14> tunnel_index;
    bit<9>  tunnel_src_index;
    bit<9>  tunnel_smac_index;
    bit<14> tunnel_dst_index;
    bit<14> tunnel_dmac_index;
    bit<1>  tunnel_terminate;
    bit<4>  egress_header_count;
    bit<8>  inner_ip_proto;
}


struct user_metadata {
    l3_metadata_t        l3_metadata;
    tunnel_metadata_t    tunnel;
}


parser IngressParser(packet_in packet,
    out headers hdr,
    out user_metadata meta,
    out ingress_intrinsic_metadata_t ingr_intr_md)
{

    state start{
        packet.extract(ingr_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        meta.l3_metadata.nexthop_index=0;
        meta.tunnel.ingress_tunnel_type=INGRESS_TUNNEL_TYPE_NONE;
        meta.tunnel.egress_tunnel_type=EGRESS_TUNNEL_TYPE_NONE;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_vlan{
        packet.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.etherType)
        {
            ETHERTYPE_VLAN: parse_vlan;
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default :  accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl,
                          hdr.ipv4.protocol) {
            (13w0x0, 4w0x5, IP_PROTOCOLS_TCP): parse_tcp;
            (13w0x0, 4w0x5, IP_PROTOCOLS_UDP): parse_udp;
            (13w0x0, 4w0x5, IP_PROTOCOLS_GRE): parse_gre;
            default: accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            IP_PROTOCOLS_TCP: parse_tcp;
            IP_PROTOCOLS_UDP: parse_udp;
            IP_PROTOCOLS_GRE: parse_gre;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_gre {
        packet.extract(hdr.gre);
        transition select(hdr.gre.C, hdr.gre.R, hdr.gre.K, hdr.gre.S,
                          hdr.gre.s, hdr.gre.recurse, hdr.gre.flags,
                          hdr.gre.ver, hdr.gre.proto) {
            (1w0x0, 1w0x0, 1w0x0,
             1w0x0, 1w0x0, 3w0x0,
             5w0x0, 3w0x0, ETHERTYPE_IPV4): parse_gre_ipv4;
            default: accept;
        }
    }
    state parse_gre_ipv4 {
        meta.tunnel.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GRE;
        transition parse_inner_ipv4;
    }
    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.fragOffset, hdr.inner_ipv4.ihl,
                          hdr.inner_ipv4.protocol) {
            (13w0x0, 4w0x5, IP_PROTOCOLS_TCP): parse_inner_tcp;
            (13w0x0, 4w0x5, IP_PROTOCOLS_UDP): parse_inner_udp;
            default: accept;
        }
    }
    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        transition accept;
    }
    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}



control preprocess_rewrite(inout headers hdr,
    inout user_metadata user_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md
)
{

    
    action drop(){
        ig_dprsr_md.drop_ctl=1;
    }

    action route(PortId_t port,bit<48> new_dst_mac)
    {
        hdr.ipv4.ttl = hdr.ipv4.ttl |-| 1;
        hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr=new_dst_mac;
        ig_tm_md.ucast_egress_port=port;
    }

    action forward(PortId_t port)
    {
        ig_tm_md.ucast_egress_port=port;
    }

    action set_l2_rewrite_with_tunnel(PortId_t port,
                                        bit<14> tunnel_index,
                                        bit<5> tunnel_type)
    {
        ig_tm_md.ucast_egress_port=port;
        user_md.tunnel.tunnel_index = tunnel_index;
        user_md.tunnel.egress_tunnel_type = tunnel_type;
    }

    action set_l3_rewrite_with_tunnel(PortId_t port,
                                      bit<48> new_dst_mac,
                                      bit<14> tunnel_index,
                                      bit<5> tunnel_type)
    {
        hdr.ethernet.srcAddr=hdr.ethernet.dstAddr;
        hdr.ethernet.srcAddr=new_dst_mac;
        ig_tm_md.ucast_egress_port=port;
        user_md.tunnel.tunnel_index = tunnel_index;
        user_md.tunnel.egress_tunnel_type = tunnel_type;
    }
     
    action set_nextHop(bit<16> index)
    {
        user_md.l3_metadata.nexthop_index=index;
    }

    table l2_match{
    	key={
    		hdr.ethernet.dstAddr :exact;
    	}

    	actions={
    		set_nextHop;
    	}

    	size=1024;
    }


    table l3_match{
        key={
            hdr.ipv4.isValid():exact;
            hdr.ipv6.isValid():exact;
            hdr.ipv6.dstAddr:ternary;
            hdr.ipv4.dstAddr:ternary;
        }
        actions={
            set_nextHop;
        }
        size=1024;
    }



    table mac_table{
        key = {
            hdr.ethernet.dstAddr :exact;
        }
        actions ={
            NoAction;
        }
        const entries = {
            0x112233445566 : NoAction;
        }
        default_action = NoAction();
        size=1024;
    }

    table rewrite{
        key={
            user_md.l3_metadata.nexthop_index:exact;
        }
        actions={
            forward;
            set_l2_rewrite_with_tunnel;
            route;
            set_l3_rewrite_with_tunnel;
        }
        size=1024;
    }


    

    apply{

        if(!mac_table.apply().hit)
        {
            l2_match.apply();
        }else{
            l3_match.apply();
        }
        rewrite.apply();
    }

}

control process_rewrite(inout headers hdr,
    inout user_metadata user_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md
)
{
    action inner_ipv4_encap() {
        user_md.l3_metadata.payload_length = hdr.ipv4.totalLen;
        user_md.tunnel.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }

    action inner_ipv6_encap() {
        
        /* 40 bytes is the length of the base IPv6 header, which is
         * not included in hdr.ipv6.payloadLen */

        user_md.l3_metadata.payload_length = 40 + hdr.ipv6.payloadLen;
        user_md.tunnel.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }

    action pre_ipv4_decap()
    {
        user_md.tunnel.inner_ip_proto = hdr.ipv4.protocol;
    }

    action pre_ipv6_decap()
    {
        user_md.tunnel.inner_ip_proto = hdr.ipv6.nextHdr;
    }

    action pre_gre_decap()
    {
        user_md.tunnel.inner_ip_proto = (bit<8>)hdr.gre.proto;
        hdr.ethernet.etherType=hdr.gre.proto;
    }



    table tunnel_encap_process_inner {
        key = {
            hdr.ipv4.isValid(): exact;
            hdr.ipv6.isValid(): exact;
        }
        actions = {
            inner_ipv4_encap;
            inner_ipv6_encap;
            NoAction;
        }
        size = 1024;
    }

    table tunnel_decap_process_inner {
        key = {
            user_md.tunnel.ingress_tunnel_type:exact;
            /*
                ipv4      +ipv4
                ipv4      +ipv6
                ipv6      +ipv4
                ipv6      +ipv6
                ipv4+gre  +ipv4
                ipv6+gre  +ipv4
                ipv4+gre  +ipv6
                ipv6+gre  +ipv6
                three types tunnel,
                we should recognize the inner proto through the proto_type of ipv4,ipv6,gre.
            */
        }
        actions = {
            pre_ipv4_decap;
            pre_ipv6_decap;
            pre_gre_decap;
            NoAction;
        }
        size = 1024;
    }




    action f_insert_gre_header() {
        /* This code only handles the GRE encapsulation cases with no
         * optional checksum, key, or sequence number. */
        hdr.outer_gre.setValid();
        hdr.outer_gre.C = 0;
        hdr.outer_gre.R = 0;
        hdr.outer_gre.K = 0;
        hdr.outer_gre.S = 0;
        hdr.outer_gre.s = 0;
        hdr.outer_gre.recurse = 0;
        hdr.outer_gre.flags = 0;
        hdr.outer_gre.ver = 0;
        /* The proto field will be set elsewhere, depending upon the
         * type of the inner packet being encapsulated. */
        //hdr.outer_gre.proto = filled_in_later;
    }
    action f_insert_ipv4_header(bit<8> proto) {
        /* Fill in all fields except totalLen, srcAddr, and dstAddr,
         * which will be filled in by later table actions.
         * hdrChecksum will be calculated just before deparsing. */
        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version = 4;
        hdr.outer_ipv4.ihl = 5;
        hdr.outer_ipv4.diffserv = 0;
        //hdr.outer_ipv4.totalLen = filled_in_later;
        hdr.outer_ipv4.identification = 0;
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.fragOffset = 0;
        hdr.outer_ipv4.ttl = 64;
        hdr.outer_ipv4.protocol = proto;
        //hdr.outer_ipv4.hdrChecksum = filled_in_later;
        //hdr.outer_ipv4.srcAddr = filled_in_later;
        //hdr.outer_ipv4.dstAddr = filled_in_later;
    }

    action f_insert_ipv6_header(bit<8> proto) {
        /* Fill in all fields except payloadLen, srcAddr, and dstAddr,
         * which will be filled in by later table actions. */
        hdr.outer_ipv6.setValid();
        hdr.outer_ipv6.version = 6;
        hdr.outer_ipv6.trafficClass = 0;
        hdr.outer_ipv6.flowLabel = 0;
        //hdr.outer_ipv6.payloadLen = filled_in_later;
        hdr.outer_ipv6.nextHdr = proto;
        hdr.outer_ipv6.hopLimit = 64;
        //hdr.outer_ipv6.srcAddr = filled_in_later;
        //hdr.outer_ipv6.dstAddr = filled_in_later;
    }

    action ipv4_gre_encap() {
        f_insert_gre_header();
        hdr.outer_gre.proto = hdr.ethernet.etherType;
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        /* 24 is size in bytes of outer_ipv4 plus outer_gre headers */
        hdr.outer_ipv4.totalLen = user_md.l3_metadata.payload_length + 24;
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = ETHERTYPE_IPV4;
    }
    action ipv4_ip_encap() {
        f_insert_ipv4_header(user_md.tunnel.inner_ip_proto);
        /* 20 is size in bytes of outer_ipv4 header */
        hdr.outer_ipv4.totalLen = user_md.l3_metadata.payload_length + 20;
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = ETHERTYPE_IPV4;
    }

    action ipv6_gre_encap() {
        f_insert_gre_header();
        hdr.outer_gre.proto = hdr.ethernet.etherType;
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        /* 4 is size in bytes of outer_gre header.  IPv6 payloadLen
         * does not include the length of the IPv6 header itself. */
        hdr.outer_ipv6.payloadLen = user_md.l3_metadata.payload_length + 4;
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = ETHERTYPE_IPV6;
    }

    action ipv6_ip_encap() {
        f_insert_ipv6_header(user_md.tunnel.inner_ip_proto);
        hdr.outer_ipv6.payloadLen = user_md.l3_metadata.payload_length;
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = ETHERTYPE_IPV6;
    }


    action add_generic_20_byte_header(bit<16> etherType,
                                      bit<32> word0, bit<32> word1,
                                      bit<32> word2, bit<32> word3,
                                      bit<32> word4) {
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = etherType;
        hdr.generic_20_byte_hdr.setValid();
        hdr.generic_20_byte_hdr.word0 = word0;
        hdr.generic_20_byte_hdr.word1 = word1;
        hdr.generic_20_byte_hdr.word2 = word2;
        hdr.generic_20_byte_hdr.word3 = word3;
        hdr.generic_20_byte_hdr.word4 = word4;
    }
    action add_generic_28_byte_header(bit<16> etherType,
                                      bit<32> word0, bit<32> word1,
                                      bit<32> word2, bit<32> word3,
                                      bit<32> word4, bit<32> word5,
                                      bit<32> word6) {
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = etherType;
        hdr.generic_28_byte_hdr.setValid();
        hdr.generic_28_byte_hdr.word0 = word0;
        hdr.generic_28_byte_hdr.word1 = word1;
        hdr.generic_28_byte_hdr.word2 = word2;
        hdr.generic_28_byte_hdr.word3 = word3;
        hdr.generic_28_byte_hdr.word4 = word4;
        hdr.generic_28_byte_hdr.word5 = word5;
        hdr.generic_28_byte_hdr.word6 = word6;
    }
    action add_generic_40_byte_header(bit<16> etherType,
                                      bit<32> word0, bit<32> word1,
                                      bit<32> word2, bit<32> word3,
                                      bit<32> word4, bit<32> word5,
                                      bit<32> word6, bit<32> word7,
                                      bit<32> word8, bit<32> word9) {
        hdr.outer_ethernet.setValid();
        hdr.outer_ethernet.etherType = etherType;
        hdr.generic_40_byte_hdr.setValid();
        hdr.generic_40_byte_hdr.word0 = word0;
        hdr.generic_40_byte_hdr.word1 = word1;
        hdr.generic_40_byte_hdr.word2 = word2;
        hdr.generic_40_byte_hdr.word3 = word3;
        hdr.generic_40_byte_hdr.word4 = word4;
        hdr.generic_40_byte_hdr.word5 = word5;
        hdr.generic_40_byte_hdr.word6 = word6;
        hdr.generic_40_byte_hdr.word7 = word7;
        hdr.generic_40_byte_hdr.word8 = word8;
        hdr.generic_40_byte_hdr.word9 = word9;
    }

    action miss_ipv4_encap()
    {
        hdr.ipv4.setInvalid();
    }
    action miss_ipv6_encap()
    {
        hdr.ipv6.setInvalid();
    }
    action miss_gre_encap()
    {
        hdr.gre.setInvalid();   
    }
    action miss_ethernet_encap()
    {
        hdr.ethernet.setInvalid();
    }
    action ipv4_gre_decap()
    {
        //hdr.ethernet.etherType=(bit<16>)user_md.tunnel.inner_ip_proto;
        miss_ipv4_encap();
        miss_gre_encap();
    }

    action ipv4_decap()
    {
        hdr.ethernet.etherType=(bit<16>)user_md.tunnel.inner_ip_proto;
        miss_ipv4_encap();
    }

    action ipv6_gre_decap()
    {
        // cast will cause problom
        // hdr.ethernet.etherType=(bit<16>)user_md.tunnel.inner_ip_proto;
        miss_ipv6_encap();
        miss_gre_encap();
    }

    action ipv6_decap()
    {
        hdr.ethernet.etherType=(bit<16>)user_md.tunnel.inner_ip_proto;
        miss_ipv6_encap();
    }
    action remove_generic_20_byte_header()
    {
        hdr.generic_20_byte_hdr.setInvalid();
    }
    action remove_generic_28_byte_header()
    {
        hdr.generic_28_byte_hdr.setInvalid();
    }
    action remove_generic_40_byte_header()
    {
        hdr.generic_40_byte_hdr.setInvalid();
    }
    table tunnel_encap_process_outer {
        key = {
            user_md.tunnel.egress_tunnel_type : exact;
        }
        actions = {
            NoAction;

            ipv4_gre_encap;
            ipv4_ip_encap;
            ipv6_gre_encap;
            ipv6_ip_encap;
            add_generic_20_byte_header;
            add_generic_28_byte_header;
            add_generic_40_byte_header;
            
            ipv4_gre_decap;
            ipv4_decap;
            ipv6_gre_decap;
            ipv6_decap;
            remove_generic_20_byte_header;
            remove_generic_28_byte_header;
            remove_generic_40_byte_header;
        }
        size = 1024;
    }



    action set_tunnel_rewrite_details(PortId_t port, bit<9> smac_idx,
                                      bit<14> dmac_idx, bit<9> sip_index,
                                      bit<14> dip_index) {
        ig_tm_md.ucast_egress_port=port;
        user_md.tunnel.tunnel_smac_index = smac_idx;
        user_md.tunnel.tunnel_dmac_index = dmac_idx;
        user_md.tunnel.tunnel_src_index = sip_index;
        user_md.tunnel.tunnel_dst_index = dip_index;
    }


    table tunnel_encap_rewrite {
        key = { 
            user_md.tunnel.tunnel_index: exact; 
        }
        actions = { 
            NoAction; 
            set_tunnel_rewrite_details; 
        }
        size = 1024;
    }

    action rewrite_tunnel_ipv4_src(bit<32> ip) { hdr.outer_ipv4.srcAddr = ip; }
    action rewrite_tunnel_ipv6_src(bit<128> ip) { hdr.outer_ipv6.srcAddr = ip; }
    table tunnel_src_rewrite {
        key = { user_md.tunnel.tunnel_src_index: exact; }
        actions = { NoAction; rewrite_tunnel_ipv4_src; rewrite_tunnel_ipv6_src; }
        size = 1024;
    }
    action rewrite_tunnel_ipv4_dst(bit<32> ip) { hdr.outer_ipv4.dstAddr = ip; }
    action rewrite_tunnel_ipv6_dst(bit<128> ip) { hdr.outer_ipv6.dstAddr = ip; }
    table tunnel_dst_rewrite {
        key = { user_md.tunnel.tunnel_dst_index: exact; }
        actions = { NoAction; rewrite_tunnel_ipv4_dst; rewrite_tunnel_ipv6_dst; }
        size = 1024;
    }
    action rewrite_tunnel_smac(bit<48> smac) {
        hdr.outer_ethernet.srcAddr = smac;
    }
    table tunnel_smac_rewrite {
        key = { user_md.tunnel.tunnel_smac_index: exact; }
        actions = { NoAction; rewrite_tunnel_smac; }
        size = 1024;
    }
    action rewrite_tunnel_dmac(bit<48> dmac) {
        hdr.outer_ethernet.dstAddr = dmac;
    }
    table tunnel_dmac_rewrite {
        key = { user_md.tunnel.tunnel_dmac_index: exact; }
        actions = { NoAction; rewrite_tunnel_dmac; }
        size = 1024;
    }

    apply{

        if(user_md.tunnel.egress_tunnel_type >0&& user_md.tunnel.egress_tunnel_type<20)
        {
            //encapsulation
            tunnel_encap_process_inner.apply();
        }else if(user_md.tunnel.egress_tunnel_type >20)
        {
            //Decapsulation
            tunnel_decap_process_inner.apply();
        }
        tunnel_encap_process_outer.apply();
        tunnel_encap_rewrite.apply();
        tunnel_src_rewrite.apply();
        tunnel_dst_rewrite.apply();
        tunnel_smac_rewrite.apply();
        tunnel_dmac_rewrite.apply();
    }
}

control Ingress(inout headers hdr,
    inout user_metadata user_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md
)
{
    apply{
        preprocess_rewrite.apply(hdr,user_md,ig_intr_md,ig_prsr_md,ig_dprsr_md,ig_tm_md);
        process_rewrite.apply(hdr,user_md,ig_intr_md,ig_prsr_md,ig_dprsr_md,ig_tm_md);
    }
}


control IngressDeparser(packet_out packet,
    inout headers hdr,
    in user_metadata meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        packet.emit(hdr.outer_ethernet);
        packet.emit(hdr.outer_vlan_tag[0]);
        packet.emit(hdr.outer_vlan_tag[1]);
        packet.emit(hdr.generic_20_byte_hdr);
        packet.emit(hdr.generic_28_byte_hdr);
        packet.emit(hdr.generic_40_byte_hdr);
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.outer_ipv6);
        packet.emit(hdr.outer_tcp);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.outer_gre);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.vlan_tag[0]);
        packet.emit(hdr.vlan_tag[1]);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gre);

        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_tcp);
        packet.emit(hdr.inner_udp);

        /* Any part of the packet that wasn't parsed as a header in
         * the parser block, is considered part of the payload of the
         * packet (as far as this P4 program is concerned, at least).
         * It is appended after the last emitted header before the
         * packet is transmitted out of the system. */
    }
}


struct my_egress_headers_t {
}

struct my_egress_metadata_t {
}


parser EgressParser(packet_in      pkt,
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
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
)pipe;
Switch(pipe) main;

