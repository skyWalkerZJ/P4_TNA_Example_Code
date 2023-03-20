#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ethernet_type_t;

enum bit<16> ether_type_t {
    TPID       = 0x8100,
    IPV4       = 0x0800
}

enum bit<8>  ip_proto_t {
    ICMP  = 1,
    IGMP  = 2,
    TCP   = 6,
    UDP   = 17
}
header ethernet_t{
    mac_addr src_mac;
    mac_addr dst_mac;
    ethernet_type_t ethernet_type;
}

header vlan_tag_t{
    bit<3>        pcp;
    bit<1>        cfi;
    bit<12>       vid;
    ether_type_t  ether_type;
}

header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    ip_proto_t   protocol;
    bit<16>      hdr_checksum;
    ipv4_addr_t  src_addr;
    ipv4_addr_t  dst_addr;
}

header ipv4_option_t{
    varbit<320> data;
}

header icmp_t {
    bit<16>  type_code;
    bit<16>  checksum;
}

header igmp_t {
    bit<16>  type_code;
    bit<16>  checksum;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

struct l4_lookup_t{
    bit<16> word_1;
    bit<16> word_2;
}

struct my_ingress_metadata_t{
    l4_lookup_t l4_lookup;
    bit<1>     first_frag;
    bit<12> next_hop_id;
    bit<10> drop_rate;
}

struct my_ingress_headers_t{
    ethernet_t ethernet;
    vlan_tag_t[2] vlan_tag;
    ipv4_t ipv4;
    ipv4_option_t ipv4_options;
    icmp_t icmp;
    igmp_t igmp;
    tcp_t tcp;
    udp_t udp;
}

parser IngressParser(packet_in pkt,
    out my_ingress_headers_t hdr,
    out my_ingress_metadata_t my_ingr_md,
    out ingress_intrinsic_metadata_t ingr_intr_md)
{

    state start{
        pkt.extract(ingr_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init{
        my_ingr_md.l4_lookup={0,0};
        my_ingr_md.first_frag=0;
        my_ingr_md.next_hop_id=0;
        my_ingr_md.drop_rate=10w0;
        transition parse_ethernet;
    }

    state parse_ethernet{
        pkt.extract(hdr.ethernet);
        transition select((bit<16>)hdr.ethernet.ethernet_type){
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parser_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parser_ipv4;
            default :  accept;
        }
    }
    state parser_vlan_tag{
        pkt.extract(hdr.vlan_tag.next);
        transition select((bit<16>)hdr.vlan_tag.last.ether_type)
        {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parser_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parser_ipv4;
            default :  accept;
        }
    }
    state parser_ipv4{
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.ihl){
            0x5 : parse_ipv4_no_options;
            0x6 &&& 0xE : parse_ipv4_options;
            0x8 &&& 0x8 : parse_ipv4_options;
        }
    }

    state parse_ipv4_options{
        pkt.extract(hdr.ipv4_options,(bit<32>)((bit<32>)hdr.ipv4.ihl - 32w5) * 32);
        transition parse_ipv4_no_options;
    }

    state parse_ipv4_no_options{
        my_ingr_md.l4_lookup=pkt.lookahead<l4_lookup_t>();
        transition select(hdr.ipv4.frag_offset,hdr.ipv4.protocol)
        {
            ( 0, ip_proto_t.ICMP ) : parse_icmp;
            ( 0, ip_proto_t.IGMP ) : parse_igmp;
            ( 0, ip_proto_t.TCP  ) : parse_tcp;
            ( 0, ip_proto_t.UDP  ) : parse_udp;
            ( 0, _               ) : parse_first_fragment;
            default : accept;
        }
    }

    state parse_icmp{
        pkt.extract(hdr.icmp);
        transition parse_first_fragment;
    }
    
    state parse_igmp{
        pkt.extract(hdr.igmp);
        transition parse_first_fragment;
    }
    
    state parse_tcp{
        pkt.extract(hdr.tcp);
        transition parse_first_fragment;
    }
    
    state parse_udp{
        pkt.extract(hdr.udp);
        transition parse_first_fragment;
    }
    
    state parse_first_fragment{
        my_ingr_md.first_frag = 1;
        transition accept;
    }
}

control Ingress(inout my_ingress_headers_t hdr,
    inout my_ingress_metadata_t my_ingr_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md
)
{
    /*
        get a random value to decide weather the packet will be dropped. 
    */
    Random<bit<10>>() rnd;
    
    action drop(){
        ig_dprsr_md.drop_ctl=1;
    }
     
    action set_nextHop(bit<12> hop_id)
    {
        my_ingr_md.next_hop_id=hop_id;               
    }

    action route(PortId_t port,mac_addr new_dst_mac)
    {
        hdr.ipv4.ttl = hdr.ipv4.ttl |-| 1;
        hdr.ethernet.src_mac=hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac=new_dst_mac;
        ig_tm_md.ucast_egress_port=port;
    }

    action forward(PortId_t port)
    {
    	ig_tm_md.ucast_egress_port=port;
    }

    action setRate()
    {
        bit<10> r=rnd.get();
    	my_ingr_md.drop_rate=r;
    }

    table l2_forward{
    	key={
    		hdr.ethernet.dst_mac: exact;
    	}

    	actions={
    		forward;
    		drop;
    	}

    	size=1024;
    }
    table ipv4_host{
        key={
            hdr.ipv4.dst_addr:exact;
        }
        actions={
            set_nextHop;
        }
        size=1024;
    }

    table ipv4_lpm{
        key={
            hdr.ipv4.dst_addr:lpm;
        }
        actions={
            set_nextHop;
        }
        size=1024;
    }

    table next_hop{
        key={
            my_ingr_md.next_hop_id:exact;
        }
        actions={
            route;
            drop;
        }
        size=1024;
    }

    table mac_table{
        key = {
            hdr.ethernet.dst_mac :exact;
        }
        actions ={
            NoAction;
        }

        /*this is the mac address of the switch.
        	if the macaddrss match the dstMacAddr in ethernet Header.
        	means this packet need to be routed.	
        */
        const entries = {
            0x112233445566 : NoAction;
        }
        default_action = NoAction();
        size=1024;
    }

    
    table ipv4_acl{
        key={
            hdr.ipv4.src_addr     : ternary;
            hdr.ipv4.dst_addr     : ternary;
            hdr.ipv4.protocol     : ternary;
            my_ingr_md.l4_lookup.word_1 : ternary;
            my_ingr_md.l4_lookup.word_2 : ternary;
            my_ingr_md.first_frag       : ternary;
        }
        actions = { 
            NoAction; 
            drop;
        }
        const default_action = NoAction();
        size=1024;
    }
    
    table packet_drop{
        /*
            the key is a random value;
            the start of rangeMatch is 0;
            the end of range match stand the drop rate;
            such as 0~300 means drop rates is 300/1024,about 0.3;
            because we use 10bits to get random value;
        */
        key={
            my_ingr_md.drop_rate     : range;
        }

        actions ={
            drop;
            NoAction;
        }
        const default_action = NoAction();
    }

    apply{

        if(!mac_table.apply().hit)
        {
            l2_forward.apply();
        }

        if(hdr.ipv4.isValid()&&hdr.ipv4.ttl>1)
        {
            if(!ipv4_host.apply().hit)
            {
                ipv4_lpm.apply();
            }
            next_hop.apply();
            ipv4_acl.apply();
            
        }
        setRate();
        packet_drop.apply();
    }

}

control IngressDeparser(packet_out pkt,
    inout my_ingress_headers_t hdr,
    in my_ingress_metadata_t meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Checksum() ipv4_checksum;
    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4_options.data
            });
        pkt.emit(hdr);
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

