#include <core.p4>
#include <tna.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
typedef bit<48> ethernet_addr;
header ethernet_h{
    ethernet_addr src_addr;
    ethernet_addr dst_addr;
    bit<16> ethernet_type;
}
header ipv4_h{
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

struct my_ingress_t_header{
    ethernet_h ethernet;
    ipv4_h ipv4;
}

struct my_ingress_metadata{
    
}

parser IngressParser(packet_in pkt,
    out my_ingress_t_header hdr,
    out my_ingress_metadata my_ingress_metadata_t,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start{
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethernet_type){
            ETHERTYPE_IPV4:IPv4_parser;
            default:accept;
        }
    }
    state IPv4_parser{
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

control Ingress(inout my_ingress_t_header hdr,
    inout my_ingress_metadata my_ingress_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
)
{
    action send(PortId_t port)
    {
        ig_tm_md.ucast_egress_port=port;
        ig_tm_md.bypass_egress = 1;
    }   

    action drop()
    {
        ig_dprsr_md.drop_ctl=1;
    }

    table ipv4_host{
        key={
            hdr.ipv4.dst_addr:exact;
        }

        actions={
            send;
            drop;
        }

        size=128;
    }

    table ipv4_lpm{
        key={
            hdr.ipv4.dst_addr:lpm;
        }

        actions={
            send;
            drop;
        }

        size=128;
    }

    apply{
        if(hdr.ipv4.isValid())
        {
            if(!ipv4_host.apply().hit)
            {
                ipv4_lpm.apply();
            }
        }
    }
}

control IngressDeparser(packet_out pkt,
    inout my_ingress_t_header hdr,
    in my_ingress_metadata my_ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md
)
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
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
