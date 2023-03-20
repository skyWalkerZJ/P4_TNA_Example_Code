# insert entries to the packet_capsulation and packet_drop control;
# run with ./run_bfshell.sh -b ./setup.py -i
from ipaddress import ip_address

p4 = bfrt.fault_injection.pipe

l3_match = p4.Ingress.basicSwitch.l3_match
rewrite = p4.Ingress.basicSwitch.rewrite


l3_match.add_with_set_nextHop(ipv4_valid=1,ipv6_valid=0,ipv4_dstAddr=ip_address("192.168.1.2"),ipv4_dstAddr_mask=0xffffffff,ipv6_dstAddr=0x0,ipv6_dstAddr_mask=0x0,index=2)
rewrite.add_with_l3_rewrite_with_tunnel(nexthop_index=2,port=2,new_dst_mac=0x222222222222,tunnel_index=1,tunnel_type=1)


packet_drop=p4.Ingress.dropByRate.packet_drop
packet_drop.add_with_drop(drop_rate_start=0,drop_rate_end=800,MATCH_PRIORITY=1)

tunnel_encap_process_inner=p4.Ingress.packet_capsulation.tunnel_encap_process_inner
tunnel_encap_process_outer=p4.Ingress.packet_capsulation.tunnel_encap_process_outer
tunnel_encap_rewrite=p4.Ingress.packet_capsulation.tunnel_encap_rewrite
tunnel_smac_rewrite=p4.Ingress.packet_capsulation.tunnel_smac_rewrite
tunnel_dmac_rewrite=p4.Ingress.packet_capsulation.tunnel_dmac_rewrite
tunnel_src_rewrite=p4.Ingress.packet_capsulation.tunnel_src_rewrite
tunnel_dst_rewrite=p4.Ingress.packet_capsulation.tunnel_dst_rewrite


tunnel_encap_process_inner.add_with_inner_ipv4_encap(ipv4_valid=1,ipv6_valid=0)
tunnel_encap_process_outer.add_with_ipv4_gre_encap(egress_tunnel_type=1)
tunnel_encap_rewrite.add_with_set_tunnel_rewrite_details(tunnel_index=1,port=2,smac_idx=1,dmac_idx=1,sip_index=1,dip_index=1)
tunnel_smac_rewrite.add_with_rewrite_tunnel_smac(tunnel_smac_index=1,smac=0x111111111111)
tunnel_dmac_rewrite.add_with_rewrite_tunnel_dmac(tunnel_dmac_index=1,dmac=0x222222222222)
tunnel_src_rewrite.add_with_rewrite_tunnel_ipv4_src(tunnel_src_index=1,ip=ip_address("47.108.61.2"))
tunnel_dst_rewrite.add_with_rewrite_tunnel_ipv4_dst(tunnel_dst_index=1,ip=ip_address("47.108.61.100"))


bfrt.complete_operations()