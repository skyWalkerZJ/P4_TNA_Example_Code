#!/usr/bin/python

import os
import sys

from scapy.all import *

try:
    ip_dst = sys.argv[1]
except:
    ip_dst = "192.168.1.21"

p = (Ether(dst="11:22:33:44:55:66", src="00:aa:bb:cc:dd:ee")/
     IP(src="192.168.0.2", dst=ip_dst)/GRE()/IP(src="88.88.88.88")/
     UDP(sport=7,dport=7)/
     "This is a test")
sendp(p, iface="veth0")



