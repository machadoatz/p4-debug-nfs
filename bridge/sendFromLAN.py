#!/usr/bin/env python
import sys
from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import Ether, IP, TCP, sendp

packet =  Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=6010, sport=6010) / "aaa"
sendp(packet, iface="eth0")