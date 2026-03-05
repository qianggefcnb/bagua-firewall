#!/usr/bin/env python3
from scapy.all import *

# 模拟端口扫描
print("发送测试包...")
for i in range(15):
    pkt = IP(src="192.168.1.100")/TCP(dport=1000+i)
    send(pkt, verbose=0)
print("发送完成")
