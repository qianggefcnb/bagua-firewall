#!/usr/bin/env python3
"""
八卦防火墙 - 完整版 (排除地址)
"""

from scapy.all import *
from collections import defaultdict

class Bagua防火墙:
    def __init__(self):
        print("=" * 50)
        print("🧱 八卦防火墙")
        print("=" * 50)
        self.状态 = 0
        print("   ✅ 启动完成")
        print("=" * 50)
    
    def 检测(self, packet):
        return 检测模块.检测(packet)


class 检测模块:
    # 排除的白名单地址
    白名单 = ("192.168.", "10.", "172.16.", "127.", "5.6.7.8", "192.168.1.1")
    
    # 敏感端口
    敏感端口 = {23, 445, 3389, 1433, 27017}
    
    # 攻击特征
    攻击库 = {2: "SYN扫描", 0: "NULL扫描"}
    
    # 恶意端口
    恶意端口 = {4444: "Metasploit", 5555: "ADB", 6667: "IRC", 31337: "BackOrifice"}
    
    统计 = defaultdict(int)
    
    @classmethod
    def 是白名单(cls, ip):
        if not ip: return True
        for p in cls.白名单:
            if ip.startswith(p) or ip == p: return True
        return False
    
    @classmethod
    def 检测(cls, packet):
        if IP not in packet: return {"状态": 0}
        
        src = packet[IP].src
        if cls.是白名单(src): return {"状态": 0, "来源": src, "结果": "白名单"}
        
        cls.统计[src] += 1
        
        # 检测
        if TCP in packet:
            dst = packet[TCP].dport
            flags = int(packet[TCP].flags)
            
            # 敏感端口
            if dst in cls.敏感端口:
                return {"状态": 1, "阴阳": "阴", "模块": "感知", "类型": f"敏感端口{dst}", "来源": src, "威胁": 0.9}
            
            # 攻击特征
            if flags in cls.攻击库:
                return {"状态": 1, "阴阳": "阴", "模块": "感知", "类型": cls.攻击库[flags], "来源": src, "威胁": 0.95}
            
            # 恶意端口
            if dst in cls.恶意端口:
                return {"状态": 1, "阴阳": "阴", "模块": "软件安全", "类型": "恶意端口", "名称": cls.恶意端口[dst], "来源": src, "威胁": 0.9}
        
        return {"状态": 0, "来源": src, "结果": "正常"}


if __name__ == "__main__":
    fw = Bagua防火墙()
    
    print("\n测试排除地址...")
    
    tests = [
        ("192.168.1.1", 80, 0),
        ("5.6.7.8", 80, 0),
        ("1.2.3.4", 445, 0),
        ("8.8.8.8", 80, 2),
    ]
    
    for ip, port, flags in tests:
        pkt = IP(src=ip)/TCP(dport=port, flags=flags) if port else IP(src=ip)
        r = fw.检测(pkt)
        print(f"  {ip}:{port} → {r.get('结果') or r.get('类型')}")
