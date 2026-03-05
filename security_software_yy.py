#!/usr/bin/env python3
"""
八卦防火墙 - 软件安全模块 (阴阳版)
主动感知 + 被动感知
"""

from scapy.all import *
from collections import defaultdict
import time

class Bagua软件安全:
    def __init__(self):
        self.状态 = 0
        self.阴阳 = None
        
        # 被动感知 (阴) - 被人攻击
        self.恶意端口 = {
            4444: ("Metasploit", "高"),
            5555: ("ADB远程", "高"),
            6667: ("IRC后门", "中"),
            31337: ("BackOrifice", "高"),
            12345: ("NetBus", "中"),
        }
        
        self.漏洞库 = {
            "SQL注入": [b"'", b"UNION", b"SELECT", b"OR 1=1", b"--"],
            "XSS": [b"<script", b"javascript:", b"onerror="],
            "命令注入": [b"; ls", b"| cat", b"& whoami"],
            "路径遍历": [b"../", b"/etc/passwd"],
        }
        
        # 主动感知 (阳) - 发现外部威胁
        self.异常端口 = {4444, 5555, 6667, 31337}
        
        self.白名单 = ("192.168.", "10.", "172.16.", "127.")
        
        self.被动统计 = defaultdict(int)
        self.主动统计 = defaultdict(int)
        
        print("🛡️ 八卦软件安全 - 阴阳感知")
        print("=" * 50)
        print("  ☯️ 阴 (被动): 被人攻击")
        print("  ⚡ 阳 (主动): 发现外部威胁")
        print("=" * 50)
    
    def 是白名单(self, ip):
        if not ip: return True
        for p in self.白名单:
            if ip.startswith(p): return True
        return False
    
    # 被动感知 (阴)
    def 阴_检测(self, packet):
        if IP not in packet or TCP not in packet:
            return None
        
        src = packet[IP].src
        dst = packet[TCP].dport
        
        if self.是白名单(src):
            return None
        
        # 恶意端口
        if dst in self.恶意端口:
            名称, 严重 = self.恶意端口[dst]
            self.被动统计[src] += 1
            return {
                "阴阳": "阴", "方式": "被动感知", "类型": "恶意端口",
                "名称": 名称, "严重": 严重, "来源": src,
                "描述": f"被动检测到恶意端口 {dst}({名称})"
            }
        
        # 漏洞利用
        if Raw in packet:
            try:
                data = bytes(packet[Raw].load)
                for 漏洞, 特征列表 in self.漏洞库.items():
                    for 特征 in 特征列表:
                        if 特征 in data:
                            self.被动统计[src] += 1
                            return {
                                "阴阳": "阴", "方式": "被动感知", "类型": "漏洞利用",
                                "名称": 漏洞, "严重": "严重", "来源": src,
                                "描述": f"被动检测到{漏洞}"
                            }
            except:
                pass
        
        return None
    
    # 主动感知 (阳)
    def 阳_检测(self, packet):
        if IP not in packet or TCP not in packet:
            return None
        
        src = packet[IP].src
        dst = packet[TCP].dport
        flags = packet[TCP].flags
        
        # 端口扫描 (SYN)
        if flags == 2:
            self.主动统计[src] += 1
            return {
                "阴阳": "阳", "方式": "主动感知", "类型": "端口扫描",
                "名称": "SYN扫描", "严重": "高", "来源": src,
                "描述": f"主动发现扫描: 端口{dst}"
            }
        
        # NULL扫描
        if flags == 0:
            self.主动统计[src] += 1
            return {
                "阴阳": "阳", "方式": "主动感知", "类型": "端口扫描",
                "名称": "NULL扫描", "严重": "高", "来源": src,
                "描述": "主动发现NULL扫描"
            }
        
        # 发现异常端口访问
        if dst in self.异常端口:
            名称 = {4444: "Metasploit", 5555: "ADB", 6667: "IRC", 31337: "BackOrifice"}[dst]
            self.主动统计[src] += 1
            return {
                "阴阳": "阳", "方式": "主动感知", "类型": "异常发现",
                "名称": f"可疑端口{dst}", "严重": "高", "来源": src,
                "描述": f"主动发现访问可疑端口 {dst}({名称})"
            }
        
        return None
    
    def 检测(self, packet):
        结果 = self.阴_检测(packet)
        if not 结果: 结果 = self.阳_检测(packet)
        
        if 结果:
            self.状态 = 1
            self.阴阳 = 结果["阴阳"]
            return 结果
        
        return {"状态": 0, "阴阳": None}
    
    def 打印(self, 结果):
        if not 结果 or 结果.get("状态") == 0:
            print(f"\n🟢 安全 - 无感知")
            return
        
        阴阳符 = "☯️阴" if 结果["阴阳"] == "阴" else "⚡阳"
        严重符 = {"低": "⚠️", "中": "🔶", "高": "🔴", "严重": "💀"}
        符 = 严重符.get(结果.get("严重", "低"), "⚠️")
        
        print(f"\n🔴 {阴阳符} {结果['方式']}!")
        print(f"   {符} {结果['类型']}: {结果['名称']}")
        print(f"   来源: {结果['来源']}")
        print(f"   描述: {结果['描述']}")


if __name__ == "__main__":
    安全 = Bagua软件安全()
    
    print("\n📡 测试...\n")
    
    # 被动
    print("--- ☯️ 被动感知 ---")
    安全.检测(IP(src="1.1.1.1")/TCP(dport=4444))
    安全.打印(安全.阴_检测(IP(src="1.1.1.1")/TCP(dport=4444)) or {"状态":0})
    
    print("\n--- SQL注入 ---")
    pkt = IP(src="2.2.2.2")/TCP(dport=80)/Raw(load=b"GET /?id=1' OR 1=1--")
    r = 安全.阴_检测(pkt)
    安全.打印(r or {"状态":0})
    
    # 主动
    print("\n--- ⚡ 主动感知 ---")
    pkt = IP(src="3.3.3.3")/TCP(dport=80, flags=2)
    r = 安全.阳_检测(pkt)
    安全.打印(r or {"状态":0})
    
    pkt = IP(src="4.4.4.4")/TCP(dport=31337)
    r = 安全.阳_检测(pkt)
    安全.打印(r or {"状态":0})
    
    print("\n✅ 完成!")
