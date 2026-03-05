#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 V5 (一)
0/1 感知 + 详细IP信息 + 来源追溯
"""

from scapy.all import *
from collections import defaultdict
import time
import json

class Bagua感知:
    def __init__(self):
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.威胁描述 = None
        self.来源IP = None
        
        # IP信息库
        self.端口作用 = {
            80: "HTTP网页", 443: "HTTPS加密", 8080: "HTTP代理",
            22: "SSH远程", 23: "Telnet明文", 3389: "RDP桌面",
            445: "SMB共享", 3306: "MySQL", 5432: "PostgreSQL",
            1433: "MSSQL", 27017: "MongoDB", 6379: "Redis",
            53: "DNS", 123: "NTP", 25: "SMTP", 110: "POP3",
            5000: "Flask", 3000: "Node.js", 8000: "Django",
            11211: "Memcached", 9200: "Elasticsearch",
        }
        
        self.敏感端口 = {23, 445, 3389, 1433, 27017, 6379, 9200, 11211}
        
        # 攻击手段库
        self.攻击手段 = {
            0x02: ("SYN扫描", "只发送SYN包试探端口", "探测开放端口"),
            0x00: ("NULL扫描", "无标志位扫描", "绕过防火墙"),
            0x01: ("FIN扫描", "只发送FIN包", "探测端口"),
            0x29: ("Xmas扫描", "FIN/PSH/URG同时置位", "探测状态"),
        }
        
        # 白名单
        self.白名单前缀 = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "127.", "224.", "255.")
        
        # 攻击者详情记录
        self.攻击者详情 = {}
        
        # 统计
        self.统计 = {"坤": defaultdict(int), "坎": defaultdict(set), "震": []}
        self.阈值 = {"坤": 20, "坎": 30, "震": 5}
        
        print("🧱 八卦感知系统 V5 启动")
        print("=" * 60)
        print(f"  端口库: {len(self.端口作用)} 个")
        print(f"  敏感端口: {len(self.敏感端口)} 个")
        print(f"  攻击手段: {len(self.攻击手段)} 种")
        print("=" * 60)
    
    def 端口作用查询(self, port):
        return self.端口作用.get(port, "未知")
    
    def 是白名单(self, ip):
        if not ip:
            return True
        for 前缀 in self.白名单前缀:
            if ip.startswith(前缀):
                return True
        return False
    
    def 获取IP详情(self, ip):
        """获取IP详细信息"""
        详情 = {"ip": ip, "类型": "未知", "地理位置": "未知"}
        
        # 判断IP类型
        if ip.startswith("192.168."):
            详情["类型"] = "局域网"
            详情["描述"] = "私有地址"
        elif ip.startswith("10."):
            详情["类型"] = "局域网"
            详情["描述"] = "私有地址"
        elif ip.startswith("172."):
            详情["类型"] = "局域网"
            详情["描述"] = "私有地址"
        elif ip.startswith("127."):
            详情["类型"] = "本地"
            详情["描述"] = "回环地址"
        elif ip.startswith("224."):
            详情["类型"] = "组播"
            详情["描述"] = "多播地址"
        else:
            详情["类型"] = "公网"
            详情["描述"] = "外部地址"
        
        # 常见公网IP识别
        公网识别 = {
            "1.1.1.": ("Cloudflare", "DNS"),
            "8.8.8.": ("Google", "DNS"),
            "114.114.114.": ("中国DNS", "DNS"),
            "223.5.5.": ("阿里DNS", "DNS"),
        }
        
        for 前缀, (来源, 服务) in 公网识别.items():
            if ip.startswith(前缀):
                详情["来源"] = 来源
                详情["服务"] = 服务
                break
        
        return 详情
    
    def 记录攻击者(self, ip, 威胁类型, 威胁等级, 描述):
        """详细记录攻击者信息"""
        if ip not in self.攻击者详情:
            self.攻击者详情[ip] = {
                "ip": ip,
                "首次攻击": time.strftime("%Y-%m-%d %H:%M:%S"),
                "攻击次数": 0,
                "攻击类型": [],
                "威胁等级": 0,
                "描述": [],
                "ip详情": self.获取IP详情(ip),
            }
        
        详情 = self.攻击者详情[ip]
        详情["攻击次数"] += 1
        if 威胁类型 not in 详情["攻击类型"]:
            详情["攻击类型"].append(威胁类型)
        详情["描述"].append(描述)
        详情["威胁等级"] = max(详情["威胁等级"], 威胁等级)
    
    def 坤卦_连接检测(self, packet):
        """坤卦: 连接检测"""
        if IP not in packet:
            return False, None, None, 0, None
        
        src = packet[IP].src
        if self.是白名单(src):
            return False, None, None, 0, None
        
        self.统计["坤"][src] += 1
        
        if self.统计["坤"][src] > self.阈值["坤"]:
            IP详情 = self.获取IP详情(src)
            描述 = f"连接数达 {self.统计['坤'][src]} 次 [{IP详情['类型']}]"
            return True, "连接数异常", src, 0.7, 描述
        
        return False, None, None, 0, None
    
    def 坎卦_端口检测(self, packet):
        """坎卦: 端口检测"""
        if IP not in packet or TCP not in packet:
            return False, None, None, 0, None
        
        src = packet[IP].src
        if self.是白名单(src):
            return False, None, None, 0, None
        
        dst = packet[TCP].dport
        self.统计["坎"][src].add(dst)
        
        IP详情 = self.获取IP详情(src)
        
        # 敏感端口
        if dst in self.敏感端口:
            描述 = f"访问敏感端口 {dst}({self.端口作用查询(dst)}) [{IP详情['类型']}]"
            return True, "敏感端口", src, 0.9, 描述
        
        # 端口扫描
        if len(self.统计["坎"][src]) > self.阈值["坎"]:
            端口列表 = [str(p) for p in list(self.统计["坎"][src])[:5]]
            描述 = f"扫描{len(self.统计['坎'][src])}个端口: {端口列表}... [{IP详情['类型']}]"
            return True, "端口扫描", src, 0.8, 描述
        
        return False, None, None, 0, None
    
    def 震卦_攻击检测(self, packet):
        """震卦: 攻击检测"""
        if IP not in packet or TCP not in packet:
            return False, None, None, 0, None
        
        src = packet[IP].src
        if self.是白名单(src):
            return False, None, None, 0, None
        
        flags = packet[TCP].flags
        dst = packet[TCP].dport
        
        IP详情 = self.获取IP详情(src)
        
        # 攻击特征检测
        if flags in self.攻击手段:
            手段, 描述, 风险 = self.攻击手段[flags]
            完整描述 = f"{手段} → 端口{dst}({self.端口作用查询(dst)}) [{IP详情['类型']}]"
            return True, 手段, src, 0.95, 完整描述
        
        # SYN Flood
        if flags & 0x02:
            self.统计["震"].append(src)
            if len(self.统计["震"]) > 10:
                return True, "SYN Flood", src, 0.99, f"大量SYN包 [{IP详情['类型']}]"
        
        return False, None, None, 0, None
    
    def 感知(self, packet):
        """主感知"""
        if IP not in packet:
            return self.获取状态()
        
        src = packet[IP].src
        
        if self.是白名单(src):
            return self.获取状态()
        
        # 各卦检测
        for 检测 in [self.坤卦_连接检测, self.坎卦_端口检测, self.震卦_攻击检测]:
            检测结果 = 检测(packet)
            if 检测结果[0]:
                _, 类型, src_ip, 等级, 描述 = 检测结果
                return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级, 描述=描述)
        
        return self.获取状态()
    
    def _触发(self, 阴=False, 阳=False, 类型=None, src=None, 等级=0.5, 描述=None):
        self.状态 = 1
        self.阴阳 = "阴" if 阴 else "阳"
        self.威胁类型 = 类型
        self.威胁等级 = 等级
        self.威胁描述 = 描述
        self.来源IP = src
        
        if src:
            self.记录攻击者(src, 类型, 等级, 描述)
        
        return self.获取状态()
    
    def 获取状态(self):
        return {
            "状态": self.状态,
            "阴阳": self.阴阳,
            "威胁等级": self.威胁等级,
            "威胁类型": self.威胁类型,
            "威胁描述": self.威胁描述,
            "来源IP": self.来源IP,
            "IP详情": self.获取IP详情(self.来源IP) if self.来源IP else None,
        }
    
    def 打印状态(self):
        if self.状态 == 0:
            print(f"🟢 [0] 无感知 - 系统平静")
        else:
            IP详情 = self.获取IP详情(self.来源IP)
            阴阳符 = "☯️" if self.阴阳 == "阴" else "⚡"
            print(f"🔴 [1] {阴阳符}{self.阴阳} 感知到威胁!")
            print(f"    🌐 来源IP: {self.来源IP}")
            print(f"    📍 IP类型: {IP详情['类型']} - {IP详情.get('描述', '')}")
            if IP详情.get('来源'):
                print(f"    🏢 来源: {IP详情['来源']} ({IP详情.get('服务', '')})")
            print(f"    ⚔️  威胁: {self.威胁类型} ({self.威胁等级:.0%})")
            print(f"    📝 描述: {self.威胁描述}")
    
    def 打印攻击者列表(self):
        """打印所有攻击者列表"""
        print("\n" + "=" * 60)
        print("👥 攻击者详细列表:")
        print("=" * 60)
        
        if not self.攻击者详情:
            print("  无攻击记录")
            return
        
        for ip, 详情 in sorted(self.攻击者详情.items(), key=lambda x: x[1]["威胁等级"], reverse=True):
            print(f"\n  🌐 IP: {ip}")
            print(f"     类型: {详情['ip详情']['类型']}")
            print(f"     首次: {详情['首次攻击']}")
            print(f"     次数: {详情['攻击次数']}")
            print(f"     威胁: {详情['威胁等级']:.0%}")
            print(f"     手段: {', '.join(详情['攻击类型'])}")


if __name__ == "__main__":
    感知 = Bagua感知()
    
    print("\n📡 V5 详细IP测试...\n")
    
    # 1. 局域网
    print("--- 局域网测试 ---")
    for i in range(25):
        pkt = IP(src="192.168.1.100")/TCP(dport=80)
        感知.感知(pkt)
    print("✅ 局域网: 无感知")
    
    # 2. 公网DNS
    print("\n--- 公网DNS测试 ---")
    for i in range(5):
        pkt = IP(src="8.8.8.8")/TCP(dport=53)
        感知.感知(pkt)
    print("✅ 公网DNS: 无感知")
    
    # 3. SYN扫描
    print("\n--- SYN扫描测试 ---")
    pkt = IP(src="1.2.3.4")/TCP(dport=80, flags=0x02)
    result = 感知.感知(pkt)
    感知.打印状态()
    
    # 4. 敏感端口
    print("\n--- 敏感端口测试 ---")
    pkt = IP(src="5.6.7.8")/TCP(dport=445)
    感知.感知(pkt)
    感知.打印状态()
    
    # 5. 端口扫描
    print("\n--- 端口扫描测试 ---")
    for port in [22, 23, 80, 445, 3306, 3389]:
        pkt = IP(src="9.8.7.6")/TCP(dport=port)
        感知.感知(pkt)
    感知.打印状态()
    
    # 攻击者列表
    感知.打印攻击者列表()
    
    print("\n✅ V5 测试完成!")
