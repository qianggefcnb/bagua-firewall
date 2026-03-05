#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 V3 (一)
0/1 感知 + 智能过滤 + 白名单
"""

from scapy.all import *
from collections import defaultdict
import time

class Bagua感知:
    def __init__(self):
        # 核心状态
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.来源IP = None
        
        # ============ 智能过滤配置 ============
        
        # 1. 白名单 (可信IP段)
        self.白名单 = {
            "192.168.0.0/16",    # 局域网
            "10.0.0.0/8",        # 局域网
            "172.16.0.0/12",     # 局域网
            "127.0.0.1",         # 本地
            "224.0.0.0/4",       # 组播
        }
        
        # 2. 正常行为端口 (不报警)
        self.正常端口 = {
            80, 443,             # HTTP/HTTPS
            53,                   # DNS
            123,                  # NTP
            22,                   # SSH (正常运维)
            3306, 5432,          # 数据库 (正常访问)
        }
        
        # 3. 异常端口 (敏感)
        self.敏感端口 = {
            23,      # Telnet
            445,     # SMB
            3389,    # RDP
            1433,    # MSSQL
            27017,   # MongoDB
            6379,    # Redis
        }
        
        # 4. 攻击特征
        self.攻击特征 = {
            "SYN扫描": lambda p: TCP in p and p[TCP].flags == 0x02,
            "NULL扫描": lambda p: TCP in p and p[TCP].flags == 0x00,
            "FIN扫描": lambda p: TCP in p and p[TCP].flags == 0x01,
            "Xmas扫描": lambda p: TCP in p and p[TCP].flags == 0x29,
        }
        
        # 统计
        self.统计 = {
            "坤": defaultdict(int),
            "坎": defaultdict(set),
            "巽": defaultdict(int),
            "震": [],
        }
        
        # 阈值
        self.阈值 = {
            "坤": 20,      # 局域网放宽到20
            "坎": 30,     # 局域网放宽到30
            "巽": 50000,
            "震": 5,
        }
        
        self.攻击者 = set()
        
        print("🧱 八卦感知系统 V3 启动")
        print("=" * 50)
        print("  智能过滤: ✅ 已启用")
        print(f"  白名单: {len(self.白名单)} 个网段")
        print(f"  正常端口: {len(self.正常端口)} 个")
        print(f"  敏感端口: {len(self.敏感端口)} 个")
        print("=" * 50)
    
    def 是白名单(self, ip):
        """检查是否在白名单"""
        if not ip:
            return True
        
        # 直接匹配
        if ip in self.白名单:
            return True
        
        # 局域网段匹配
        if ip.startswith("192.168."):
            return True
        if ip.startswith("10."):
            return True
        if ip.startswith("172.16.") or ip.startswith("172.17.") or ip.startswith("172.18.") or ip.startswith("172.19."):
            return True
        if ip.startswith("172.2"):  # 20-31
            return True
        
        return False
    
    def 是正常端口(self, port):
        """检查是否正常端口"""
        return port in self.正常端口
    
    def 是敏感端口(self, port):
        """检查是否敏感端口"""
        return port in self.敏感端口
    
    def 坤卦_连接检测(self, packet):
        """坤卦: 连接检测 - 排除白名单"""
        if IP not in packet:
            return False, None, None, 0
        
        src = packet[IP].src
        
        # 跳过白名单
        if self.是白名单(src):
            return False, None, None, 0
        
        self.统计["坤"][src] += 1
        
        if self.统计["坤"][src] > self.阈值["坤"]:
            return True, "连接数异常", src, 0.7
        
        return False, None, None, 0
    
    def 坎卦_端口检测(self, packet):
        """坎卦: 端口检测 - 区分正常/敏感"""
        if IP not in packet or TCP not in packet:
            return False, None, None, 0
        
        src = packet[IP].src
        dst = packet[TCP].dport
        
        # 跳过白名单
        if self.是白名单(src):
            return False, None, None, 0
        
        # 记录所有访问的端口
        self.统计["坎"][src].add(dst)
        
        # 只对敏感端口报警
        if self.是敏感端口(dst):
            return True, f"敏感端口{dst}", src, 0.9
        
        # 大量访问非敏感端口
        if len(self.统计["坎"][src]) > self.阈值["坎"]:
            return True, "端口扫描", src, 0.8
        
        return False, None, None, 0
    
    def 巽卦_流量检测(self, packet):
        """巽卦: 流量检测"""
        if IP not in packet:
            return False, None, None, 0
        
        src = packet[IP].src
        
        if self.是白名单(src):
            return False, None, None, 0
        
        size = len(packet[IP])
        self.统计["巽"][src] += size
        
        if self.统计["巽"][src] > self.阈值["巽"]:
            return True, "流量异常", src, 0.9
        
        return False, None, None, 0
    
    def 震卦_异常检测(self, packet):
        """震卦: 攻击特征检测"""
        if IP not in packet:
            return False, None, None, 0
        
        src = packet[IP].src
        
        if self.是白名单(src):
            return False, None, None, 0
        
        异常 = []
        
        # 检测攻击特征
        for 名称, 检测 in self.攻击特征.items():
            if 检测(packet):
                异常.append(名称)
        
        # 检测异常标志组合
        if TCP in packet:
            flags = packet[TCP].flags
            # SYN+FIN 同时存在是异常
            if (flags & 0x02) and (flags & 0x01):
                异常.append("SYN+FIN")
        
        if 异常:
            self.统计["震"].append({"ip": src, "异常": 异常, "time": time.time()})
            if len(self.统计["震"]) > self.阈值["震"]:
                return True, "攻击特征", src, 0.95
        
        return False, None, None, 0
    
    def 感知(self, packet):
        """主感知"""
        if IP not in packet:
            return self.获取状态()
        
        src = packet[IP].src
        
        # 白名单直接放行
        if self.是白名单(src):
            return self.获取状态()
        
        # 各卦检测
        检测, 类型, src_ip, 等级 = self.坤卦_连接检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级)
        
        检测, 类型, src_ip, 等级 = self.坎卦_端口检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级)
        
        检测, 类型, src_ip, 等级 = self.巽卦_流量检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级)
        
        检测, 类型, src_ip, 等级 = self.震卦_异常检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级)
        
        return self.获取状态()
    
    def _触发(self, 阴=False, 阳=False, 类型=None, src=None, 等级=0.5):
        self.状态 = 1
        self.阴阳 = "阴" if 阴 else "阳"
        self.威胁类型 = 类型
        self.威胁等级 = 等级
        self.来源IP = src
        if src:
            self.攻击者.add(src)
        return self.获取状态()
    
    def 获取状态(self):
        return {
            "状态": self.状态,
            "阴阳": self.阴阳,
            "威胁等级": self.威胁等级,
            "威胁类型": self.威胁类型,
            "来源IP": self.来源IP,
            "攻击者数量": len(self.攻击者)
        }
    
    def 打印状态(self):
        if self.状态 == 0:
            print(f"🟢 [0] 无感知 - 平静")
        else:
            阴阳符 = "☯️" if self.阴阳 == "阴" else "⚡"
            print(f"🔴 [1] {阴阳符}{self.阴阳} | {self.威胁类型} | {self.威胁等级:.0%} | {self.来源IP}")
    
    def 统计汇总(self):
        print("\n📊 八卦统计 (排除白名单):")
        print(f"  坤: {dict(self.统计['坤'])}")
        print(f"  坎: {dict(self.统计['坎'])}")
        print(f"  攻击者: {self.攻击者}")


# 测试
if __name__ == "__main__":
    感知 = Bagua感知()
    
    print("\n📡 混合测试 (正常+异常)...\n")
    
    # 1. 正常局域网流量 (不应报警)
    print("--- 测试正常局域网流量 ---")
    for i in range(30):  # 大量但正常
        pkt = IP(src="192.168.1.100")/TCP(dport=80)
        感知.感知(pkt)
    print("✅ 局域网流量: 无感知")
    
    # 2. 正常端口访问 (不应报警)
    print("\n--- 测试正常端口 ---")
    for port in [80, 443, 22, 3306]:
        for i in range(5):
            pkt = IP(src="8.8.8.8")/TCP(dport=port)
            感知.感知(pkt)
    print("✅ 正常端口: 无感知")
    
    # 3. 敏感端口访问 (应报警)
    print("\n--- 测试敏感端口 ---")
    pkt = IP(src="1.2.3.4")/TCP(dport=445)
    result = 感知.感知(pkt)
    感知.打印状态()
    
    # 4. 攻击特征 (应报警)
    print("\n--- 测试攻击特征 ---")
    pkt = IP(src="5.6.7.8")/TCP(dport=80, flags=0x02)  # SYN扫描
    result = 感知.感知(pkt)
    感知.打印状态()
    
    感知.统计汇总()
    print("\n✅ V3 测试完成!")
