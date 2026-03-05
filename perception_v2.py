#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 V2 (一)
0/1 感知 + 阴阳 + 三生万物
"""

from scapy.all import *
import time
from collections import defaultdict
import json

class Bagua感知:
    def __init__(self):
        # 核心状态
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.来源IP = None
        
        # 八卦统计
        self.统计 = {
            "坤": defaultdict(int),   # 连接数
            "坎": defaultdict(set),  # 端口扫描
            "巽": defaultdict(int),  # 流量
            "震": [],                 # 异常事件
        }
        
        # 阈值配置
        self.阈值 = {
            "坤": 5,      # 连接数
            "坎": 10,     # 端口数
            "巽": 10000,  # 流量字节
            "震": 3,      # 异常次数
        }
        
        # 攻击者记录
        self.攻击者 = set()
        
        print("🧱 八卦感知系统 V2 启动")
        print("=" * 50)
        print(f"  坤(连接): {self.阈值['坤']}")
        print(f"  坎(端口): {self.阈值['坎']}")
        print(f"  巽(流量): {self.阈值['巽']}")
        print(f"  震(报警): {self.阈值['震']}")
        print("=" * 50)
    
    def 坤卦_连接检测(self, packet):
        """坤卦: 基础连接检测 - 检测连接数异常"""
        if IP in packet:
            src = packet[IP].src
            self.统计["坤"][src] += 1
            
            if self.统计["坤"][src] > self.阈值["坤"]:
                return True, "连接数异常", src, 0.7
        return False, None, None, 0
    
    def 坎卦_端口检测(self, packet):
        """坎卦: 端口扫描检测 - 检测端口扫描"""
        if IP in packet and TCP in packet:
            src = packet[IP].src
            dst = packet[TCP].dport
            self.统计["坎"][src].add(dst)
            
            if len(self.统计["坎"][src]) > self.阈值["坎"]:
                return True, "端口扫描", src, 0.8
        return False, None, None, 0
    
    def 巽卦_流量检测(self, packet):
        """巽卦: 流量检测 - 检测流量异常"""
        if IP in packet:
            src = packet[IP].src
            size = len(packet[IP])
            self.统计["巽"][src] += size
            
            if self.统计["巽"][src] > self.阈值["巽"]:
                return True, "流量异常", src, 0.9
        return False, None, None, 0
    
    def 震卦_异常检测(self, packet):
        """震卦: 异常检测 - 检测各种异常"""
        异常 = []
        
        # SYN flood检测
        if TCP in packet and packet[TCP].flags & 0x02:  # SYN
            异常.append("SYN扫描")
        
        # ICMP检测
        if ICMP in packet:
            异常.append("ICMP探测")
        
        # 端口检测
        if TCP in packet:
            port = packet[TCP].dport
            if port in [21, 23, 445, 3389]:  # 敏感端口
                异常.append(f"敏感端口{port}")
        
        if 异常:
            src = packet[IP].src if IP in packet else "未知"
            self.统计["震"].append({"ip": src, "异常": 异常, "time": time.time()})
            if len(self.统计["震"]) > self.阈值["震"]:
                return True, "异常事件", src, 0.85
        
        return False, None, None, 0
    
    def 阳卦_主动检测(self, packet):
        """阳卦: 主动感知 - 检测外部威胁"""
        # 检测是否是主动探测
        if TCP in packet:
            flags = packet[TCP].flags
            # SYN-only 可能是扫描
            if flags == 0x02:  # SYN
                return True, "主动扫描", packet[IP].src, 0.6
        
        # 检测异常协议
        if DNS in packet:
            # 大量DNS查询可能是攻击
            if self.统计["坤"][packet[IP].src] > 3:
                return True, "DNS查询异常", packet[IP].src, 0.5
        
        return False, None, None, 0
    
    def 感知(self, packet):
        """主感知函数"""
        if IP not in packet:
            return self.获取状态()
        
        # 阴卦检测 (被动)
        检测, 类型, src, 等级 = self.坤卦_连接检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src, 等级=等级)
        
        检测, 类型, src, 等级 = self.坎卦_端口检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src, 等级=等级)
        
        检测, 类型, src, 等级 = self.巽卦_流量检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src, 等级=等级)
        
        检测, 类型, src, 等级 = self.震卦_异常检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src, 等级=等级)
        
        # 阳卦检测 (主动)
        检测, 类型, src, 等级 = self.阳卦_主动检测(packet)
        if 检测:
            return self._触发(阳=True, 类型=类型, src=src, 等级=等级)
        
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
        print("\n📊 八卦统计:")
        print(f"  坤: {dict(self.统计['坤'])}")
        print(f"  坎: {len(self.统计['坎'])} 个IP扫描")
        print(f"  巽: {dict(self.统计['巽'])}")
        print(f"  震: {len(self.统计['震'])} 个异常事件")
        print(f"  攻击者: {self.攻击者}")


# 测试
if __name__ == "__main__":
    感知 = Bagua感知()
    
    print("\n📡 模拟攻击测试...\n")
    
    # 模拟多种攻击
    for i in range(15):  # 端口扫描
        pkt = IP(src="192.168.1.100")/TCP(dport=1000+i)
        感知.感知(pkt)
    
    for i in range(3):  # SYN扫描
        pkt = IP(src="10.0.0.50")/TCP(dport=80, flags=0x02)
        感知.感知(pkt)
    
    # ICMP探测
    pkt = IP(src="172.16.0.1")/ICMP()
    感知.感知(pkt)
    
    感知.打印状态()
    感知.统计汇总()
    
    print("\n✅ V2 测试完成!")
