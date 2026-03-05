#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 (一)
0/1 感知: 无感知 vs 感知到威胁
"""

from scapy.all import *
import time
from collections import defaultdict

class Bagua感知:
    def __init__(self):
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.来源IP = None
        
        # 统计
        self.连接计数 = defaultdict(int)
        self.端口扫描 = defaultdict(set)
        
        # 阈值
        self.连接阈值 = 5
        self.端口阈值 = 10
        
        print("🧱 八卦感知系统启动")
        print(f"   连接阈值: {self.连接阈值}")
        print(f"   端口阈值: {self.端口阈值}")
        print("=" * 40)
    
    def 坤卦_基础检测(self, packet):
        """坤卦: 基础连接检测"""
        if IP in packet:
            src_ip = packet[IP].src
            self.连接计数[src_ip] += 1
            if self.连接计数[src_ip] > self.连接阈值:
                return True, "连接数异常", src_ip
        return False, None, None
    
    def 坎卦_端口检测(self, packet):
        """坎卦: 端口扫描检测"""
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            self.端口扫描[src_ip].add(dst_port)
            if len(self.端口扫描[src_ip]) > self.端口阈值:
                return True, "端口扫描", src_ip
        return False, None, None
    
    def 感知(self, packet):
        """主感知函数"""
        # 坤卦
        检测到, 类型, src = self.坤卦_基础检测(packet)
        if 检测到:
            return self._触发感知(阴=True, 威胁类型=类型, 威胁等级=0.7, 来源=src)
        
        # 坎卦
        检测到, 类型, src = self.坎卦_端口检测(packet)
        if 检测到:
            return self._触发感知(阴=True, 威胁类型=类型, 威胁等级=0.8, 来源=src)
        
        return {"状态": 0, "阴阳": None, "威胁等级": 0, "威胁类型": None}
    
    def _触发感知(self, 阴=False, 阳=False, 威胁类型=None, 威胁等级=0.5, 来源=None):
        self.状态 = 1
        self.阴阳 = "阴" if 阴 else "阳"
        self.威胁类型 = 威胁类型
        self.威胁等级 = 威胁等级
        self.来源IP = 来源
        return self.获取状态()
    
    def 获取状态(self):
        return {
            "状态": self.状态,
            "阴阳": self.阴阳,
            "威胁等级": self.威胁等级,
            "威胁类型": self.威胁类型,
            "来源IP": self.来源IP
        }
    
    def 打印状态(self):
        if self.状态 == 0:
            print(f"🟢 状态: 0 (无感知)")
        else:
            print(f"🔴 状态: 1 | 阴阳: {self.阴阳} | 类型: {self.威胁类型} | 威胁: {self.威胁等级:.0%} | IP: {self.来源IP}")


# 测试
if __name__ == "__main__":
    感知 = Bagua感知()
    
    print("\n📡 模拟测试...\n")
    
    # 模拟端口扫描 (11个不同端口)
    for i in range(11):
        pkt = IP(src="192.168.1.100", dst="10.0.0.1")/TCP(dport=1000+i)
        result = 感知.感知(pkt)
        if result["状态"] == 1:
            感知.打印状态()
    
    print("\n✅ 测试完成!")
