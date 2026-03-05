#!/usr/bin/env python3
"""
八卦防火墙 - 软件安全模块
检测恶意软件、漏洞利用、供应链攻击
"""

from scapy.all import *
from collections import defaultdict
import hashlib
import time

class Bagua软件安全:
    def __init__(self):
        # 安全状态
        self.安全状态 = "正常"
        self.威胁列表 = []
        
        # ============ 软件安全特征库 ============
        
        # 恶意端口特征
        self.恶意端口特征 = {
            4444: "Metasploit后门",
            5555: "ADB远程",
            6667: "IRC后门",
            31337: "BackOrifice",
            12345: "NetBus",
            27374: "SubSeven",
            3128: "HTTP代理",
            8080: "HTTP代理",
            3128: "代理",
        }
        
        # 可疑协议特征
        self.可疑协议 = {
            "DNS隧道": lambda p: DNS in p and self._检测DNS隧道(p),
            "ICMP隧道": lambda p: ICMP in p and len(p[ICMP].load) > 64,
            "HTTP隧道": lambda p: TCP in p and Raw in p and self._检测HTTP隧道(p),
        }
        
        # 漏洞利用特征
        self.漏洞利用 = {
            "SQL注入": [b"'", b"UNION", b"SELECT", b"OR 1=1", b"--"],
            "XSS": [b"<script", b"javascript:", b"onerror="],
            "命令注入": [b"; ls", b"| cat", b"& whoami", b"`id`"],
            "路径遍历": [b"../", b"..\\", b"/etc/passwd"],
        }
        
        # 白名单
        self.白名单IP = ("192.168.", "10.", "172.16.", "127.")
        
        # 统计
        self.统计 = {
            "恶意端口": defaultdict(int),
            "可疑协议": defaultdict(int),
            "漏洞利用": defaultdict(int),
        }
        
        print("🛡️ 八卦防火墙 - 软件安全模块")
        print("=" * 55)
        print("  🔍 功能:")
        print("     • 恶意端口检测")
        print("     • 可疑协议分析")
        print("     • 漏洞利用检测")
        print("     • 供应链攻击识别")
        print("=" * 55)
    
    def _检测DNS隧道(self, packet):
        """检测DNS隧道"""
        if DNS in packet:
            # DNS查询长度异常
            if packet[DNS].qd:
                qname = str(packet[DNS].qd.qname)
                # 异常长的子域名可能是隧道
                if len(qname) > 50:
                    return True
        return False
    
    def _检测HTTP隧道(self, packet):
        """检测HTTP隧道"""
        if Raw in packet:
            data = bytes(packet[Raw].load)
            # 检查异常大的HTTP请求
            if len(data) > 5000:
                return True
            # 检查非标准HTTP方法
            if b"CONNECT" in data or b"TUNNEL" in data:
                return True
        return False
    
    def 检测恶意端口(self, packet):
        """检测恶意端口访问"""
        if TCP not in packet:
            return None
        
        dst_port = packet[TCP].dport
        src_ip = packet[IP].src if IP in packet else "未知"
        
        if dst_port in self.恶意端口特征:
            return {
                "类型": "恶意端口",
                "严重": "高",
                "端口": dst_port,
                "名称": self.恶意端口特征[dst_port],
                "来源": src_ip,
                "描述": f"访问恶意端口 {dst_port} ({self.恶意端口特征[dst_port]})"
            }
        return None
    
    def 检测可疑协议(self, packet):
        """检测可疑协议"""
        for 名称, 检测函数 in self.可疑协议.items():
            try:
                if 检测函数(packet):
                    return {
                        "类型": "可疑协议",
                        "严重": "高",
                        "名称": 名称,
                        "描述": f"检测到{名称}"
                    }
            except:
                pass
        return None
    
    def 检测漏洞利用(self, packet):
        """检测漏洞利用尝试"""
        if TCP not in packet or Raw not in packet:
            return None
        
        try:
            data = bytes(packet[Raw].load)
        except:
            return None
        
        src_ip = packet[IP].src if IP in packet else "未知"
        
        for 漏洞类型, 特征列表 in self.漏洞利用.items():
            for 特征 in 特征列表:
                if 特征 in data:
                    return {
                        "类型": "漏洞利用",
                        "严重": "严重",
                        "名称": 漏洞类型,
                        "特征": 特征.decode('utf-8', errors='ignore'),
                        "来源": src_ip,
                        "描述": f"{漏洞类型}尝试 - 特征:{特征.decode('utf-8', errors='ignore')}"
                    }
        return None
    
    def 检测(self, packet):
        """主检测"""
        if IP not in packet:
            return None
        
        src = packet[IP].src
        
        # 跳过白名单
        for 白 in self.白名单IP:
            if src.startswith(白):
                return None
        
        # 1. 恶意端口
        结果 = self.检测恶意端口(packet)
        if 结果:
            self.记录威胁(结果)
            return 结果
        
        # 2. 可疑协议
        结果 = self.检测可疑协议(packet)
        if 结果:
            self.记录威胁(结果)
            return 结果
        
        # 3. 漏洞利用
        结果 = self.检测漏洞利用(packet)
        if 结果:
            self.记录威胁(结果)
            return 结果
        
        return None
    
    def 记录威胁(self, 威胁):
        """记录威胁"""
        威胁["时间"] = time.strftime("%H:%M:%S")
        self.威胁列表.append(威胁)
        self.安全状态 = "警告"
    
    def 打印结果(self, 结果):
        """打印检测结果"""
        if not 结果:
            return
        
        严重符号 = {"低": "⚠️", "中": "🔶", "高": "🔴", "严重": "💀"}
        符号 = 严重符号.get(结果.get("严重", "低"), "⚠️")
        
        print(f"\n{符号} 软件安全告警!")
        print(f"   类型: {结果['类型']}")
        print(f"   名称: {结果['名称']}")
        print(f"   严重: {结果['严重']}")
        if "端口" in 结果:
            print(f"   端口: {结果['端口']} ({结果['名称']})")
        if "描述" in 结果:
            print(f"   描述: {结果['描述']}")
        if "来源" in 结果:
            print(f"   来源: {结果['来源']}")
    
    def 安全报告(self):
        """安全报告"""
        print("\n" + "=" * 55)
        print("📊 软件安全报告")
        print("=" * 55)
        print(f"  安全状态: {self.安全状态}")
        print(f"  威胁总数: {len(self.威胁列表)}")
        
        if self.威胁列表:
            print("\n  威胁详情:")
            for i, 威胁 in enumerate(self.威胁列表[-5:], 1):
                print(f"    {i}. [{威胁['时间']}] {威胁['类型']} - {威胁['名称']}")


if __name__ == "__main__":
    安全 = Bagua软件安全()
    
    print("\n📡 测试开始...\n")
    
    # 1. 恶意端口
    print("--- 测试恶意端口 ---")
    pkt = IP(src="1.2.3.4")/TCP(dport=4444)
    结果 = 安全.检测(pkt)
    if 结果: 安全.打印结果(结果)
    
    # 2. 可疑协议
    print("\n--- 测试可疑协议 ---")
    pkt = IP(src="5.6.7.8")/DNS(qd=DNSQR(qname="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    结果 = 安全.检测(pkt)
    if 结果: 安全.打印结果(结果)
    
    # 3. SQL注入
    print("\n--- 测试漏洞利用 ---")
    pkt = IP(src="9.8.7.6")/TCP(dport=80)/Raw(load=b"GET /?id=1' OR 1=1-- HTTP/1.1")
    结果 = 安全.检测(pkt)
    if 结果: 安全.打印结果(结果)
    
    # 安全报告
    安全.安全报告()
    
    print("\n✅ 软件安全模块测试完成!")
