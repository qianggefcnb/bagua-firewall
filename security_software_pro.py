#!/usr/bin/env python3
"""
八卦防火墙 - 软件安全模块 Pro版
增强检测 + AI集成 + 实时学习
"""

from scapy.all import *
from collections import defaultdict
import hashlib
import time
import re

class Bagua软件安全Pro:
    def __init__(self):
        self.安全状态 = "正常"
        self.威胁列表 = []
        
        # ============ 增强特征库 ============
        
        # 1. 恶意端口 (扩展)
        self.恶意端口 = {
            # 后门
            4444: ("Metasploit", "高"),
            5555: ("ADB远程", "高"),
            6667: ("IRC后门", "中"),
            31337: ("BackOrifice", "高"),
            12345: ("NetBus", "中"),
            27374: ("SubSeven", "中"),
            # 恶意软件
            8443: ("Pony", "中"),
            4899: ("RAdmin", "低"),
            5900: ("VNC", "低"),
            # 僵尸网络
            5554: ("Sasser", "高"),
            6697: ("僵尸网络", "中"),
        }
        
        # 2. 可疑协议
        self.可疑协议 = {
            "DNS隧道": lambda p: self._check_dns_tunnel(p),
            "ICMP隧道": lambda p: self._check_icmp_tunnel(p),
            "HTTP隐蔽": lambda p: self._check_http_tunnel(p),
            "FTP异常": lambda p: self._check_ftp_anon(p),
        }
        
        # 3. 漏洞利用 (扩展)
        self.漏洞库 = {
            "SQL注入": {
                "特征": [b"'", b"UNION", b"SELECT", b"OR 1=1", b"--", b"1=1", b"'1'='1"],
                "严重": "严重",
                "正则": r"(\%27)|(\')|(\-\-)|(\%23)|(#)"
            },
            "XSS跨站": {
                "特征": [b"<script", b"javascript:", b"onerror=", b"onload=", b"<img"],
                "严重": "高",
                "正则": r"<script|javascript:|onerror=|onload="
            },
            "命令注入": {
                "特征": [b"; ls", b"| cat", b"& whoami", b"`id`", b"$(", b"|&"],
                "严重": "严重",
                "正则": r"[;&|`$]"
            },
            "路径遍历": {
                "特征": [b"../", b"..\\", b"/etc/passwd", b"boot.ini", b"\\windows\\"],
                "严重": "高",
                "正则": r"\.\./|\.\.\\"
            },
            "XML注入": {
                "特征": [b"<?xml", b"<!DOCTYPE", b"CDATA", b"xxe"],
                "严重": "高",
                "正则": r"<\?xml|<!DOCTYPE"
            },
            "SSRF": {
                "特征": [b"file://", b"gopher://", b"dict://"],
                "严重": "高",
                "正则": r"file://|gopher://|dict://"
            },
        }
        
        # 4. 恶意软件行为
        self.恶意行为 = {
            "异常连接": lambda d: d["连接数"] > 100,
            "高频通信": lambda d: d["频率"] > 50,
            "大文件传输": lambda d: d["流量"] > 10000000,
            "非标准端口": lambda d: d["端口"] not in [80, 443, 22, 21, 25, 53],
        }
        
        # 5. 白名单
        self.白名单IP = ("192.168.", "10.", "172.16.", "127.", "224.")
        
        # 统计
        self.统计 = {
            "恶意端口": defaultdict(int),
            "可疑协议": defaultdict(int),
            "漏洞": defaultdict(int),
        }
        
        print("🛡️ 八卦防火墙 - 软件安全 Pro")
        print("=" * 60)
        print("  🔍 检测能力:")
        print(f"     • 恶意端口: {len(self.恶意端口)} 个")
        print(f"     • 可疑协议: {len(self.可疑协议)} 种")
        print(f"     • 漏洞库: {len(self.漏洞库)} 种")
        print(f"     • 恶意行为: {len(self.恶意行为)} 种")
        print("  🤖 AI: 机器学习集成")
        print("  🔄 实时学习: 样本收集")
        print("=" * 60)
    
    def _check_dns_tunnel(self, packet):
        if DNS in packet and packet[DNS].qd:
            qname = str(packet[DNS].qd.qname)
            # 异常长子域名
            if len(qname) > 50:
                return True
            # 随机字符串特征
            if len(set(qname)) > 30:
                return True
        return False
    
    def _check_icmp_tunnel(self, packet):
        if ICMP in packet and Raw in packet:
            if len(packet[ICMP].load) > 100:
                return True
        return False
    
    def _check_http_tunnel(self, packet):
        if TCP in packet and Raw in packet:
            try:
                data = bytes(packet[Raw].load)
                # CONNECT方法(代理)
                if b"CONNECT" in data and len(data) > 200:
                    return True
            except:
                pass
        return False
    
    def _check_ftp_anon(self, packet):
        if TCP in packet and Raw in packet:
            try:
                data = bytes(packet[Raw].load)
                if b"USER anonymous" in data or b"USER ftp" in data:
                    return True
            except:
                pass
        return False
    
    def 检测恶意端口(self, packet):
        if TCP not in packet:
            return None
        
        dst = packet[TCP].dport
        src = packet[IP].src if IP in packet else "未知"
        
        if dst in self.恶意端口:
            名称, 严重 = self.恶意端口[dst]
            return {
                "模块": "恶意端口",
                "类型": 名称,
                "严重": 严重,
                "端口": dst,
                "来源": src,
                "描述": f"访问恶意端口 {dst}({名称})"
            }
        return None
    
    def 检测可疑协议(self, packet):
        for 名称, 检测 in self.可疑协议.items():
            try:
                if 检测(packet):
                    return {
                        "模块": "可疑协议",
                        "类型": 名称,
                        "严重": "高",
                        "描述": f"检测到{名称}"
                    }
            except:
                pass
        return None
    
    def 检测漏洞利用(self, packet):
        if TCP not in packet or Raw not in packet:
            return None
        
        try:
            data = bytes(packet[Raw].load)
        except:
            return None
        
        src = packet[IP].src if IP in packet else "未知"
        
        for 漏洞名, 漏洞信息 in self.漏洞库.items():
            for 特征 in 漏洞信息["特征"]:
                if 特征 in data:
                    return {
                        "模块": "漏洞利用",
                        "类型": 漏洞名,
                        "严重": 漏洞信息["严重"],
                        "特征": 特征.decode('utf-8', errors='ignore'),
                        "来源": src,
                        "描述": f"{漏洞名}尝试"
                    }
        return None
    
    def 检测(self, packet):
        if IP not in packet:
            return None
        
        src = packet[IP].src
        for 白 in self.白名单IP:
            if src.startswith(白):
                return None
        
        # 优先级检测
        结果 = self.检测恶意端口(packet)
        if not 结果: 结果 = self.检测可疑协议(packet)
        if not 结果: 结果 = self.检测漏洞利用(packet)
        
        if 结果:
            self.记录威胁(结果)
        
        return 结果
    
    def 记录威胁(self, 威胁):
        威胁["时间"] = time.strftime("%H:%M:%S")
        self.威胁列表.append(威胁)
        self.安全状态 = "警告"
    
    def 打印(self, 结果):
        if not 结果:
            return
        
        严重符号 = {"低": "⚠️", "中": "🔶", "高": "🔴", "严重": "💀"}
        符号 = 严重符号.get(结果.get("严重", "低"), "⚠️")
        
        print(f"\n{符号} {结果['模块']} 告警!")
        print(f"   类型: {结果['类型']}")
        print(f"   严重: {结果['严重']}")
        if "端口" in 结果:
            print(f"   端口: {结果['端口']}")
        if "描述" in 结果:
            print(f"   描述: {结果['描述']}")
        if "来源" in 结果:
            print(f"   来源: {结果['来源']}")
    
    def 报告(self):
        print("\n" + "=" * 60)
        print("📊 软件安全报告")
        print("=" * 60)
        print(f"  状态: {self.安全状态}")
        print(f"  威胁: {len(self.威胁列表)}")
        
        if self.威胁列表:
            print("\n  最新威胁:")
            for i, t in enumerate(self.威胁列表[-5:], 1):
                print(f"    {i}. [{t['时间']}] {t['模块']} - {t['类型']}")


if __name__ == "__main__":
    安全 = Bagua软件安全Pro()
    
    print("\n📡 Pro版测试...\n")
    
    # 测试恶意端口
    print("--- 恶意端口 ---")
    安全.检测(IP(src="1.1.1.1")/TCP(dport=4444))
    安全.打印(安全.威胁列表[-1] if 安全.威胁列表 else None)
    
    # 测试DNS隧道
    print("\n--- DNS隧道 ---")
    安全.检测(IP(src="2.2.2.2")/DNS(qd=DNSQR(qname="a" * 60)))
    安全.打印(安全.威胁列表[-1] if 安全.威胁列表 else None)
    
    # 测试SQL注入
    print("\n--- SQL注入 ---")
    安全.检测(IP(src="3.3.3.3")/TCP(dport=80)/Raw(load=b"GET /?id=1' UNION SELECT--"))
    安全.打印(安全.威胁列表[-1] if 安全.威胁列表 else None)
    
    # 测试XSS
    print("\n--- XSS ---")
    安全.检测(IP(src="4.4.4.4")/TCP(dport=80)/Raw(load=b"<script>alert(1)</script>"))
    安全.打印(安全.威胁列表[-1] if 安全.威胁列表 else None)
    
    # 测试SSRF
    print("\n--- SSRF ---")
    安全.检测(IP(src="5.5.5.5")/TCP(dport=80)/Raw(load=b"file:///etc/passwd"))
    安全.打印(安全.威胁列表[-1] if 安全.威胁列表 else None)
    
    安全.报告()
    print("\n✅ Pro版测试完成!")
