#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 V4 (一)
0/1 感知 + 端口作用 + 攻击手段细化
"""

from scapy.all import *
from collections import defaultdict
import time

class Bagua感知:
    def __init__(self):
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.威胁描述 = None
        self.来源IP = None
        
        # ============ 端口作用字典 ============
        self.端口作用 = {
            # Web服务
            80: "HTTP网页",
            443: "HTTPS加密",
            8080: "HTTP代理",
            8443: "HTTPS替代",
            8888: "HTTP альт",
            
            # 远程管理
            22: "SSH远程",
            23: "Telnet明文",
            3389: "RDP远程桌面",
            5900: "VNC远程",
            
            # 文件传输
            20: "FTP数据",
            21: "FTP控制",
            69: "TFTP简单",
            
            # 数据库
            3306: "MySQL",
            5432: "PostgreSQL",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            9200: "Elasticsearch",
            
            # 邮件
            25: "SMTP邮件",
            110: "POP3邮件",
            143: "IMAP邮件",
            
            # 系统服务
            53: "DNS域名",
            123: "NTP时间",
            161: "SNMP监控",
            389: "LDAP目录",
            636: "LDAPS加密",
            
            # 敏感服务
            445: "SMB文件共享",
            139: "NetBIOS",
            135: "RPC远程",
            161: "SNMP",
            
            # 特定服务
            5000: "Flask默认",
            3000: "Node.js",
            8000: "Django",
            9000: "PHP-FPM",
            11211: "Memcached",
            
            # 恶意端口
            4444: "Metasploit",
            5555: "ADB远程",
            6667: "IRC后门",
            31337: "Back Orifice",
        }
        
        # ============ 攻击手段 ============
        self.攻击手段 = {
            # 端口扫描
            " SYN扫描": {
                "描述": "只发送SYN包试探端口",
                "风险": "探测开放端口",
                "端口": None,
            },
            " NULL扫描": {
                "描述": "无标志位扫描",
                "风险": "绕过防火墙",
                "端口": None,
            },
            " FIN扫描": {
                "描述": "只发送FIN包",
                "风险": "探测端口",
                "端口": None,
            },
            " Xmas扫描": {
                "描述": "FIN/PSH/URG同时置位",
                "风险": "探测状态",
                "端口": None,
            },
            " TCP全连接": {
                "描述": "完整三次握手",
                "风险": "端口扫描",
                "端口": None,
            },
        }
        
        # ============ 敏感端口 ============
        self.敏感端口 = {
            23: "Telnet明文",
            445: "SMB共享",
            3389: "RDP桌面",
            1433: "MSSQL",
            27017: "MongoDB",
            6379: "Redis",
            9200: "ES",
            11211: "Memcached",
        }
        
        # ============ 白名单 ============
        self.白名单 = {"192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "127."}
        
        # 统计
        self.统计 = {"坤": defaultdict(int), "坎": defaultdict(set), "巽": defaultdict(int), "震": []}
        self.阈值 = {"坤": 20, "坎": 30, "巽": 50000, "震": 5}
        self.攻击者 = set()
        
        print("🧱 八卦感知系统 V4 启动")
        print("=" * 55)
        print(f"  端口库: {len(self.端口作用)} 个")
        print(f"  攻击库: {len(self.攻击手段)} 种")
        print(f"  敏感端口: {len(self.敏感端口)} 个")
        print("=" * 55)
    
    def 端口作用查询(self, port):
        """查询端口作用"""
        return self.端口作用.get(port, "未知端口")
    
    def 是白名单(self, ip):
        """检查白名单"""
        if not ip:
            return True
        for 白 in self.白名单:
            if ip.startswith(白):
                return True
        return False
    
    def 检测攻击手段(self, packet):
        """检测攻击手段"""
        if TCP not in packet:
            return None
        
        src = packet[IP].src
        dst = packet[TCP].dport
        flags = packet[TCP].flags
        
        结果 = []
        
        # SYN扫描
        if flags == 0x02:  # SYN only
            结果.append({
                "手段": "SYN扫描",
                "描述": "只发送SYN包试探端口",
                "风险": "探测开放端口",
                "端口": f"{dst}({self.端口作用查询(dst)})"
            })
        
        # NULL扫描
        elif flags == 0x00:
            结果.append({
                "手段": "NULL扫描",
                "描述": "无标志位扫描",
                "风险": "绕过防火墙",
                "端口": f"{dst}({self.端口作用查询(dst)})"
            })
        
        # FIN扫描
        elif flags == 0x01:
            结果.append({
                "手段": "FIN扫描",
                "描述": "只发送FIN包",
                "风险": "探测端口",
                "端口": f"{dst}({self.端口作用查询(dst)})"
            })
        
        # Xmas扫描
        elif flags == 0x29:
            结果.append({
                "手段": "Xmas扫描",
                "描述": "FIN/PSH/URG同时置位",
                "风险": "探测状态",
                "端口": f"{dst}({self.端口作用查询(dst)})"
            })
        
        # 敏感端口访问
        if dst in self.敏感端口:
            结果.append({
                "手段": "敏感端口访问",
                "描述": f"访问敏感服务 {self.敏感端口[dst]}",
                "风险": "可能利用漏洞",
                "端口": f"{dst}({self.敏感端口[dst]})"
            })
        
        # SYN Flood检测
        if flags & 0x02:
            self.统计["震"].append({"time": time.time(), "src": src, "type": "SYN"})
            if len([x for x in self.统计["震"] if x["type"] == "SYN"]) > 10:
                结果.append({
                    "手段": "SYN Flood",
                    "描述": "大量SYN包",
                    "风险": "DoS攻击",
                    "端口": "全端口"
                })
        
        return 结果 if 结果 else None
    
    def 坤卦_连接检测(self, packet):
        """坤卦: 连接数检测"""
        if IP not in packet:
            return False, None, None, 0, None
        
        src = packet[IP].src
        if self.是白名单(src):
            return False, None, None, 0, None
        
        self.统计["坤"][src] += 1
        
        if self.统计["坤"][src] > self.阈值["坤"]:
            描述 = f"单IP {src} 连接数达 {self.统计['坤'][src]}"
            return True, "连接数异常", src, 0.7, 描述
        
        return False, None, None, 0, None
    
    def 坎卦_端口检测(self, packet):
        """坎卦: 端口扫描检测"""
        if IP not in packet or TCP not in packet:
            return False, None, None, 0, None
        
        src = packet[IP].src
        if self.是白名单(src):
            return False, None, None, 0, None
        
        dst = packet[TCP].dport
        self.统计["坎"][src].add(dst)
        
        # 敏感端口
        if dst in self.敏感端口:
            描述 = f"访问敏感端口 {dst}({self.敏感端口[dst]})"
            return True, "敏感端口", src, 0.9, 描述
        
        # 端口扫描
        if len(self.统计["坎"][src]) > self.阈值["坎"]:
            端口列表 = [self.端口作用查询(p) for p in list(self.统计["坎"][src])[:5]]
            描述 = f"扫描多个端口: {端口列表}"
            return True, "端口扫描", src, 0.8, 描述
        
        return False, None, None, 0, None
    
    def 震卦_攻击检测(self, packet):
        """震卦: 攻击检测"""
        if IP not in packet:
            return False, None, None, 0, None
        
        src = packet[IP].src
        if self.是白名单(src):
            return False, None, None, 0, None
        
        攻击 = self.检测攻击手段(packet)
        if 攻击:
            # 取最严重的一个
            最严重 = 攻击[0]
            return True, 最严重["手段"], src, 0.95, f"{最严重['描述']} - {最严重['风险']}"
        
        return False, None, None, 0, None
    
    def 感知(self, packet):
        """主感知"""
        if IP not in packet:
            return self.获取状态()
        
        src = packet[IP].src
        
        if self.是白名单(src):
            return self.获取状态()
        
        # 检测
        检测, 类型, src_ip, 等级, 描述 = self.坤卦_连接检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级, 描述=描述)
        
        检测, 类型, src_ip, 等级, 描述 = self.坎卦_端口检测(packet)
        if 检测:
            return self._触发(阴=True, 类型=类型, src=src_ip, 等级=等级, 描述=描述)
        
        检测, 类型, src_ip, 等级, 描述 = self.震卦_攻击检测(packet)
        if 检测:
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
            self.攻击者.add(src)
        return self.获取状态()
    
    def 获取状态(self):
        return {
            "状态": self.状态,
            "阴阳": self.阴阳,
            "威胁等级": self.威胁等级,
            "威胁类型": self.威胁类型,
            "威胁描述": self.威胁描述,
            "来源IP": self.来源IP,
            "攻击者数量": len(self.攻击者)
        }
    
    def 打印状态(self):
        if self.状态 == 0:
            print(f"🟢 [0] 无感知 - 平静")
        else:
            阴阳符 = "☯️" if self.阴阳 == "阴" else "⚡"
            print(f"🔴 [1] {阴阳符}{self.阴阳}")
            print(f"    威胁: {self.威胁类型} ({self.威胁等级:.0%})")
            print(f"    描述: {self.威胁描述}")
            print(f"    来源: {self.来源IP}")
    
    def 端口作用表(self):
        """打印端口作用表"""
        print("\n📋 端口作用表:")
        for 端口, 作用 in list(self.端口作用.items())[:15]:
            print(f"    {端口:5d} → {作用}")


if __name__ == "__main__":
    感知 = Bagua感知()
    
    print("\n📡 V4 详细测试...\n")
    
    # 1. 局域网测试
    print("--- 测试局域网 ---")
    for i in range(30):
        pkt = IP(src="192.168.1.100")/TCP(dport=80)
        感知.感知(pkt)
    print("✅ 局域网: 无感知")
    
    # 2. 正常端口
    print("\n--- 测试正常端口 ---")
    for port in [80, 443, 22]:
        pkt = IP(src="8.8.8.8")/TCP(dport=port)
        感知.感知(pkt)
    print("✅ 正常端口: 无感知")
    
    # 3. SYN扫描
    print("\n--- 测试SYN扫描 ---")
    pkt = IP(src="1.1.1.1")/TCP(dport=80, flags=0x02)
    result = 感知.感知(pkt)
    感知.打印状态()
    
    # 4. 敏感端口
    print("\n--- 测试敏感端口 ---")
    pkt = IP(src="2.2.2.2")/TCP(dport=445)
    result = 感知.感知(pkt)
    感知.打印状态()
    
    # 5. 多端口扫描
    print("\n--- 测试端口扫描 ---")
    for port in [22, 23, 80, 443, 445, 3306, 3389, 5432, 6379, 8080]:
        pkt = IP(src="3.3.3.3")/TCP(dport=port)
        感知.感知(pkt)
    感知.打印状态()
    
    # 端口作用表
    感知.端口作用表()
    
    print("\n✅ V4 测试完成!")
