#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 (最终版)
0/1 感知 + 完整IP信息 + 攻击记录
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
        self.威胁描述 = None
        self.来源IP = None
        
        # 端口数据库
        self.端口库 = {
            # Web
            80: ("HTTP", "网页服务"), 443: ("HTTPS", "加密网页"),
            8080: ("HTTP代理", "Web代理"), 8443: ("HTTPS", "替代加密"),
            
            # 远程
            22: ("SSH", "远程Shell"), 23: ("Telnet", "明文远程"),
            3389: ("RDP", "远程桌面"), 5900: ("VNC", "图形远程"),
            
            # 数据库
            3306: ("MySQL", "数据库"), 5432: ("PostgreSQL", "数据库"),
            1433: ("MSSQL", "数据库"), 27017: ("MongoDB", "文档数据库"),
            6379: ("Redis", "缓存"), 9200: ("Elasticsearch", "搜索"),
            
            # 文件
            20: ("FTP数据", "文件传输"), 21: ("FTP控制", "文件传输"),
            445: ("SMB", "文件共享"), 69: ("TFTP", "简单传输"),
            
            # 邮件
            25: ("SMTP", "邮件发送"), 110: ("POP3", "邮件接收"),
            143: ("IMAP", "邮件协议"),
            
            # 系统
            53: ("DNS", "域名解析"), 123: ("NTP", "时间同步"),
            161: ("SNMP", "监控"), 389: ("LDAP", "目录服务"),
            
            # 服务
            5000: ("Flask", "Web框架"), 3000: ("Node.js", "运行环境"),
            8000: ("Django", "Web框架"), 9000: ("PHP-FPM", "PHP"),
            11211: ("Memcached", "缓存"),
            
            # 恶意
            4444: ("Metasploit", "攻击框架"), 5555: ("ADB", "安卓调试"),
            6667: ("IRC", "后门通道"), 31337: ("BackOrifice", "后门"),
        }
        
        self.敏感端口 = {23, 445, 3389, 1433, 27017, 6379, 9200, 11211, 4444, 5555}
        
        # 攻击手段
        self.攻击库 = {
            0x02: ("SYN扫描", "只发SYN包试探", "探测开放端口"),
            0x00: ("NULL扫描", "无标志位", "绕过防火墙"),
            0x01: ("FIN扫描", "只发FIN包", "探测端口"),
            0x29: ("Xmas扫描", "FIN/PSH/URG", "探测状态"),
        }
        
        # 白名单
        self.白名单 = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", 
                      "172.19.", "172.2", "127.", "224.", "255.", "0.", "169.254.")
        
        # 统计
        self.统计 = {"连接": defaultdict(int), "端口": defaultdict(set), "SYN": [], "攻击": []}
        self.阈值 = {"连接": 20, "端口": 30, "SYN": 10}
        
        # 攻击者记录
        self.攻击者 = {}
        
        print("🧱 八卦感知系统")
        print("=" * 60)
        print(f"  端口库: {len(self.端口库)} 个")
        print(f"  攻击库: {len(self.攻击库)} 种")
        print(f"  敏感端口: {len(self.敏感端口)} 个")
        print("=" * 60)
        print("  状态: 0=无感知, 1=感知到威胁")
        print("  阴阳: 阴=被动(被打), 阳=主动(发现敌人)")
        print("=" * 60)
    
    def 端口信息(self, port):
        """获取端口详细信息"""
        if port in self.端口库:
            return f"{port}({self.端口库[port][0]}-{self.端口库[port][1]})"
        return f"{port}(未知)"
    
    def 是白名单(self, ip):
        if not ip:
            return True
        for 前缀 in self.白名单:
            if ip.startswith(前缀):
                return True
        return False
    
    def IP分类(self, ip):
        """IP分类"""
        if ip.startswith("192.168."):
            return "局域网", "私有地址"
        elif ip.startswith("10."):
            return "局域网", "私有地址"
        elif ip.startswith("172."):
            return "局域网", "私有地址"
        elif ip.startswith("127."):
            return "本地", "回环地址"
        elif ip.startswith("224."):
            return "组播", "多播地址"
        elif ip.startswith("169.254."):
            return "链路本地", "自动分配"
        else:
            return "公网", "外部地址"
    
    def 记录攻击者(self, ip, 类型, 等级, 描述):
        """记录攻击者"""
        if ip not in self.攻击者:
            分类, 说明 = self.IP分类(ip)
            self.攻击者[ip] = {
                "ip": ip, "类型": 分类, "说明": 说明,
                "首次": time.strftime("%H:%M:%S"),
                "次数": 0, "手段": [], "最大威胁": 0
            }
        
        a = self.攻击者[ip]
        a["次数"] += 1
        a["最大威胁"] = max(a["最大威胁"], 等级)
        if 类型 not in a["手段"]:
            a["手段"].append(类型)
    
    def 检测(self, packet):
        """检测威胁"""
        if IP not in packet:
            return
        
        src = packet[IP].src
        if self.是白名单(src):
            return
        
        分类, _ = self.IP分类(src)
        
        # 坤卦: 连接数
        self.统计["连接"][src] += 1
        if self.统计["连接"][src] > self.阈值["连接"]:
            self._感知(阴=True, ip=src, 类型="连接数异常", 
                      等级=0.7, 描述=f"连接{self.统计['连接'][src]}次 [{分类}]")
            return
        
        # 坎卦: 端口扫描
        if TCP in packet:
            dst = packet[TCP].dport
            self.统计["端口"][src].add(dst)
            
            # 敏感端口
            if dst in self.敏感端口:
                self._感知(阴=True, ip=src, 类型="敏感端口", 
                          等级=0.9, 描述=f"访问{self.端口信息(dst)} [{分类}]")
                return
            
            # 端口扫描
            if len(self.统计["端口"][src]) > self.阈值["端口"]:
                self._感知(阴=True, ip=src, 类型="端口扫描", 
                          等级=0.8, 描述=f"扫描{len(self.统计['端口'][src])}个端口 [{分类}]")
                return
        
        # 震卦: 攻击特征
        if TCP in packet:
            flags = packet[TCP].flags
            if flags in self.攻击库:
                手段, 描述, 风险 = self.攻击库[flags]
                dst = packet[TCP].dport
                self._感知(阴=True, ip=src, 类型=手段, 
                          等级=0.95, 描述=f"{手段}→{self.端口信息(dst)} [{分类}]")
                return
            
            # SYN Flood
            if flags & 0x02:
                self.统计["SYN"].append(src)
                if len(self.统计["SYN"]) > self.阈值["SYN"]:
                    self._感知(阴=True, ip=src, 类型="SYN Flood", 
                              等级=0.99, 描述=f"大量SYN包 [{分类}]")
                    return
    
    def _感知(self, 阴=False, 阳=False, ip=None, 类型=None, 等级=0.5, 描述=None):
        self.状态 = 1
        self.阴阳 = "阴" if 阴 else "阳"
        self.来源IP = ip
        self.威胁类型 = 类型
        self.威胁等级 = 等级
        self.威胁描述 = 描述
        self.记录攻击者(ip, 类型, 等级, 描述)
    
    def 状态查询(self):
        """查询当前状态"""
        return {
            "状态": self.状态,
            "阴阳": self.阴阳,
            "威胁等级": self.威胁等级,
            "威胁类型": self.威胁类型,
            "描述": self.威胁描述,
            "IP": self.来源IP,
            "IP类型": self.IP分类(self.来源IP)[0] if self.来源IP else None
        }
    
    def 打印状态(self):
        """打印当前状态"""
        if self.状态 == 0:
            print(f"\n🟢 [0] 无感知 - 系统平静")
        else:
            分类, _ = self.IP分类(self.来源IP)
            阴阳 = "☯️阴(被动)" if self.阴阳 == "阴" else "⚡阳(主动)"
            print(f"\n🔴 [1] {阴阳} 感知到威胁!")
            print(f"    🌐 来源: {self.来源IP} ({分类})")
            print(f"    ⚔️  威胁: {self.威胁类型} ({self.威胁等级:.0%})")
            print(f"    📝 描述: {self.威胁描述}")
    
    def 攻击列表(self):
        """攻击者列表"""
        print("\n" + "=" * 60)
        if not self.攻击者:
            print("👥 无攻击记录")
            return
        
        for ip, a in sorted(self.攻击者.items(), key=lambda x: x[1]["最大威胁"], reverse=True):
            print(f"\n  🌐 {ip} ({a['类型']})")
            print(f"     首次: {a['首次']} | 次数: {a['次数']} | 威胁: {a['最大威胁']:.0%}")
            print(f"     手段: {', '.join(a['手段'])}")
        print()


if __name__ == "__main__":
    感知 = Bagua感知()
    
    # 测试
    print("\n📡 测试开始...\n")
    
    # 1. 局域网
    for _ in range(25):
        感知.检测(IP(src="192.168.1.100")/TCP(dport=80))
    print("✅ 局域网流量: 无感知")
    
    # 2. 正常公网
    for _ in range(5):
        感知.检测(IP(src="8.8.8.8")/TCP(dport=53))
    print("✅ 正常访问: 无感知")
    
    # 3. SYN扫描
    感知.检测(IP(src="1.2.3.4")/TCP(dport=80, flags=0x02))
    感知.打印状态()
    
    # 4. 敏感端口
    感知.检测(IP(src="5.6.7.8")/TCP(dport=445))
    感知.打印状态()
    
    # 5. 端口扫描
    for port in [22, 80, 443, 445, 3306, 3389]:
        感知.检测(IP(src="9.8.7.6")/TCP(dport=port))
    感知.打印状态()
    
    # 攻击列表
    感知.攻击列表()
    
    print("✅ 感知系统测试完成!")
