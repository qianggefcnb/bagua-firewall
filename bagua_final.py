#!/usr/bin/env python3
"""八卦防火墙 - 最终版"""
from scapy.all import *
from collections import defaultdict

class Bagua防火墙:
    def __init__(self):
        print("=" * 45)
        print("🧱 八卦防火墙 - 最终版")
        self.感知 = 感知模块()
        self.软件安全 = 软件安全模块()
        self.阴阳 = 阴阳转换模块()
        self.防御 = 防御模块()
        print("✅ 启动完成")
    
    def 检测(self, packet):
        if IP in packet and self.感知.是白名单(packet[IP].src):
            self.阴阳.无攻击()
            return {"状态": 0, "模式": self.阴阳.当前}
        
        结果 = self.感知.检测(packet)
        if not 结果 or 结果.get("状态") == 0:
            结果 = self.软件安全.检测(packet)
        
        if 结果 and 结果.get("状态") == 1:
            self.阴阳.检测攻击()
            结果["模式"] = self.阴阳.当前
            self.防御.响应(结果, self.阴阳.当前)
        else:
            self.阴阳.无攻击()
            结果 = {"状态": 0, "模式": self.阴阳.当前}
        return 结果


class 感知模块:
    def __init__(self):
        self.敏感 = {23,445,3389}
        self.白名单 = ("192.168.","10.","127.", "5.6.7.8","8.8.8.")
        self.统计 = defaultdict(int)
    
    def 是白名单(self, ip):
        if not ip: return True
        for p in self.白名单:
            if ip.startswith(p): return True
        return False
    
    def 检测(self, packet):
        if IP not in packet: return {"状态": 0}
        src = packet[IP].src
        if self.是白名单(src): return {"状态": 0}
        self.统计[src] += 1
        if TCP in packet:
            dst = packet[TCP].dport
            if dst in self.敏感:
                return {"状态":1,"模块":"感知","类型":f"敏感{dst}","威胁":0.9}
            if int(packet[TCP].flags)==2 and self.统计[src]>3:
                return {"状态":1,"模块":"感知","类型":"SYN扫描","威胁":0.95}
        return {"状态": 0}


class 软件安全模块:
    def __init__(self):
        self.恶意 = {4444:"Meta",5555:"ADB"}
        self.白名单 = ("192.168.","10.","127.", "5.6.7.8","8.8.8.")
    
    def 是白名单(self, ip):
        if not ip: return True
        for p in self.白名单:
            if ip.startswith(p): return True
        return False
    
    def 检测(self, packet):
        if IP not in packet: return {"状态": 0}
        src = packet[IP].src
        if self.是白名单(src): return {"状态": 0}
        if TCP in packet and packet[TCP].dport in self.恶意:
            return {"状态":1,"模块":"安全","类型":"恶意端口","威胁":0.9}
        return {"状态": 0}


class 阴阳转换模块:
    def __init__(self):
        self.当前 = "阴"
        self.强度 = 0
    
    def 检测攻击(self):
        self.强度 = min(100, self.强度 + 10)
        旧 = self.当前
        if self.当前=="阴" and self.强度>=70: self.当前="阳"
        elif self.当前=="阳" and self.强度<=20: self.当前="阴"
        if 旧!=self.当前: print(f"🔄 {旧}→{self.当前} 强度{self.强度}")
    
    def 无攻击(self):
        self.强度 = max(0, self.强度 - 5)


class 防御模块:
    def 响应(self, r, 模式):
        s={"阴":"监控","阳":"反击"}
        print(f"🔴 {r.get('模块')}-{r.get('类型')} | {模式} {s.get(模式)}")


if __name__ == "__main__":
    fw = Bagua防火墙()
    print("测试...\n正常:")
    for _ in range(10): fw.检测(IP(src="8.8.8.8")/TCP(dport=80))
    print(f"模式:{fw.阴阳.当前} 强度:{fw.阴阳.强度}\n攻击:")
    for _ in range(8): fw.检测(IP(src="1.2.3.4")/TCP(dport=445))
    print(f"模式:{fw.阴阳.当前} 强度:{fw.阴阳.强度}\n停止:")
    for _ in range(10): fw.检测(IP(src="8.8.8.8")/TCP(dport=80))
    print(f"模式:{fw.阴阳.当前} 强度:{fw.阴阳.强度}")
    print("✅完成")
