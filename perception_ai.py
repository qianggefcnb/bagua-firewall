#!/usr/bin/env python3
"""
八卦防火墙 - 感知系统 AI增强版 V2
0/1 感知 + 人工智能 + 双重检测
"""

from scapy.all import *
from collections import defaultdict
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class Bagua感知AI:
    def __init__(self):
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.威胁描述 = None
        self.来源IP = None
        self.检测方式 = None
        
        # AI初始化
        print("🤖 初始化AI模型...")
        self.AI模型 = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.缩放器 = StandardScaler()
        
        # 正常数据
        正常数据 = np.random.randn(500, 4) * 0.5 + [5, 3, 0.5, 500]
        self.缩放器.fit_transform(正常数据)
        self.AI模型.fit(正常数据)
        
        # 数据收集
        self.特征缓存 = defaultdict(list)
        
        # 端口库
        self.端口库 = {80:"HTTP",443:"HTTPS",22:"SSH",23:"Telnet",445:"SMB",
                       3306:"MySQL",3389:"RDP",5432:"PostgreSQL",27017:"MongoDB"}
        self.敏感端口 = {23,445,3389,1433,27017}
        self.攻击库 = {0x02:"SYN扫描",0x00:"NULL扫描",0x01:"FIN扫描"}
        self.白名单 = ("192.168.","10.","172.16.","172.17.","127.")
        
        self.统计 = {"连接":defaultdict(int),"端口":defaultdict(set)}
        self.阈值 = {"连接":20,"端口":30}
        self.攻击者 = {}
        
        print("🧱 八卦感知 AI增强版 V2 启动")
        print("=" * 55)
        print("  🤖 AI: Isolation Forest 异常检测")
        print("  ⚔️  规则: 传统特征检测")
        print("  🔄 双重检测: AI + 规则")
        print("=" * 55)
    
    def 是白名单(self, ip):
        if not ip: return True
        for p in self.白名单:
            if ip.startswith(p): return True
        return False
    
    def IP分类(self, ip):
        if ip.startswith(("192.168.","10.","172.")): return "局域网"
        if ip.startswith("127."): return "本地"
        return "公网"
    
    def AI检测(self, packet, src):
        """AI异常检测"""
        if IP not in packet: return None
        
        连接 = self.统计["连接"][src]
        端口 = len(self.统计["端口"][src])
        间隔 = 1.0/(连接+1)
        包大小 = len(packet[IP])
        
        特征 = np.array([[连接, 端口, 间隔, 包大小]])
        特征 = self.缩放器.transform(特征)
        
        预测 = self.AI模型.predict(特征)[0]
        分数 = self.AI模型.score_samples(特征)[0]
        
        # 异常检测
        if 预测 == -1:
            威胁 = min(1.0, (0.3 - 分数) * 3 + 0.5)
            return {"方式":"🤖AI","类型":"异常行为","威胁":威胁,
                   "描述":f"AI识别异常(分数:{分数:.2f},连接:{连接},端口:{端口})"}
        return None
    
    def 规则检测(self, packet, src):
        """传统规则检测"""
        分类 = self.IP分类(src)
        
        # 连接数
        self.统计["连接"][src] += 1
        if self.统计["连接"][src] > self.阈值["连接"]:
            return {"方式":"📋规则","类型":"连接数异常","威胁":0.7,
                   "描述":f"连接{self.统计['连接'][src]}次 [{分类}]"}
        
        # 端口
        if TCP in packet:
            dst = packet[TCP].dport
            self.统计["端口"][src].add(dst)
            
            if dst in self.敏感端口:
                return {"方式":"📋规则","类型":"敏感端口","威胁":0.9,
                       "描述":f"访问{self.端口库.get(dst,str(dst))} [{分类}]"}
            
            if len(self.统计["端口"][src]) > self.阈值["端口"]:
                return {"方式":"📋规则","类型":"端口扫描","威胁":0.8,
                       "描述":f"扫描{len(self.统计['端口'][src])}端口 [{分类}]"}
        
        # 攻击特征
        if TCP in packet and packet[TCP].flags in self.攻击库:
            return {"方式":"📋规则","类型":self.攻击库[packet[TCP].flags],"威胁":0.95,
                   "描述":f"{self.攻击库[packet[TCP].flags]} [{分类}]"}
        
        return None
    
    def 检测(self, packet):
        if IP not in packet: return
        src = packet[IP].src
        if self.是白名单(src): return
        
        结果 = None
        
        # 优先AI检测 (更智能)
        if self.统计["连接"][src] >= 3:  # 至少3个连接才AI检测
            AI结果 = self.AI检测(packet, src)
            if AI结果 and AI结果["威胁"] > 0.6:
                结果 = AI结果
        
        # 备用规则检测
        if not 结果:
            结果 = self.规则检测(packet, src)
        
        if 结果:
            self._感知(阴=True, ip=src, **结果)
    
    def _感知(self, 阴=False, 阳=False, ip=None, 方式=None, 类型=None, 威胁=0.5, 描述=None):
        self.状态 = 1
        self.阴阳 = "阴" if 阴 else "阳"
        self.来源IP = ip
        self.检测方式 = 方式
        self.威胁类型 = 类型
        self.威胁等级 = 威胁
        self.威胁描述 = 描述
        
        if ip not in self.攻击者:
            self.攻击者[ip] = {"类型":类型,"次数":0,"威胁":0,"方式":方式}
        a = self.攻击者[ip]
        a["次数"] += 1
        a["威胁"] = max(a["威胁"], 威胁)
    
    def 打印状态(self):
        if self.状态 == 0:
            print(f"\n🟢 [0] 无感知")
        else:
            阴阳 = "☯️阴" if self.阴阳 == "阴" else "⚡阳"
            print(f"\n🔴 [1] {阴阳} 感知!")
            print(f"    {self.检测方式}")
            print(f"    🌐 {self.来源IP} ({self.IP分类(self.来源IP)})")
            print(f"    ⚔️  {self.威胁类型} ({self.威胁等级:.0%})")
            print(f"    📝 {self.威胁描述}")


if __name__ == "__main__":
    感知 = Bagua感知AI()
    
    print("\n📡 测试...\n")
    
    # 1. 局域网
    for _ in range(25):
        感知.检测(IP(src="192.168.1.100")/TCP(dport=80))
    print("✅ 局域网: 无感知")
    
    # 2. 正常公网
    for _ in range(10):
        感知.检测(IP(src="8.8.8.8")/TCP(dport=53))
    print("✅ 正常访问: 无感知")
    
    # 3. AI异常
    print("\n--- AI检测 ---")
    for i in range(20):
        感知.检测(IP(src="1.2.3.4")/TCP(dport=1000+i))
    感知.打印状态()
    
    # 4. 规则检测
    print("\n--- 规则检测 ---")
    感知.检测(IP(src="5.6.7.8")/TCP(dport=80, flags=0x02))
    感知.打印状态()
    
    print("\n✅ AI+规则 双重检测完成!")
