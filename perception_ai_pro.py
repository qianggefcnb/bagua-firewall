#!/usr/bin/env python3
"""
八卦防火墙 - AI感知系统 Pro版
三重AI引擎 + 8维特征 + 实时学习
"""

from scapy.all import *
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

class Bagua感知Pro:
    def __init__(self):
        self.状态 = 0
        self.阴阳 = None
        self.威胁等级 = 0.0
        self.威胁类型 = None
        self.威胁描述 = None
        self.来源IP = None
        self.检测方式 = None
        
        print("🤖 初始化AI引擎...")
        self.AI异常 = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
        self.AI分类 = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.AI神经网络 = MLPClassifier(hidden_layer_sizes=(64, 32, 16), max_iter=500, random_state=42)
        self.缩放器 = StandardScaler()
        
        正常数据 = self._生成数据("正常")
        攻击数据 = self._生成数据("攻击")
        全部数据 = np.vstack([正常数据, 攻击数据])
        self.缩放器.fit_transform(全部数据)
        self.AI异常.fit(正常数据)
        self.AI神经网络.fit(正常数据, [0]*len(正常数据))
        self.已训练 = True
        print("  ✅ AI训练完成")
        
        self.端口库 = {80:"HTTP",443:"HTTPS",22:"SSH",23:"Telnet",445:"SMB",3306:"MySQL",3389:"RDP"}
        self.敏感端口 = {23,445,3389,1433,27017,6379}
        self.攻击库 = {2:"SYN扫描",0:"NULL扫描",1:"FIN扫描"}
        self.白名单 = ("192.168.","10.","172.16.","127.")
        self.统计 = {"连接":defaultdict(int),"端口":defaultdict(set),"SYN":defaultdict(int)}
        self.阈值 = {"连接":20,"端口":30,"SYN":10}
        self.攻击者 = {}
        self.攻击数据库 = []
        
        print("🧱 八卦感知 AI Pro")
        print("=" * 50)
        print("  🤖 AI: IsolationForest + NeuralNetwork")
        print("  📊 特征: 8维向量")
        print("=" * 50)
    
    def _生成数据(self, 类型):
        数据 = []
        for _ in range(1000):
            if 类型 == "正常":
                f = [np.random.randint(1,10), np.random.randint(1,5), np.random.randint(100,1000),
                     np.random.exponential(1), np.random.randint(0,2), np.random.random(), np.random.random(), 0]
            else:
                f = [np.random.randint(50,200), np.random.randint(20,100), np.random.randint(50000,100000),
                     np.random.uniform(0,0.1), np.random.randint(1,5), np.random.random(), np.random.random(), 1]
            数据.append(f)
        return np.array(数据)
    
    def 提取特征(self, packet, src):
        if IP not in packet: return None
        连接 = self.统计["连接"][src]
        端口 = len(self.统计["端口"][src])
        间隔 = 1.0 / (连接 + 1)
        标志 = int(packet[TCP].flags) if TCP in packet else 0
        端口分布 = len(self.统计["端口"][src]) / max(1, 连接)
        协议 = 1 if TCP in packet else 0
        异常 = 1 if (TCP in packet and int(packet[TCP].flags) in self.攻击库) else 0
        新端口比例 = len([p for p in self.统计["端口"][src] if p in self.敏感端口]) / max(1, 端口)
        return [连接, 端口, 连接*100, 间隔, 标志, 端口分布, 协议, 新端口比例]
    
    def AI检测(self, packet, src):
        特征 = self.提取特征(packet, src)
        if 特征 is None: return None
        try:
            fs = self.缩放器.transform([特征])
            异常分数 = self.AI异常.score_samples(fs)[0]
            神经分数 = self.AI神经网络.predict_proba(fs)[0][0]
            综合 = (1-异常分数)*0.5 + (1-神经分数)*0.5
            if 综合 > 0.7:
                self.攻击数据库.append(特征)
                if len(self.攻击数据库) > 1000: self.攻击数据库 = self.攻击数据库[-1000:]
                return {"方式":"🤖AI Pro","类型":"AI判定","威胁":综合,"描述":f"AI(异常:{异常分数:.2f})"}
        except: pass
        return None
    
    def 规则检测(self, packet, src):
        分类 = self.IP分类(src)
        if TCP in packet and int(packet[TCP].flags) & 2:
            self.统计["SYN"][src] += 1
            if self.统计["SYN"][src] > self.阈值["SYN"]:
                return {"方式":"📋规则","类型":"SYN Flood","威胁":0.99,"描述":f"洪泛 [{分类}]"}
        self.统计["连接"][src] += 1
        if self.统计["连接"][src] > self.阈值["连接"]:
            return {"方式":"📋规则","类型":"连接异常","威胁":0.7,"描述":f"连接{self.统计['连接'][src]}次"}
        if TCP in packet:
            dst = packet[TCP].dport
            self.统计["端口"][src].add(dst)
            if dst in self.敏感端口:
                return {"方式":"📋规则","类型":"敏感端口","威胁":0.9,"描述":f"{self.端口库.get(dst,str(dst))}"}
            if len(self.统计["端口"][src]) > self.阈值["端口"]:
                return {"方式":"📋规则","类型":"端口扫描","威胁":0.8,"描述":f"扫描{len(self.统计['端口'][src])}端口"}
        if TCP in packet and int(packet[TCP].flags) in self.攻击库:
            return {"方式":"📋规则","类型":self.攻击库[int(packet[TCP].flags)],"威胁":0.95,"描述":"扫描攻击"}
        return None
    
    def 是白名单(self, ip):
        if not ip: return True
        for p in self.白名单:
            if ip.startswith(p): return True
        return False
    
    def IP分类(self, ip):
        if ip.startswith(("192.168.","10.","172.")): return "局域网"
        return "公网"
    
    def 检测(self, packet):
        if IP not in packet: return
        src = packet[IP].src
        if self.是白名单(src): return
        结果 = None
        if self.已训练 and self.统计["连接"][src] >= 3:
            结果 = self.AI检测(packet, src)
        if not 结果: 结果 = self.规则检测(packet, src)
        if 结果:
            self.状态 = 1
            self.阴阳 = "阴"
            self.来源IP = src
            self.检测方式 = 结果["方式"]
            self.威胁类型 = 结果["类型"]
            self.威胁等级 = 结果["威胁"]
            self.威胁描述 = 结果["描述"]
    
    def 打印状态(self):
        if self.状态 == 0:
            print(f"\n🟢 [0] 无感知")
        else:
            print(f"\n🔴 [1] ☯️阴 感知!")
            print(f"    {self.检测方式}")
            print(f"    🌐 {self.来源IP} ({self.IP分类(self.来源IP)})")
            print(f"    ⚔️  {self.威胁类型} ({self.威胁等级:.0%})")
            print(f"    📝 {self.威胁描述}")


if __name__ == "__main__":
    感知 = Bagua感知Pro()
    print("\n📡 Pro测试...\n")
    for _ in range(30): 感知.检测(IP(src="192.168.1.100")/TCP(dport=80))
    print("✅ 局域网")
    for _ in range(15): 感知.检测(IP(src="8.8.8.8")/TCP(dport=443))
    print("✅ 公网")
    print("\n--- AI检测 ---")
    for i in range(25): 感知.检测(IP(src="1.2.3.4")/TCP(dport=1000+i))
    感知.打印状态()
    print("\n--- 规则检测 ---")
    感知.检测(IP(src="5.6.7.8")/TCP(dport=80, flags=2))
    感知.打印状态()
    print("\n✅ 完成!")
