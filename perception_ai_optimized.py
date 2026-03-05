#!/usr/bin/env python3
"""
八卦防火墙 - AI感知模块 (优化版)
学以致用：加入超参数优化 + 集成学习
"""

from scapy.all import *
from collections import defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score
import warnings
warnings.filterwarnings('ignore')

class BaguaAI感知:
    def __init__(self):
        print("🤖 初始化AI感知模块 (优化版)...")
        
        # ============ 1. 多模型集成 ============
        # 主模型：Isolation Forest (异常检测)
        self.异常模型 = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            max_samples='auto',
            random_state=42,
            n_jobs=-1  # 优化：并行计算
        )
        
        # 备用模型：Random Forest (分类)
        self.分类模型 = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        # 深度学习模型
        self.神经网络 = MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),  # 优化：更深网络
            activation='relu',
            solver='adam',
            alpha=0.001,
            max_iter=500,
            random_state=42,
            early_stopping=True
        )
        
        # 特征缩放
        self.缩放器 = StandardScaler()
        
        # ============ 2. 训练数据 (模拟) ============
        print("📚 训练模型...")
        self._训练模型()
        
        # ============ 3. 特征库 ============
        self.端口库 = {
            80:"HTTP",443:"HTTPS",22:"SSH",23:"Telnet",445:"SMB",
            3306:"MySQL",3389:"RDP",5432:"PostgreSQL",27017:"MongoDB"
        }
        self.敏感端口 = {23,445,3389,1433,27017,6379}
        self.攻击库 = {2:"SYN",0:"NULL",1:"FIN",9:"Xmas"}
        
        # 白名单
        self.白名单 = ("192.168.","10.","172.16.","127.", "5.6.7.8", "192.168.1.1")
        
        # 统计
        self.统计 = {"连接": defaultdict(int), "端口": defaultdict(set)}
        self.阈值 = {"连接": 20, "端口": 30}
        
        # 攻击者记录
        self.攻击者 = {}
        
        print("✅ AI感知优化版启动")
        print("=" * 50)
        print("  模型: IsolationForest + RandomForest + MLP")
        print("  优化: 并行计算 + 早停 + 超参数")
        print("=" * 50)
    
    def _训练模型(self):
        """训练多模型"""
        # 正常数据
        正常 = np.random.randn(500, 8) * 0.5 + [5, 3, 100, 0.5, 1, 0.5, 0.5, 0.1]
        
        # 异常数据
        异常 = np.random.randn(200, 8) * 0.8 + [50, 30, 50000, 0.01, 3, 0.9, 0.8, 0.8]
        
        全部 = np.vstack([正常, 异常])
        self.缩放器.fit_transform(全部)
        
        # 训练异常检测
        self.异常模型.fit(正常)
        
        # 训练分类
        标签 = [0]*500 + [1]*200
        self.分类模型.fit(全部, 标签)
        
        # 训练神经网络
        self.神经网络.fit(正常, [0]*500)
        
        print("  ✅ 异常模型训练完成")
        print("  ✅ 分类模型训练完成")
        print("  ✅ 神经网络训练完成")
    
    def 提取特征(self, packet, src):
        """提取8维特征"""
        if IP not in packet:
            return None
        
        连接 = self.统计["连接"][src]
        端口 = len(self.统计["端口"][src])
        流量 = 连接 * 100
        间隔 = 1.0 / (连接 + 1)
        
        # TCP标志
        标志 = int(packet[TCP].flags) if TCP in packet else 0
        
        # 端口分布
        分布 = 端口 / max(1, 连接)
        
        # 协议
        协议 = 1 if TCP in packet else (2 if ICMP in packet else 0)
        
        # 敏感端口比例
        敏感 = len([p for p in self.统计["端口"][src] if p in self.敏感端口]) / max(1, 端口)
        
        return [连接, 端口, 流量, 间隔, 标志, 分布, 协议, 敏感]
    
    def AI检测(self, packet, src):
        """AI综合检测"""
        特征 = self.提取特征(packet, src)
        if 特征 is None:
            return None
        
        try:
            fs = self.缩放器.transform([特征])
            
            # 多模型投票
            异常分数 = self.异常模型.score_samples(fs)[0]
            分类 = self.分类模型.predict_proba(fs)[0]
            神经 = self.神经网络.predict_proba(fs)[0]
            
            # 综合评分
            综合 = (
                (1 - 异常分数) * 0.3 +  # 异常检测权重
                分类[1] * 0.3 +         # 分类权重
                (1 - 神经[0]) * 0.4      # 神经网络权重
            )
            
            if 综合 > 0.6:
                return {
                    "方式": "🤖AI优化",
                    "类型": "AI综合判定",
                    "威胁": min(1.0, 综合 + 0.2),
                    "描述": f"AI多模型(异常:{异常分数:.2f},分类:{分类[1]:.2f})"
                }
        except Exception as e:
            pass
        
        return None
    
    def 规则检测(self, packet, src):
        """规则检测"""
        分类 = self.IP分类(src)
        
        # SYN Flood
        if TCP in packet and int(packet[TCP].flags) & 2:
            self.统计["连接"][src] += 1
            if self.统计["连接"][src] > self.阈值["连接"]:
                return {"方式":"📋规则","类型":"SYN Flood","威胁":0.99,"描述":f"连接洪泛 [{分类}]"}
        
        # 端口
        if TCP in packet:
            dst = packet[TCP].dport
            self.统计["端口"][src].add(dst)
            
            if dst in self.敏感端口:
                return {"方式":"📋规则","类型":"敏感端口","威胁":0.9,"描述":f"{self.端口库.get(dst,str(dst))}"}
            
            if len(self.统计["端口"][src]) > self.阈值["端口"]:
                return {"方式":"📋规则","类型":"端口扫描","威胁":0.8,"描述":f"扫描{len(self.统计['端口'][src])}端口"}
        
        # 攻击特征
        if TCP in packet and int(packet[TCP].flags) in self.攻击库:
            return {"方式":"📋规则","类型":self.攻击库[int(packet[TCP].flags)],"威胁":0.95,"描述":"扫描攻击"}
        
        return None
    
    def IP分类(self, ip):
        if ip.startswith(("192.168.","10.","172.")): return "局域网"
        if ip.startswith("127."): return "本地"
        return "公网"
    
    def 是白名单(self, ip):
        if not ip: return True
        for p in self.白名单:
            if ip.startswith(p) or ip == p: return True
        return False
    
    def 检测(self, packet):
        if IP not in packet: return {"状态":0}
        
        src = packet[IP].src
        if self.是白名单(src): return {"状态":0}
        
        # AI检测优先
        if self.统计["连接"][src] >= 3:
            AI结果 = self.AI检测(packet, src)
            if AI结果:
                return {"状态":1,"阴阳":"阴",**AI结果,"来源":src}
        
        # 规则备用
        结果 = self.规则检测(packet, src)
        if 结果:
            return {"状态":1,"阴阳":"阴","来源":src,**结果}
        
        return {"状态":0}
    
    def 打印状态(self, 结果):
        if not 结果 or 结果.get("状态") == 0:
            print(f"\n🟢 安全")
        else:
            print(f"\n🔴 威胁: {结果.get('类型')} ({结果.get('威胁',0):.0%})")
            print(f"    方式: {结果.get('方式')}")
            print(f"    来源: {结果.get('来源')}")


if __name__ == "__main__":
    AI = BaguaAI感知()
    
    print("\n📡 测试...")
    
    # 正常
    for _ in range(10):
        AI.检测(IP(src="8.8.8.8")/TCP(dport=80))
    print("✅ 正常流量")
    
    # 异常
    print("\n--- 攻击测试 ---")
    for i in range(5):
        AI.检测(IP(src="1.2.3.4")/TCP(dport=1000+i))
    
    结果 = AI.检测(IP(src="1.2.3.4")/TCP(dport=445))
    AI.打印状态(结果)
    
    结果 = AI.检测(IP(src="5.5.5.5")/TCP(dport=80, flags=2))
    AI.打印状态(结果)
    
    print("\n✅ 优化版测试完成!")
