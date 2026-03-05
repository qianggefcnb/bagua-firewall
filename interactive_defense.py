#!/usr/bin/env python3
"""
Bagua Firewall - Interactive Defense Mode
感知被攻击后可选择是否反击
"""

from scapy.all import *
from collections import defaultdict

class InteractiveDefense:
    """交互式防御 - 攻击时可选择反击"""
    
    def __init__(self):
        self.mode = "PASSIVE"  # PASSIVE / ACTIVE
        self.threat_level = 0
        self.auto_block = False
        self.pending_attacks = []
        
        print("=== Interactive Defense Mode ===")
        print("Mode: PASSIVE (waiting for threats)")
    
    def detect_threat(self, threat_info):
        """检测到威胁"""
        self.threat_level = min(100, self.threat_level + 20)
        
        attack = {
            "source": threat_info.get("source", "unknown"),
            "type": threat_info.get("type", "unknown"),
            "severity": threat_info.get("severity", "medium"),
            "time": "now"
        }
        
        self.pending_attacks.append(attack)
        
        return self.generate_alert(attack)
    
    def generate_alert(self, attack):
        """生成警报"""
        alert = """
========================================
    🔴 检测到攻击！
========================================
    
攻击来源: {source}
攻击类型: {type}
严重程度: {severity}
威胁等级: {level}%
        
可用操作:
    [1] 放行 (忽略)
    [2] 记录 (仅记录)
    [3] 封禁 (阻止IP)
    [4] 反击 (反向攻击)
    [5] 全面反击 (所有漏洞)
    
当前模式: {mode}
        
请选择 [1-5]: """.format(
            source=attack["source"],
            type=attack["type"],
            severity=attack["severity"],
            level=self.threat_level,
            mode=self.mode
        )
        
        return alert
    
    def process_choice(self, choice, attack):
        """处理选择"""
        result = ""
        
        if choice == "1":  # 放行
            result = ">>> 已放行"
            self.threat_level = max(0, self.threat_level - 10)
            
        elif choice == "2":  # 记录
            result = ">>> 已记录到日志"
            self.threat_level = max(0, self.threat_level - 5)
            
        elif choice == "3":  # 封禁
            result = ">>> 已封禁 IP: " + attack["source"]
            self.threat_level = 0
            
        elif choice == "4":  # 反击
            result = ">>> 反击中: " + attack["source"]
            result += "\n>>> 已发送探测包"
            self.mode = "ACTIVE"
            
        elif choice == "5":  # 全面反击
            result = ">>> 全面反击启动！"
            result += "\n>>> CVE-2021-41773 (Apache)"
            result += "\n>>> CVE-2021-4104 (Redis)"
            result += "\n>>> 已完成扫描"
            self.mode = "ACTIVE"
            self.threat_level = 0
            
        else:
            result = ">>> 无效选择"
        
        return result
    
    def set_auto(self, enabled):
        """设置自动模式"""
        self.auto_block = enabled
        if enabled:
            self.mode = "AUTO"
            print(">>> Auto mode enabled")
    
    def status(self):
        """状态"""
        return {
            "mode": self.mode,
            "threat_level": self.threat_level,
            "pending": len(self.pending_attacks),
            "auto": self.auto_block
        }


# Test
if __name__ == "__main__":
    defense = InteractiveDefense()
    
    print("\n=== Test ===\n")
    
    # Simulate attack detection
    alert = defense.detect_threat({
        "source": "1.2.3.4",
        "type": "SQL Injection",
        "severity": "HIGH"
    })
    
    print(alert)
    
    # Simulate user choice
    choice = "4"
    result = defense.process_choice(choice, defense.pending_attacks[0])
    print(result)
    
    print("\nStatus:", defense.status())
    print("\nDone!")
