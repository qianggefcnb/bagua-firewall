#!/usr/bin/env python3
"""
八卦防火墙 - 阴阳转换模块
根据攻击强度自动切换防御模式
"""

from collections import defaultdict
import time

class 阴阳转换:
    def __init__(self):
        # 模式: 阴(被动) / 阳(主动)
        self.当前模式 = "阴"
        
        # 攻击强度 (0-100)
        self.攻击强度 = 0
        
        # 转换阈值
        self.阈值 = {
            "阴→阳": 70,  # 攻击强度>70转为阳
            "阳→阴": 20,  # 攻击强度<20转回阴
        }
        
        # 统计
        self.统计 = {
            "攻击次数": 0,
            "转换次数": 0,
            "模式历史": []
        }
        
        print("🧱 阴阳转换模块启动")
        print(f"   初始模式: {self.当前模式}")
        print(f"   阴→阳阈值: {self.阈值['阴→阳']}")
        print(f"   阳→阴阈值: {self.阈值['阳→阴']}")
    
    def 检测攻击(self):
        """检测到攻击，攻击强度+10"""
        self.统计["攻击次数"] += 1
        self.攻击强度 = min(100, self.攻击强度 + 10)
        return self.检测转换()
    
    def 无攻击(self):
        """无攻击，攻击强度-5"""
        self.攻击强度 = max(0, self.攻击强度 - 5)
        return self.检测转换()
    
    def 检测转换(self):
        """检测是否需要转换"""
        旧模式 = self.当前模式
        
        # 阴→阳
        if self.当前模式 == "阴" and self.攻击强度 >= self.阈值["阴→阳"]:
            self.当前模式 = "阳"
        
        # 阳→阴
        elif self.当前模式 == "阳" and self.攻击强度 <= self.阈值["阳→阴"]:
            self.当前模式 = "阴"
        
        # 记录转换
        if 旧模式 != self.当前模式:
            self.统计["转换次数"] += 1
            self.统计["模式历史"].append({
                "时间": time.strftime("%H:%M:%S"),
                "从": 旧模式,
                "到": self.当前模式,
                "强度": self.攻击强度
            })
            return True, 旧模式, self.当前模式
        
        return False, 旧模式, self.当前模式
    
    def 获取响应(self):
        """根据当前模式获取响应策略"""
        if self.当前模式 == "阴":
            return {
                "模式": "阴(被动)",
                "策略": ["监控", "记录", "过滤"],
                "消耗": "低"
            }
        else:
            return {
                "模式": "阳(主动)",
                "策略": ["反击", "封禁", "诱捕"],
                "消耗": "高"
            }
    
    def 状态(self):
        return {
            "模式": self.当前模式,
            "攻击强度": self.攻击强度,
            "响应": self.获取响应()
        }


# 测试
if __name__ == "__main__":
    转换 = 阴阳转换()
    
    print("\n=== 模拟攻击场景 ===\n")
    
    # 模拟持续攻击
    print("1. 开始攻击...")
    for i in range(8):
        转换.检测攻击()
        状态 = 转换.状态()
        print(f"   攻击{i+1}: 强度={状态['攻击强度']}, 模式={状态['模式']}")
    
    print("\n2. 攻击停止...")
    for i in range(10):
        转换.无攻击()
        状态 = 转换.状态()
        print(f"   平静{状态['攻击强度']}: {状态['模式']}")
    
    print(f"\n统计: {转换.统计}")
