# 🧱 八卦防火墙

基于阴阳八卦理论的智能防火墙系统

## 功能

| 模块 | 说明 |
|------|------|
| AI感知 | IsolationForest + RandomForest + MLP |
| 漏洞扫描 | SQL注入、XSS、命令注入、目录扫描 |
| 智能合约 | Reentrancy、Flash Loan等10种漏洞 |
| 反向扫描 | 以攻代守，扫描攻击者漏洞 |
| 阴阳转换 | 动态防御模式切换 |
| 交互防御 | 可选择是否反击 |

## 文件结构

```
bagua-firewall/
├── bagua_final_vuln.py     # 集成版
├── interactive_defense.py  # 交互防御
├── attack_scanner.py       # 反向漏洞扫描
├── perception_vuln.py      # 漏洞扫描
├── solidity_vulns.py      # 智能合约漏洞
├── yin_yang_mode.py       # 阴阳转换
└── README.md
```

## 使用

```bash
# 运行
python3 bagua_final_vuln.py

# 交互模式
python3 interactive_defense.py
```

## 阴阳转换

```
攻击强度 ≥70: 阴 → 阳 (被动 → 主动)
攻击强度 ≤20: 阳 → 阴 (主动 → 被动)
```

## 漏洞库

**Web漏洞**: SQL注入、XSS、命令注入、目录遍历、文件上传

**智能合约**: Reentrancy、Integer Overflow、Flash Loan、Access Control

**反击漏洞**: Apache、Nginx、Redis、Router等

## 更新日志

- 2026-03-05: 添加交互式防御，可选择是否反击
- 2026-03-05: 添加反向漏洞扫描
- 2026-03-05: 添加智能合约漏洞库

## GitHub

https://github.com/qianggefcnb/bagua-firewall
