# 八卦防火墙

基于阴阳八卦理论的智能防火墙系统

## 功能

- AI感知: IsolationForest + RandomForest + MLP
- 漏洞扫描: Web漏洞 + CVE + 智能合约
- 反向扫描: 以攻代守
- 阴阳转换: 动态防御

## 漏洞库

### Web漏洞
- SQL注入 (CWE-89)
- XSS (CWE-79)
- 命令注入 (CWE-78)
- 目录遍历 (CWE-22)
- 文件上传 (CWE-434)

### CVE
- CVE-2022-23808 (CPU)
- CVE-2021-4104 (Redis) - CRITICAL
- CVE-2021-41773 (Apache)
- CVE-2021-45046 (Log4j) - CRITICAL

### 智能合约
- Reentrancy (CWE-841)
- Integer Overflow (CWE-190)
- Flash Loan
- Access Control

## 模块

- bagua_final_vuln.py - 集成版
- interactive_defense.py - 交互防御
- attack_scanner.py - 反向扫描
- vulns_enhanced.py - 增强漏洞库

## 更新

- 2026-03-05: 添加CVE-2022-23808, Log4j等
- 2026-03-05: 添加交互式防御
