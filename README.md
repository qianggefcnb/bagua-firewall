# 八卦防火墙

基于阴阳八卦理论的智能防火墙系统

## 功能

- AI感知: IsolationForest + RandomForest + MLP
- 漏洞扫描: Web + CVE + 系统 + 数据库 + 智能合约
- 反向扫描: 以攻代守
- 阴阳转换: 动态防御

## 漏洞库 (22种)

### Web漏洞 (5)
- SQL注入 (CWE-89)
- XSS (CWE-79)
- 命令注入 (CWE-78)
- 目录遍历 (CWE-22)
- 文件上传 (CWE-434)

### CVE (7)
- CVE-2022-23808 (CPU) - HIGH
- CVE-2021-4104 (Redis) - CRITICAL
- CVE-2021-41773 (Apache) - HIGH
- CVE-2021-45046 (Log4j) - CRITICAL
- CVE-2021-4045 (IoT) - HIGH

### 系统漏洞 (3)
- Kernel提权 (Kernelhub)
- Windows提权 (SpoolFool)
- 路由器漏洞

### 数据库漏洞 (3)
- MySQL XXE
- H2 Database XXE
- Redis RCE

### 智能合约 (4)
- Reentrancy - CRITICAL
- Integer Overflow - HIGH
- Flash Loan - CRITICAL
- Access Control - HIGH

## 工具

- Kernelhub - 内核漏洞库
- w3af - Web审计框架
- CVE_Database - 漏洞数据库

## 模块

- bagua_final_vuln.py
- interactive_defense.py
- attack_scanner.py
- vulns_enhanced.py

## 更新

- 2026-03-05: 添加系统/数据库漏洞
