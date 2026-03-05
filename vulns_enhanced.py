#!/usr/bin/env python3
"""
Enhanced Vulnerability Database - Complete
Based on GitHub learning
"""

class VulnDB:
    def __init__(self):
        # Web vulnerabilities
        self.web = {
            "SQL_Injection": {"severity": "HIGH", "cve": "CWE-89"},
            "XSS": {"severity": "MEDIUM", "cve": "CWE-79"},
            "Command_Injection": {"severity": "HIGH", "cve": "CWE-78"},
            "Path_Traversal": {"severity": "MEDIUM", "cve": "CWE-22"},
            "File_Upload": {"severity": "HIGH", "cve": "CWE-434"},
        }
        
        # CVE
        self.cve = {
            "CVE-2022-23808": {"type": "CPU", "severity": "HIGH"},
            "CVE-2021-4104": {"type": "Redis", "severity": "CRITICAL"},
            "CVE-2021-41773": {"type": "Apache", "severity": "HIGH"},
            "CVE-2021-45046": {"type": "Log4j", "severity": "CRITICAL"},
            "CVE-2021-4045": {"type": "IoT", "severity": "HIGH"},
        }
        
        # Smart Contract
        self.smart_contract = {
            "Reentrancy": {"severity": "CRITICAL"},
            "Integer_Overflow": {"severity": "HIGH"},
            "Flash_Loan": {"severity": "CRITICAL"},
            "Access_Control": {"severity": "HIGH"},
        }
        
        # System
        self.system = {
            "Kernel_PrivEsc": {"severity": "CRITICAL"},
            "Windows_PrivEsc": {"severity": "CRITICAL"},
            "Router_Exploit": {"severity": "HIGH"},
        }
        
        # Database
        self.database = {
            "MySQL_XXE": {"severity": "MEDIUM"},
            "H2_XXE": {"severity": "HIGH"},
            "Redis_RCE": {"severity": "CRITICAL"},
        }
        
        # Security Tools - from GitHub learning
        self.tools = {
            # 渗透测试
            "PentestGPT": {"stars": 11909, "desc": "自动化渗透测试Agent"},
            "fsociety": {"stars": 11908, "desc": "渗透测试框架"},
            
            # 漏洞扫描
            "nuclei": {"stars": 27320, "desc": "快速漏洞扫描器"},
            
            # 子域名
            "subfinder": {"stars": 13170, "desc": "被动子域名枚举"},
            "reconftw": {"stars": 7281, "desc": "侦察工具"},
            
            # 安全审计
            "lynis": {"stars": 15352, "desc": "Linux/macOS安全审计"},
            
            # 红队
            "sherlock": {"stars": 73372, "desc": "社交媒体用户名搜索"},
            
            # 漏洞库
            "Kernelhub": {"stars": 3189, "desc": "内核漏洞库"},
            "w3af": {"stars": 4853, "desc": "Web审计框架"},
            "CVE_Database": {"desc": "漏洞数据库"},
        }
        
        print("VulnDB: " + str(len(self.web)+len(self.cve)+len(self.smart_contract)+len(self.system)+len(self.database)) + " vulns, " + str(len(self.tools)) + " tools")

if __name__ == "__main__":
    db = VulnDB()
