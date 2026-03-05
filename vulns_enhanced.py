#!/usr/bin/env python3
"""
Enhanced Vulnerability Database - 增强漏洞库
Based on recent learning
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
        
        # CVE - from learning
        self.cve = {
            "CVE-2022-23808": {"type": "CPU漏洞", "severity": "HIGH"},
            "CVE-2021-4104": {"type": "Redis漏洞", "severity": "CRITICAL"},
            "CVE-2021-41773": {"type": "Apache", "severity": "HIGH"},
            "CVE-2021-23017": {"type": "Nginx", "severity": "MEDIUM"},
            "CVE-2021-28041": {"type": "OpenSSH", "severity": "MEDIUM"},
            "CVE-2021-45046": {"type": "Log4j", "severity": "CRITICAL"},
            "CVE-2021-4045": {"type": "IoT命令注入", "severity": "HIGH"},
        }
        
        # Smart Contract
        self.smart_contract = {
            "Reentrancy": {"severity": "CRITICAL", "cve": "CWE-841"},
            "Integer_Overflow": {"severity": "HIGH", "cve": "CWE-190"},
            "Flash_Loan": {"severity": "CRITICAL"},
            "Access_Control": {"severity": "HIGH", "cve": "CWE-284"},
        }
        
        # System/OS vulnerabilities - NEW
        self.system = {
            "Kernel_Privilege_Escalation": {
                "severity": "CRITICAL",
                "cve": "CVE-2021-xxx",
                "source": "Kernelhub"
            },
            "Windows_Local_Privilege": {
                "severity": "CRITICAL", 
                "cve": "CVE-2021-xxxx",
                "source": "SpoolFool"
            },
            "Router_Exploit": {
                "severity": "HIGH",
                "cve": "CVE-2021-4045",
                "source": "IoT"
            },
        }
        
        # Database vulnerabilities - NEW
        self.database = {
            "MySQL_XXE": {"severity": "MEDIUM", "cve": "JDBC-XXE"},
            "H2_Database_XXE": {"severity": "HIGH", "cve": "JDBC-SQLXML"},
            "Redis_RCE": {"severity": "CRITICAL", "cve": "CVE-2021-4104"},
        }
        
        # Tools from learning
        self.tools = {
            "Kernelhub": "Linux/Mac/Windows内核漏洞",
            "w3af": "Web应用攻击审计框架",
            "CVE_Database": "漏洞数据库",
            "SpoolFool": "Windows提权",
            "zenith": "内存损坏漏洞",
        }
        
        print("VulnDB: " + str(len(self.web) + len(self.cve) + len(self.smart_contract) + len(self.system) + len(self.database)) + " vulns loaded")
    
    def get_all(self):
        return {
            "web": self.web,
            "cve": self.cve,
            "smart_contract": self.smart_contract,
            "system": self.system,
            "database": self.database,
            "tools": self.tools
        }

if __name__ == "__main__":
    db = VulnDB()
    all_vulns = db.get_all()
    print("\n=== Vulnerability Database ===")
    for category, vulns in all_vulns.items():
        if isinstance(vulns, dict):
            print("\n" + category.upper() + ": " + str(len(vulns)))
