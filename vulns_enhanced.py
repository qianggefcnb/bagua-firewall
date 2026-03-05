#!/usr/bin/env python3
"""
Enhanced Vulnerability Database
Including CVE knowledge learned
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
        
        # CVE Database from learning
        self.cve = {
            "CVE-2022-23808": {"type": "CPU漏洞", "severity": "HIGH"},
            "CVE-2021-4104": {"type": "Redis漏洞", "severity": "CRITICAL"},
            "CVE-2021-41773": {"type": "Apache", "severity": "HIGH"},
            "CVE-2021-23017": {"type": "Nginx", "severity": "MEDIUM"},
            "CVE-2021-28041": {"type": "OpenSSH", "severity": "MEDIUM"},
            "CVE-2021-45046": {"type": "Log4j", "severity": "CRITICAL"},
        }
        
        # Smart Contract
        self.smart_contract = {
            "Reentrancy": {"severity": "CRITICAL", "cve": "CWE-841"},
            "Integer_Overflow": {"severity": "HIGH", "cve": "CWE-190"},
            "Flash_Loan": {"severity": "CRITICAL"},
            "Access_Control": {"severity": "HIGH", "cve": "CWE-284"},
        }
        
        # From CVE Database project
        self.cve_database = {
            "pyvfeed": "Python漏洞库",
            "vulnerability-data-archive": "漏洞数据存档",
            "advisory-database": "漏洞咨询库",
        }
        
        print("VulnDB: Loaded " + str(len(self.web)) + " web, " + str(len(self.cve)) + " CVE")
    
    def get_all(self):
        return {"web": self.web, "cve": self.cve, "smart_contract": self.smart_contract}

if __name__ == "__main__":
    db = VulnDB()
    print(db.get_all())
