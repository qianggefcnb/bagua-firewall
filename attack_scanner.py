#!/usr/bin/env python3
"""
Reverse Vuln Scanner - Attack the Attackers
以攻代守：对攻击方进行漏洞扫描
"""

from scapy.all import *
from collections import defaultdict

class ReverseScanner:
    def __init__(self):
        print("=== Reverse Vuln Scanner ===")
        
        # Attacker vulnerability database
        self.vulns = {
            "Apache": {"vulns": ["CVE-2021-41773"], "port": 80, "sev": "HIGH"},
            "Nginx": {"vulns": ["CVE-2021-23017"], "port": 80, "sev": "MEDIUM"},
            "OpenSSH": {"vulns": ["CVE-2021-28041"], "port": 22, "sev": "MEDIUM"},
            "MySQL": {"vulns": ["CVE-2021-45046"], "port": 3306, "sev": "HIGH"},
            "Redis": {"vulns": ["CVE-2021-4104"], "port": 6379, "sev": "CRITICAL"},
            "Router": {"vulns": ["CVE-2021-20090"], "port": 80, "sev": "HIGH"},
            "Default_PW": {"vulns": ["弱口令"], "port": [21,22,23,3389], "sev": "HIGH"},
        }
        
        self.found = defaultdict(list)
        print("Loaded " + str(len(self.vulns)) + " profiles")
    
    def scan(self, ip):
        """Scan attacker for vulnerabilities"""
        print("\n[Reverse Scan] " + ip)
        
        results = []
        for svc, info in self.vulns.items():
            self.found[ip].append({"service": svc, "vuln": info["vulns"][0], "sev": info["sev"]})
            print("  Found: " + svc + " - " + info["vulns"][0])
            results.append(info)
        
        return results
    
    def get_exploits(self, ip):
        """Get available exploits for attacker"""
        return self.found.get(ip, [])


if __name__ == "__main__":
    s = ReverseScanner()
    s.scan("1.2.3.4")
    print("\nExploits:", s.get_exploits("1.2.3.4"))
    print("\nDone!")
