#!/usr/bin/env python3
"""
Bagua Firewall - Vulnerability Scanner Perception Module
Enhanced: SQL Injection, XSS, Command Injection, Directory Scan
"""

from scapy.all import *
from collections import defaultdict

class VulnScanner:
    """Passive Vulnerability Scanner"""
    
    def __init__(self):
        print("VulnScanner: Initializing...")
        
        # Vulnerability Database
        self.vulns = {
            "SQL_Injection": {
                "pattern": [b"' OR ", b"UNION SELECT", b"1=1", b"--"],
                "severity": "HIGH",
                "cve": "CWE-89"
            },
            "XSS": {
                "pattern": [b"<script>", b"javascript:", b"onerror=", b"onload="],
                "severity": "MEDIUM", 
                "cve": "CWE-79"
            },
            "Command_Injection": {
                "pattern": [b"; ls", b"| cat", b"& whoami", b"$(", b"`"],
                "severity": "HIGH",
                "cve": "CWE-78"
            },
            "Path_Traversal": {
                "pattern": [b"../", b"..\\", b"/etc/passwd"],
                "severity": "MEDIUM",
                "cve": "CWE-22"
            },
            "File_Upload": {
                "pattern": [b".php", b".asp", b".exe", b".sh", b".jsp"],
                "severity": "HIGH",
                "cve": "CWE-434"
            },
        }
        
        # Probe Database
        self.probes = {
            "Directory_Scan": [b"/admin", b"/phpinfo", b"/.git", b"/.env"],
            "Fingerprint": [b"Server:", b"Apache", b"Nginx", b"X-Powered-By"],
            "Brute_Force": [b"401", b"403", b"404"],
        }
        
        # Stats
        self.stats = defaultdict(lambda: {"attempts": 0, "vulns": [], "probes": []})
        
        # Whitelist
        self.whitelist = ("192.168.", "10.", "172.16.", "127.", "5.6.7.8")
        
        print(f"VulnScanner: Loaded {len(self.vulns)} vulns, {len(self.probes)} probes")
    
    def is_whitelist(self, ip):
        if not ip: return True
        for p in self.whitelist:
            if ip.startswith(p) or ip == p: return True
        return False
    
    def check_vuln(self, data):
        if not data: return []
        found = []
        try:
            for name, info in self.vulns.items():
                for pat in info["pattern"]:
                    if pat.lower() in data.lower():
                        found.append({"type": name, "severity": info["severity"], "cve": info["cve"]})
        except: pass
        return found
    
    def check_probe(self, data):
        if not data: return []
        found = []
        try:
            for name, patterns in self.probes.items():
                for pat in patterns:
                    if pat in data:
                        found.append({"type": name})
        except: pass
        return found
    
    def scan(self, packet):
        """Main scan function"""
        if IP not in packet: return None
        src = packet[IP].src
        if self.is_whitelist(src): return None
        
        result = {"module": "VulnScanner", "yin_yang": "Yin", "source": src, "status": "SAFE"}
        self.stats[src]["attempts"] += 1
        
        # Check payload
        if TCP in packet and Raw in packet:
            data = bytes(packet[Raw].load)
            
            # Vulnerability check
            vulns = self.check_vuln(data)
            if vulns:
                self.stats[src]["vulns"].extend(vulns)
                result["status"] = "THREAT"
                result["threat_type"] = "VULN_ATTACK"
                result["vulns"] = vulns
            
            # Probe check
            probes = self.check_probe(data)
            if probes:
                self.stats[src]["probes"].extend(probes)
                if result["status"] != "THREAT":
                    result["status"] = "SUSPICIOUS"
                    result["threat_type"] = "PROBE"
                    result["probes"] = probes
        
        # Check malicious ports
        if TCP in packet:
            port = packet[TCP].dport
            evil_ports = {4444: "Metasploit", 5555: "ADB", 6667: "IRC"}
            if port in evil_ports:
                result["status"] = "THREAT"
                result["threat_type"] = "EVIL_PORT"
                result["port"] = {port: evil_ports[port]}
        
        return result


# Test
if __name__ == "__main__":
    scanner = VulnScanner()
    
    print("\n=== Test ===\n")
    
    # Normal
    r = scanner.scan(IP(src="8.8.8.8")/TCP(dport=80)/Raw(b"GET / HTTP/1.1"))
    print(f"1. Normal: {r['status']}")
    
    # SQL Injection
    r = scanner.scan(IP(src="1.2.3.4")/TCP(dport=80)/Raw(b"GET /login.php?id=1' OR '1'='1"))
    print(f"2. SQL: {r['status']} - {r.get('vulns', 'none')}")
    
    # XSS
    r = scanner.scan(IP(src="1.2.3.5")/TCP(dport=80)/Raw(b"GET /search?q=<script>alert(1)</script>"))
    print(f"3. XSS: {r['status']} - {r.get('vulns', 'none')}")
    
    # Directory Scan
    r = scanner.scan(IP(src="1.2.3.6")/TCP(dport=80)/Raw(b"GET /admin HTTP/1.1"))
    print(f"4. Probe: {r['status']} - {r.get('probes', 'none')}")
    
    print("\nDone!")
