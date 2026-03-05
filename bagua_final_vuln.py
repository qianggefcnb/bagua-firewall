#!/usr/bin/env python3
"""Bagua Firewall - Final Version with Vuln Scanner"""

from scapy.all import *
from collections import defaultdict

class BaguaFirewall:
    def __init__(self):
        print("=" * 50)
        print("Bagua Firewall - Final with Vuln Scanner")
        print("=" * 50)
        self.perception = PerceptionModule()
        self.vuln_scanner = VulnScanner()
        self.yin_yang = YinYangMode()
        self.defense = DefenseModule()
        print("Modules loaded")
    
    def detect(self, packet):
        # Whitelist check
        if IP in packet:
            src = packet[IP].src
            if self.perception.is_whitelist(src):
                self.yin_yang.no_attack()
                return {"status": 0, "mode": self.yin_yang.current}
        
        # Perception check
        result = self.perception.detect(packet)
        if not result or result.get("status") == 0:
            result = self.vuln_scanner.scan(packet)
        
        # Response
        if result and result.get("status") == 1:
            self.yin_yang.detect_attack()
            result["mode"] = self.yin_yang.current
            self.defense.response(result)
        else:
            self.yin_yang.no_attack()
            result = {"status": 0, "mode": self.yin_yang.current}
        
        return result


class PerceptionModule:
    def __init__(self):
        self.sensitive = {23, 445, 3389}
        self.whitelist = ("192.168.", "10.", "127.", "5.6.7.8", "8.8.8.")
        self.stats = defaultdict(int)
    
    def is_whitelist(self, ip):
        if not ip: return True
        for p in self.whitelist:
            if ip.startswith(p): return True
        return False
    
    def detect(self, packet):
        if IP not in packet: return {"status": 0}
        src = packet[IP].src
        if self.is_whitelist(src): return {"status": 0}
        self.stats[src] += 1
        
        if TCP in packet:
            dst = packet[TCP].dport
            if dst in self.sensitive:
                return {"status": 1, "module": "Perception", "type": f"Sensitive{dst}", "source": src}
            if packet[TCP].flags == 2 and self.stats[src] > 3:
                return {"status": 1, "module": "Perception", "type": "SYN Scan", "source": src}
        return {"status": 0}


class VulnScanner:
    def __init__(self):
        self.vulns = {
            "SQL_Injection": {"pattern": [b"' OR ", b"UNION SELECT"], "severity": "HIGH"},
            "XSS": {"pattern": [b"<script>", b"javascript:"], "severity": "MEDIUM"},
            "Command_Injection": {"pattern": [b"; ls", b"| cat", b"$(", b"`"], "severity": "HIGH"},
        }
        self.probes = {
            "Directory_Scan": [b"/admin", b"/.git", b"/.env"],
            "Fingerprint": [b"Server:", b"Apache", b"Nginx"],
        }
        self.whitelist = ("192.168.", "10.", "127.", "5.6.7.8")
        self.stats = defaultdict(lambda: {"vulns": [], "probes": []})
    
    def is_whitelist(self, ip):
        if not ip: return True
        for p in self.whitelist:
            if ip.startswith(p): return True
        return False
    
    def check(self, data):
        found = []
        try:
            for name, info in self.vulns.items():
                for pat in info["pattern"]:
                    if pat in data:
                        found.append({"type": name, "severity": info["severity"]})
        except: pass
        return found
    
    def scan(self, packet):
        if IP not in packet: return None
        src = packet[IP].src
        if self.is_whitelist(src): return None
        
        result = {"module": "VulnScanner", "yin_yang": "Yin", "source": src, "status": 0}
        
        if TCP in packet and Raw in packet:
            data = bytes(packet[Raw].load)
            vulns = self.check(data)
            if vulns:
                self.stats[src]["vulns"].extend(vulns)
                result["status"] = 1
                result["threat_type"] = "VULN_ATTACK"
                result["vulns"] = vulns
        
        return result


class YinYangMode:
    def __init__(self):
        self.current = "Yin"
        self.strength = 0
    
    def detect_attack(self):
        self.strength = min(100, self.strength + 10)
        old = self.current
        if self.current == "Yin" and self.strength >= 70: self.current = "Yang"
        elif self.current == "Yang" and self.strength <= 20: self.current = "Yin"
        if old != self.current: print(f"YinYang: {old} -> {self.current}")
    
    def no_attack(self):
        self.strength = max(0, self.strength - 5)


class DefenseModule:
    def response(self, threat):
        strategy = {"Yin": "Monitor", "Yang": "Counter"}
        print(f"[{threat.get('module')}] {threat.get('type')} | Mode: {threat.get('mode', 'Yin')}")


if __name__ == "__main__":
    fw = BaguaFirewall()
    print("\nTest:")
    
    # Normal
    for _ in range(5):
        fw.detect(IP(src="8.8.8.8")/TCP(dport=80))
    print(f"Normal: {fw.yin_yang.current}, Strength: {fw.yin_yang.strength}")
    
    # Attack
    for _ in range(8):
        fw.detect(IP(src="1.2.3.4")/TCP(dport=445))
    print(f"Attack: {fw.yin_yang.current}, Strength: {fw.yin_yang.strength}")
    
    # SQL Injection
    print("\nSQL Injection Test:")
    fw.detect(IP(src="1.2.3.5")/TCP(dport=80)/Raw(b"GET /login.php?id=1' OR '1'='1"))
    
    print("\nDone!")
