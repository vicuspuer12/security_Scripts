#!/usr/bin/env python3

import requests
import json
from scapy.all import *
from datetime import datetime
import time
import os
from threading import Thread
import nvdlib
import socket

class NetworkScanner:
    def __init__(self):
        # Initialize with your API keys
        self.vt_api_key = "YOUR_VIRUSTOTAL_API_KEY"
        self.nvd_api_key = "YOUR_NVD_API_KEY"  # Optional
        self.suspicious_ips = set()
        self.known_vulnerabilities = {}
        
    def analyze_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Check IPs against VirusTotal
            self.check_ip_virustotal(src_ip)
            self.check_ip_virustotal(dst_ip)
            
            # If TCP packet, extract more information
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                self.check_port_vulnerabilities(dst_port)
    
    def check_ip_virustotal(self, ip):
        if ip in self.suspicious_ips:
            return
        
        headers = {
            "x-apikey": self.vt_api_key
        }
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                result = response.json()
                if result["data"]["attributes"]["last_analysis_stats"]["malicious"] > 0:
                    self.suspicious_ips.add(ip)
                    self.log_threat(f"Suspicious IP detected: {ip}")
        except Exception as e:
            print(f"Error checking VirusTotal: {e}")
    
    def check_port_vulnerabilities(self, port):
        # Query NVD for vulnerabilities related to this port
        try:
            vulns = nvdlib.searchCVE(
                keywordSearch=f"port {port}",
                key=self.nvd_api_key
            )
            
            for vuln in vulns:
                if vuln.id not in self.known_vulnerabilities:
                    self.known_vulnerabilities[vuln.id] = {
                        'description': vuln.descriptions[0].value,
                        'severity': vuln.metrics.cvssMetricV31[0].cvssData.baseScore if vuln.metrics.cvssMetricV31 else None
                    }
                    self.log_threat(f"Potential vulnerability found: {vuln.id} on port {port}")
        except Exception as e:
            print(f"Error checking CVE database: {e}")
    
    def log_threat(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")
        
        # Log to file
        with open("threats.log", "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    
    def start_capture(self, interface="eth0"):
        print(f"Starting network capture on interface {interface}")
        sniff(iface=interface, prn=self.analyze_packet, store=0)

def main():
    scanner = NetworkScanner()
    
    # Create a thread for packet capture
    capture_thread = Thread(target=scanner.start_capture)
    capture_thread.daemon = True
    capture_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping network scanner...")

if __name__ == "__main__":
    main()
