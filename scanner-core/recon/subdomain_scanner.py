"""
Advanced Subdomain Scanner & Live Checker
Saves results to file and filters for live servers.
"""

import requests
import socket
import concurrent.futures
import os
import time
from typing import List, Dict, Any

class SubdomainScanner:
    def __init__(self, target_domain: str, output_dir: str = "scans"):
        self.target_domain = target_domain
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        self.subdomains_file = os.path.join(output_dir, f"{target_domain}_subdomains.txt")
        self.live_file = os.path.join(output_dir, f"{target_domain}_live.txt")

    def run(self) -> Dict[str, Any]:
        """Run full subdomain discovery and live check pipeline"""
        print(f"[*] Starting subdomain scan for {self.target_domain}...")
        
        # 1. Discover Subdomains
        subdomains = self.discover_subdomains()
        self.save_to_file(self.subdomains_file, subdomains)
        print(f"[+] Found {len(subdomains)} subdomains. Saved to {self.subdomains_file}")
        
        # 2. Check for Live Servers
        print(f"[*] Checking for live servers...")
        live_servers = self.check_live_servers(subdomains)
        self.save_to_file(self.live_file, live_servers)
        print(f"[+] Found {len(live_servers)} live servers. Saved to {self.live_file}")
        
        return {
            "total_subdomains": len(subdomains),
            "live_servers": len(live_servers),
            "subdomains_file": self.subdomains_file,
            "live_file": self.live_file,
            "live_urls": live_servers
        }

    def discover_subdomains(self) -> List[str]:
        """Combine multiple sources for subdomain discovery"""
        found = set()
        
        # Source 1: CRT.sh (Certificate Transparency)
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['name_value']
                    if '\n' in name:
                        for n in name.split('\n'):
                            found.add(n)
                    else:
                        found.add(name)
        except Exception as e:
            print(f"[-] Error fetching from crt.sh: {e}")

        # Source 2: Hackertarget API
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.target_domain}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        sub = line.split(',')[0]
                        found.add(sub)
        except Exception as e:
            print(f"[-] Error fetching from Hackertarget: {e}")

        # Clean and filter results
        clean_subdomains = []
        for sub in found:
            sub = sub.lower().strip()
            if sub.endswith(self.target_domain) and '*' not in sub:
                clean_subdomains.append(sub)
                
        return sorted(list(set(clean_subdomains)))

    def check_live_servers(self, subdomains: List[str]) -> List[str]:
        """Check which subdomains are running web servers"""
        live_urls = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {
                executor.submit(self._probe_url, sub): sub for sub in subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_url):
                result = future.result()
                if result:
                    live_urls.append(result)
                    
        return live_urls

    def _probe_url(self, domain: str) -> str:
        """Probe a single domain for HTTP/HTTPS"""
        # Try HTTPS first
        try:
            url = f"https://{domain}"
            requests.get(url, timeout=3, allow_redirects=True)
            return url
        except:
            # Try HTTP if HTTPS fails
            try:
                url = f"http://{domain}"
                requests.get(url, timeout=3, allow_redirects=True)
                return url
            except:
                return None

    def save_to_file(self, filename: str, lines: List[str]):
        """Save a list of strings to a file"""
        with open(filename, 'w') as f:
            for line in lines:
                f.write(f"{line}\n")

if __name__ == "__main__":
    # Test run
    scanner = SubdomainScanner("example.com")
    scanner.run()
