"""
Advanced Subdomain Scanner & Live Checker
Uses Go-based tools (subfinder, httpx) for high performance and accuracy.
"""

import os
import json
from typing import List, Dict, Any
from urllib.parse import urlparse
from core.tool_runner import ToolRunner

class SubdomainScanner:
    def __init__(self, target_domain: str, output_dir: str = "scans"):
        # Strip scheme and path
        parsed = urlparse(target_domain if '://' in target_domain else f'http://{target_domain}')
        self.target_domain = parsed.netloc or parsed.path
        self.output_dir = output_dir
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        safe_name = self.target_domain.replace(':', '_').replace('/', '_')
        self.subdomains_file = os.path.join(output_dir, f"{safe_name}_subdomains.txt")
        self.live_file = os.path.join(output_dir, f"{safe_name}_live.txt")
        self.httpx_json_file = os.path.join(output_dir, f"{safe_name}_live.json")

    def run(self, on_discovered=None, on_live=None) -> Dict[str, Any]:
        print(f"[*] Starting Go-based recon for {self.target_domain}...")
        
        # 1. Discover Subdomains using subfinder
        subdomains = self.discover_subdomains(on_discovered)
        print(f"[+] Found {len(subdomains)} subdomains. Saved to {self.subdomains_file}")
        
        # 2. Check Live Servers & Tech Stack using httpx
        print(f"[*] Checking for live servers and technology stack...")
        live_servers = self.check_live_servers(on_live)
        
        # Format for backward compatibility if needed, but return full objects
        live_urls = [server.get('url') for server in live_servers if server.get('url')]
        
        print(f"[+] Found {len(live_servers)} live servers. Saved to {self.live_file}")
        
        return {
            "total_subdomains": len(subdomains),
            "live_servers": len(live_servers),
            "subdomains_file": self.subdomains_file,
            "live_file": self.live_file,
            "live_urls": live_urls,
            "live_data": live_servers
        }

    def discover_subdomains(self, on_discovered=None) -> List[str]:
        if not ToolRunner.is_installed("subfinder"):
            print("[-] subfinder not found in PATH! Falling back to just the base domain.")
            subdomains = [self.target_domain]
            with open(self.subdomains_file, 'w') as f:
                f.write(self.target_domain + "\n")
            if on_discovered:
                on_discovered(self.target_domain)
            return subdomains
            
        # Use JSON output for better parsing during streaming
        cmd = [
            "subfinder",
            "-d", self.target_domain,
            "-silent",
            "-all", # Use all sources
            "-json", # Stream JSON for real-time updates
        ]
        
        subdomains = []
        try:
            # subfinder -json outputs {"host":"sub.domain.com","source":"..."}
            for entry in ToolRunner.run_command_json_stream(cmd):
                sub = entry.get("host")
                if sub:
                    subdomains.append(sub)
                    if on_discovered:
                        on_discovered(sub)
        except Exception as e:
            print(f"[-] Subfinder streaming failed: {e}")

        # Save to file for next step
        with open(self.subdomains_file, 'w') as f:
            for sub in set(subdomains):
                f.write(sub + "\n")
                
        return list(set(subdomains))

    def check_live_servers(self, on_live=None) -> List[Dict[str, Any]]:
        if not os.path.exists(self.subdomains_file):
            return []
            
        if not ToolRunner.is_installed("httpx"):
            print("[-] httpx not found! Skipping tech detection and fast live check.")
            return []
            
        cmd = [
            "httpx",
            "-l", self.subdomains_file,
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-json",
        ]
        
        live_servers = []
        live_urls = []
        
        try:
            for data in ToolRunner.run_command_json_stream(cmd):
                live_servers.append(data)
                url = data.get("url")
                if url:
                    live_urls.append(url)
                if on_live:
                    on_live(data)
        except Exception as e:
            print(f"[-] httpx streaming failed: {e}")
                        
        # Save results
        with open(self.httpx_json_file, 'w') as f:
            for server in live_servers:
                f.write(json.dumps(server) + "\n")

        with open(self.live_file, 'w') as f:
            for url in set(live_urls):
                f.write(url + "\n")
                
        return live_servers

if __name__ == "__main__":
    scanner = SubdomainScanner("example.com")
    print(scanner.run())
