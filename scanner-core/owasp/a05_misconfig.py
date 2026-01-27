"""
Security Misconfiguration Detection
OWASP A05:2021 - Security Misconfiguration
"""

import requests
from typing import List, Dict, Any


class MisconfigModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
        # Security headers to check
        self.security_headers = {
            "X-Frame-Options": {
                "severity": "medium",
                "description": "Protects against clickjacking attacks"
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "Prevents MIME type sniffing"
            },
            "Strict-Transport-Security": {
                "severity": "medium",
                "description": "Enforces HTTPS connections"
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "Prevents XSS and injection attacks"
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "Legacy XSS protection (deprecated but still useful)"
            },
            "Referrer-Policy": {
                "severity": "low",
                "description": "Controls referrer information"
            }
        }
        
    def check_headers(self) -> List[Dict[str, Any]]:
        """Check for missing security headers"""
        findings = []
        
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            missing_headers = []
            for header, info in self.security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                    
            if missing_headers:
                findings.append({
                    "name": "Missing Security Headers",
                    "severity": "medium",
                    "owasp_category": "A05:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Header Analysis",
                    "evidence": {
                        "missing_headers": missing_headers,
                        "current_headers": dict(headers)
                    },
                    "poc": f"curl -I {self.target_url}",
                    "remediation": f"Add the following headers: {', '.join(missing_headers)}"
                })
                
        except Exception as e:
            print(f"Error checking headers: {str(e)}")
            
        return findings
        
    def check_server_info(self) -> List[Dict[str, Any]]:
        """Check for information disclosure in headers"""
        findings = []
        
        try:
            response = requests.get(self.target_url, timeout=10)
            headers = response.headers
            
            # Check for Server header
            if 'Server' in headers:
                findings.append({
                    "name": "Server Information Disclosure",
                    "severity": "info",
                    "owasp_category": "A05:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Header Analysis",
                    "evidence": {
                        "server": headers['Server']
                    },
                    "poc": f"curl -I {self.target_url}",
                    "remediation": "Remove or obfuscate Server header"
                })
                
            # Check for X-Powered-By header
            if 'X-Powered-By' in headers:
                findings.append({
                    "name": "Technology Stack Disclosure",
                    "severity": "info",
                    "owasp_category": "A05:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Header Analysis",
                    "evidence": {
                        "x_powered_by": headers['X-Powered-By']
                    },
                    "poc": f"curl -I {self.target_url}",
                    "remediation": "Remove X-Powered-By header"
                })
                
        except Exception as e:
            print(f"Error checking server info: {str(e)}")
            
        return findings
        
    def scan(self) -> List[Dict[str, Any]]:
        """Run all misconfiguration checks"""
        findings = []
        findings.extend(self.check_headers())
        findings.extend(self.check_server_info())
        return findings
