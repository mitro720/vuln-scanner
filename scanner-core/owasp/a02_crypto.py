"""
Cryptographic Failures Detection
OWASP A02:2021 - Cryptographic Failures
"""

import requests
import ssl
import socket
from typing import List, Dict, Any
from urllib.parse import urlparse


class CryptoModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
    def check_https(self) -> List[Dict[str, Any]]:
        """Check if HTTPS is enforced"""
        findings = []
        
        try:
            parsed = urlparse(self.target_url)
            
            # Check if using HTTP instead of HTTPS
            if parsed.scheme == 'http':
                findings.append({
                    "name": "Unencrypted Connection (HTTP)",
                    "severity": "high",
                    "owasp_category": "A02:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Protocol Analysis",
                    "evidence": {
                        "scheme": "http",
                        "description": "Site uses unencrypted HTTP"
                    },
                    "poc": f"curl -I {self.target_url}",
                    "remediation": "Implement HTTPS and redirect all HTTP traffic to HTTPS"
                })
                
        except Exception as e:
            print(f"Error checking HTTPS: {str(e)}")
            
        return findings
        
    def check_ssl_tls(self) -> List[Dict[str, Any]]:
        """Check SSL/TLS configuration"""
        findings = []
        
        try:
            parsed = urlparse(self.target_url)
            
            if parsed.scheme != 'https':
                return findings
                
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Check SSL/TLS version
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    
                    # Check for outdated protocols
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        findings.append({
                            "name": "Outdated SSL/TLS Version",
                            "severity": "high",
                            "owasp_category": "A02:2021",
                            "url": self.target_url,
                            "confidence": 100,
                            "technique": "SSL/TLS Analysis",
                            "evidence": {
                                "version": version,
                                "description": "Using outdated SSL/TLS protocol"
                            },
                            "poc": f"openssl s_client -connect {hostname}:{port}",
                            "remediation": "Upgrade to TLS 1.2 or TLS 1.3"
                        })
                        
        except Exception as e:
            print(f"Error checking SSL/TLS: {str(e)}")
            
        return findings
        
    def check_sensitive_data_exposure(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Check for sensitive data in responses"""
        findings = []
        
        sensitive_patterns = [
            ('password', 'Password field in response'),
            ('api_key', 'API key in response'),
            ('secret', 'Secret in response'),
            ('token', 'Token in response'),
            ('credit_card', 'Credit card data'),
            ('ssn', 'Social Security Number'),
        ]
        
        try:
            for url in urls[:10]:  # Limit to first 10 URLs
                response = requests.get(url, timeout=10)
                content = response.text.lower()
                
                for pattern, description in sensitive_patterns:
                    if pattern in content:
                        findings.append({
                            "name": "Potential Sensitive Data Exposure",
                            "severity": "medium",
                            "owasp_category": "A02:2021",
                            "url": url,
                            "confidence": 70,
                            "technique": "Content Analysis",
                            "evidence": {
                                "pattern": pattern,
                                "description": description
                            },
                            "poc": f"curl {url}",
                            "remediation": "Encrypt sensitive data and avoid exposing it in responses"
                        })
                        break
                        
        except Exception as e:
            print(f"Error checking sensitive data: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str] = None) -> List[Dict[str, Any]]:
        """Scan for cryptographic failures"""
        all_findings = []
        
        all_findings.extend(self.check_https())
        all_findings.extend(self.check_ssl_tls())
        
        if urls:
            all_findings.extend(self.check_sensitive_data_exposure(urls))
            
        return all_findings
