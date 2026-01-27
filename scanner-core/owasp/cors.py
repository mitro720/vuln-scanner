"""
CORS Misconfiguration Detection Module
OWASP A05:2021 - Security Misconfiguration
"""

import requests
from typing import List, Dict, Any


class CORSModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
        # Test origins
        self.test_origins = [
            'https://evil.com',
            'http://attacker.com',
            'null',
            'https://example.com.evil.com',
        ]
        
    def test_cors(self) -> List[Dict[str, Any]]:
        """Test for CORS misconfigurations"""
        findings = []
        
        try:
            for origin in self.test_origins:
                headers = {'Origin': origin}
                response = requests.get(self.target_url, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                # Check for dangerous configurations
                if acao == origin or acao == '*':
                    severity = "high" if acac == "true" else "medium"
                    
                    findings.append({
                        "name": "CORS Misconfiguration",
                        "vulnerability_type": "cors_misconfiguration",
                        "severity": severity,
                        "owasp_category": "A05:2021",
                        "url": self.target_url,
                        "confidence": 100,
                        "technique": "CORS Header Analysis",
                        "evidence": {
                            "test_origin": origin,
                            "access_control_allow_origin": acao,
                            "access_control_allow_credentials": acac,
                            "allows_credentials": acac == "true"
                        },
                        "poc": f"curl -H 'Origin: {origin}' {self.target_url}",
                        "remediation": "Use specific origin whitelist, avoid reflecting Origin header"
                    })
                    
                # Check for null origin bypass
                if origin == 'null' and acao == 'null':
                    findings.append({
                        "name": "CORS Null Origin Bypass",
                        "vulnerability_type": "cors_misconfiguration",
                        "severity": "high",
                        "owasp_category": "A05:2021",
                        "url": self.target_url,
                        "confidence": 100,
                        "technique": "Null Origin Test",
                        "evidence": {
                            "access_control_allow_origin": "null",
                            "access_control_allow_credentials": acac
                        },
                        "poc": f"curl -H 'Origin: null' {self.target_url}",
                        "remediation": "Never allow 'null' origin"
                    })
                    
        except Exception as e:
            print(f"Error testing CORS: {str(e)}")
            
        return findings
        
    def scan(self) -> List[Dict[str, Any]]:
        """Scan for CORS misconfigurations"""
        return self.test_cors()
