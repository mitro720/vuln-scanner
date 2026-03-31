"""
CORS Misconfiguration Detection Module
OWASP A05:2021 - Security Misconfiguration
"""

import requests
from typing import List, Dict, Any


class CORSModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
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
                response = self.http.get(self.target_url, headers=headers, timeout=10)
                
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
        
    def scan(self, urls=None) -> List[Dict[str, Any]]:
        """Scan for CORS misconfigurations across all discovered URLs"""
        all_findings = []
        targets = urls if urls else [self.target_url]
        for url in targets:
            original = self.target_url
            self.target_url = url
            all_findings.extend(self.test_cors())
            self.target_url = original
        return all_findings

