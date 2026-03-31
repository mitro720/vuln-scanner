"""
Server-Side Template Injection (SSTI) Scanner Module
"""
import requests
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any

class SSTIModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url # Base URL
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
            
        # Keep only the 2 most reliable payloads to avoid slow scans
        self.payloads = [
            {"engine": "Generic/Jinja2/Twig", "payload": "{{7*7}}", "expected": "49"},
            {"engine": "Generic/FreeMarker", "payload": "${7*7}", "expected": "49"},
        ]
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        # Limit to the 3 most likely injection params to keep scan fast
        test_params = ['q', 'search', 'name']
        
        for url in urls:
            for param in test_params:
                found = False
                for payload_info in self.payloads:
                    if found:
                        break
                    payload = payload_info['payload']
                    expected = payload_info['expected']
                    engine = payload_info['engine']
                    
                    test_url = f"{url}?{param}={payload}"
                    
                    try:
                        resp = self.http.get(test_url, timeout=5)
                        
                        if expected in resp.text and payload not in resp.text:
                            findings.append({
                                "name": "Server-Side Template Injection (SSTI)",
                                "severity": "critical",
                                "owasp_category": "Injection",
                                "url": test_url,
                                "description": f"SSTI detected. Engine evaluated '{payload}' → '{expected}'. Likely engine: {engine}",
                                "confidence": 95,
                                "technique": "Active Probing",
                                "evidence": f"Payload: {payload} | Result '{expected}' found in response.",
                                "remediation": "Sanitize all user input before passing to a template engine. Use logic-less templates or sandbox the engine."
                            })
                            found = True
                            break
                    except requests.RequestException:
                        continue
                        
        return findings

