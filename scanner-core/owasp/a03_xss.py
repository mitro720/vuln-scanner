"""
Cross-Site Scripting (XSS) Detection
OWASP A03:2021 - Injection
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class XSSModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None):
        self.target_url = target_url
        
        # Default XSS payloads
        default_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
        ]
        
        # Merge with custom payloads if provided
        self.payloads = payload_loader.merge_with_defaults(
            default_payloads,
            custom_payloads or ['xss.txt']  # Load from file by default
        )
        
    def test_reflected_xss(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Test for reflected XSS"""
        findings = []
        
        try:
            for payload in self.payloads:
                # Build test URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                response = requests.get(test_url, timeout=10)
                
                # Check if payload is reflected without encoding
                if payload in response.text:
                    findings.append({
                        "name": "Reflected Cross-Site Scripting (XSS)",
                        "severity": "high",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 90,
                        "technique": "Reflected",
                        "evidence": {
                            "payload": payload,
                            "reflected": True,
                            "response_snippet": response.text[:300]
                        },
                        "poc": f"curl -X GET \"{test_url}\"",
                        "remediation": "Implement output encoding/escaping and Content Security Policy"
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing XSS: {str(e)}")
            
        return findings
        
    def test_dom_xss(self, url: str) -> List[Dict[str, Any]]:
        """Test for DOM-based XSS"""
        findings = []
        
        try:
            response = requests.get(url, timeout=10)
            html = response.text.lower()
            
            # Look for dangerous JavaScript patterns
            dangerous_patterns = [
                'document.write(',
                'innerhtml',
                'outerhtml',
                'eval(',
                'settimeout(',
                'setinterval(',
            ]
            
            for pattern in dangerous_patterns:
                if pattern in html and 'location' in html:
                    findings.append({
                        "name": "Potential DOM-based XSS",
                        "severity": "medium",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "confidence": 60,
                        "technique": "DOM-based",
                        "evidence": {
                            "pattern": pattern,
                            "description": "Dangerous JavaScript pattern found"
                        },
                        "poc": "Manual testing required",
                        "remediation": "Avoid using dangerous JavaScript functions with user input"
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing DOM XSS: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for XSS vulnerabilities"""
        all_findings = []
        
        for url in urls:
            # Test reflected XSS
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                findings = self.test_reflected_xss(url, param)
                all_findings.extend(findings)
                
            # Test DOM XSS
            dom_findings = self.test_dom_xss(url)
            all_findings.extend(dom_findings)
                
        return all_findings
