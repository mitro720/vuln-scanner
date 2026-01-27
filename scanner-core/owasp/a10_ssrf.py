"""
Server-Side Request Forgery (SSRF) Detection
OWASP A10:2021 - Server-Side Request Forgery
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class SSRFModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None):
        self.target_url = target_url
        
        # Default SSRF payloads
        default_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'http://0.0.0.0',
            'http://[::1]',
        ]
        
        # Merge with custom payloads if provided
        self.payloads = payload_loader.merge_with_defaults(
            default_payloads,
            custom_payloads or ['ssrf.txt']
        )
        
    def test_ssrf(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Test for SSRF vulnerabilities"""
        findings = []
        
        try:
            # Get baseline response
            baseline = requests.get(url, timeout=10)
            baseline_length = len(baseline.text)
            
            for payload in self.payloads:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                response = requests.get(test_url, timeout=10)
                
                # Check for different response (potential SSRF)
                if abs(len(response.text) - baseline_length) > 100:
                    findings.append({
                        "name": "Server-Side Request Forgery (SSRF)",
                        "severity": "critical",
                        "owasp_category": "A10:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 75,
                        "technique": "SSRF Testing",
                        "evidence": {
                            "payload": payload,
                            "response_length_diff": abs(len(response.text) - baseline_length)
                        },
                        "poc": f"curl -X GET \"{test_url}\"",
                        "remediation": "Validate and whitelist allowed URLs, disable redirects"
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing SSRF: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for SSRF vulnerabilities"""
        all_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Test parameters that might accept URLs
            url_params = ['url', 'uri', 'path', 'redirect', 'next', 'callback']
            
            for param in params.keys():
                if any(p in param.lower() for p in url_params):
                    findings = self.test_ssrf(url, param)
                    all_findings.extend(findings)
                    
        return all_findings
