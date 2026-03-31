"""
JWT (JSON Web Token) Vulnerability Detection Module
OWASP A07:2021 - Identification and Authentication Failures
"""

import requests
import jwt
import base64
import json
from typing import List, Dict, Any


class JWTModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
    def test_jwt_vulnerabilities(self, token: str) -> List[Dict[str, Any]]:
        """Test JWT for common vulnerabilities"""
        findings = []
        
        try:
            # Decode without verification to inspect
            unverified = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
            
            # Test 1: None algorithm
            if header.get('alg', '').lower() == 'none':
                findings.append({
                    "name": "JWT None Algorithm Vulnerability",
                    "vulnerability_type": "jwt_vulnerability",
                    "severity": "critical",
                    "owasp_category": "A07:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Algorithm Confusion",
                    "evidence": {
                        "algorithm": header.get('alg'),
                        "header": header,
                        "payload": unverified
                    },
                    "poc": "Modify JWT header to use 'none' algorithm",
                    "remediation": "Reject tokens with 'none' algorithm"
                })
                
            # Test 2: Weak secret (common secrets)
            weak_secrets = ['secret', 'password', '123456', 'admin', 'test']
            for secret in weak_secrets:
                try:
                    jwt.decode(token, secret, algorithms=['HS256'])
                    findings.append({
                        "name": "JWT Weak Secret",
                        "vulnerability_type": "jwt_vulnerability",
                        "severity": "critical",
                        "owasp_category": "A07:2021",
                        "url": self.target_url,
                        "confidence": 100,
                        "technique": "Weak Secret Detection",
                        "evidence": {
                            "weak_secret": secret,
                            "algorithm": header.get('alg')
                        },
                        "poc": f"jwt.decode(token, '{secret}', algorithms=['HS256'])",
                        "remediation": "Use strong, random secrets (256+ bits)"
                    })
                    break
                except:
                    pass
                    
            # Test 3: Algorithm confusion (RS256 to HS256)
            if header.get('alg') == 'RS256':
                findings.append({
                    "name": "Potential JWT Algorithm Confusion",
                    "vulnerability_type": "jwt_vulnerability",
                    "severity": "high",
                    "owasp_category": "A07:2021",
                    "url": self.target_url,
                    "confidence": 60,
                    "technique": "Algorithm Confusion",
                    "evidence": {
                        "current_algorithm": "RS256",
                        "description": "May be vulnerable to RS256 to HS256 confusion"
                    },
                    "poc": "Change algorithm to HS256 and sign with public key",
                    "remediation": "Explicitly specify allowed algorithms in verification"
                })
                
            # Test 4: Sensitive data in payload
            sensitive_keys = ['password', 'secret', 'api_key', 'private_key', 'ssn']
            found_sensitive = []
            for key in unverified.keys():
                if any(s in key.lower() for s in sensitive_keys):
                    found_sensitive.append(key)
                    
            if found_sensitive:
                findings.append({
                    "name": "Sensitive Data in JWT",
                    "vulnerability_type": "jwt_vulnerability",
                    "severity": "medium",
                    "owasp_category": "A02:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Token Analysis",
                    "evidence": {
                        "sensitive_fields": found_sensitive,
                        "payload": unverified
                    },
                    "poc": "Decode JWT to view sensitive data",
                    "remediation": "Never store sensitive data in JWT payload"
                })
                
            # Test 5: No expiration
            if 'exp' not in unverified:
                findings.append({
                    "name": "JWT Missing Expiration",
                    "vulnerability_type": "jwt_vulnerability",
                    "severity": "medium",
                    "owasp_category": "A07:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "technique": "Token Analysis",
                    "evidence": {
                        "payload": unverified,
                        "description": "Token has no expiration time"
                    },
                    "poc": "Token can be used indefinitely",
                    "remediation": "Always set 'exp' claim with reasonable expiration"
                })
                
        except Exception as e:
            print(f"Error testing JWT: {str(e)}")
            
        return findings
        
    def extract_jwt_from_response(self, response: requests.Response) -> str:
        """Extract JWT from response"""
        # Check Authorization header
        auth_header = response.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
            
        # Check cookies
        for cookie in response.cookies:
            if 'token' in cookie.name.lower() or 'jwt' in cookie.name.lower():
                return cookie.value
                
        # Check response body
        try:
            data = response.json()
            if 'token' in data:
                return data['token']
            if 'access_token' in data:
                return data['access_token']
        except:
            pass
            
        return None
        
    def scan(self, urls=None) -> List[Dict[str, Any]]:
        """Scan for JWT vulnerabilities across all discovered URLs"""
        all_findings = []
        targets = urls if urls else [self.target_url]
        for url in targets:
            try:
                response = self.http.get(url, timeout=10)
                token = self.extract_jwt_from_response(response)
                if token:
                    findings = self.test_jwt_vulnerabilities(token)
                    all_findings.extend(findings)
            except Exception as e:
                print(f"Error scanning JWT on {url}: {str(e)}")
        return all_findings

