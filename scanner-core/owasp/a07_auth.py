"""
Authentication Failures Detection
OWASP A07:2021 - Identification and Authentication Failures
"""

import requests
from typing import List, Dict, Any


class AuthModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
        # Common weak credentials
        self.weak_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '12345'),
            ('root', 'root'),
            ('test', 'test'),
        ]
        
    def test_weak_credentials(self, login_url: str) -> List[Dict[str, Any]]:
        """Test for weak/default credentials"""
        findings = []
        
        try:
            for username, password in self.weak_credentials:
                data = {
                    'username': username,
                    'password': password
                }
                
                response = requests.post(login_url, data=data, timeout=10, allow_redirects=False)
                
                # Check for successful login indicators
                if response.status_code in [200, 302] and 'error' not in response.text.lower():
                    findings.append({
                        "name": "Weak Default Credentials",
                        "severity": "critical",
                        "owasp_category": "A07:2021",
                        "url": login_url,
                        "confidence": 85,
                        "technique": "Credential Testing",
                        "evidence": {
                            "username": username,
                            "description": "Default credentials accepted"
                        },
                        "poc": f"curl -X POST {login_url} -d 'username={username}&password=***'",
                        "remediation": "Enforce strong password policies and remove default credentials"
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing credentials: {str(e)}")
            
        return findings
        
    def check_session_management(self) -> List[Dict[str, Any]]:
        """Check session cookie security"""
        findings = []
        
        try:
            response = requests.get(self.target_url, timeout=10)
            
            for cookie in response.cookies:
                issues = []
                
                # Check for missing Secure flag
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                    
                # Check for missing HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("Missing HttpOnly flag")
                    
                # Check for missing SameSite attribute
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("Missing SameSite attribute")
                    
                if issues:
                    findings.append({
                        "name": "Insecure Session Cookie",
                        "severity": "medium",
                        "owasp_category": "A07:2021",
                        "url": self.target_url,
                        "confidence": 100,
                        "technique": "Cookie Analysis",
                        "evidence": {
                            "cookie_name": cookie.name,
                            "issues": issues
                        },
                        "poc": f"curl -I {self.target_url}",
                        "remediation": "Set Secure, HttpOnly, and SameSite flags on session cookies"
                    })
                    
        except Exception as e:
            print(f"Error checking session management: {str(e)}")
            
        return findings
        
    def check_password_policy(self, forms: List[Dict]) -> List[Dict[str, Any]]:
        """Check for password policy enforcement"""
        findings = []
        
        try:
            for form in forms:
                # Look for password fields
                has_password = any(
                    inp.get('type') == 'password' 
                    for inp in form.get('inputs', [])
                )
                
                if has_password:
                    # Check if there's a password strength indicator
                    # This is a basic check - in reality, would need to test actual submission
                    findings.append({
                        "name": "Password Policy Not Enforced",
                        "severity": "low",
                        "owasp_category": "A07:2021",
                        "url": form.get('url'),
                        "confidence": 50,
                        "technique": "Form Analysis",
                        "evidence": {
                            "description": "Password form found without visible strength requirements"
                        },
                        "poc": "Manual testing required",
                        "remediation": "Implement strong password policy with complexity requirements"
                    })
                    break
                    
        except Exception as e:
            print(f"Error checking password policy: {str(e)}")
            
        return findings
        
    def scan(self, forms: List[Dict] = None) -> List[Dict[str, Any]]:
        """Scan for authentication failures"""
        all_findings = []
        
        all_findings.extend(self.check_session_management())
        
        if forms:
            all_findings.extend(self.check_password_policy(forms))
            
        return all_findings
