"""
Broken Access Control Detection
OWASP A01:2021 - Broken Access Control
"""

import requests
from typing import List, Dict, Any
from urllib.parse import urlparse
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.payload_loader import payload_loader


class AccessControlModule:
    def __init__(self, target_url: str, custom_payloads: List[str] = None):
        self.target_url = target_url
        
        # Common admin/sensitive paths
        self.sensitive_paths = [
            '/admin',
            '/administrator',
            '/admin.php',
            '/admin/login',
            '/wp-admin',
            '/phpmyadmin',
            '/dashboard',
            '/api/admin',
            '/api/users',
            '/config',
            '/.env',
            '/.git/config',
            '/backup',
            '/private',
        ]
        
        # Default path traversal payloads
        default_traversal = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
        ]
        
        # Merge with custom payloads if provided
        self.traversal_payloads = payload_loader.merge_with_defaults(
            default_traversal,
            custom_payloads or ['path_traversal.json']
        )
        
    def test_path_traversal(self, url: str) -> List[Dict[str, Any]]:
        """Test for path traversal vulnerabilities"""
        findings = []
        
        try:
            for payload in self.traversal_payloads:
                test_url = f"{url}?file={payload}"
                response = requests.get(test_url, timeout=10)
                
                # Check for common file contents
                if 'root:' in response.text or '[extensions]' in response.text:
                    findings.append({
                        "name": "Path Traversal",
                        "severity": "critical",
                        "owasp_category": "A01:2021",
                        "url": url,
                        "confidence": 95,
                        "technique": "Path Traversal",
                        "evidence": {
                            "payload": payload,
                            "response_snippet": response.text[:200]
                        },
                        "poc": f"curl -X GET \"{test_url}\"",
                        "remediation": "Validate and sanitize file paths, use whitelisting"
                    })
                    break
                    
        except Exception as e:
            print(f"Error testing path traversal: {str(e)}")
            
        return findings
        
    def test_exposed_endpoints(self) -> List[Dict[str, Any]]:
        """Test for exposed admin/sensitive endpoints"""
        findings = []
        
        try:
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for path in self.sensitive_paths:
                test_url = f"{base_url}{path}"
                
                try:
                    response = requests.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check if endpoint is accessible
                    if response.status_code in [200, 301, 302]:
                        findings.append({
                            "name": "Exposed Sensitive Endpoint",
                            "severity": "medium",
                            "owasp_category": "A01:2021",
                            "url": test_url,
                            "confidence": 80,
                            "technique": "Endpoint Discovery",
                            "evidence": {
                                "status_code": response.status_code,
                                "path": path
                            },
                            "poc": f"curl -I {test_url}",
                            "remediation": "Implement proper access controls and authentication"
                        })
                        
                except:
                    pass
                    
        except Exception as e:
            print(f"Error testing exposed endpoints: {str(e)}")
            
        return findings
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Scan for access control issues"""
        all_findings = []
        
        # Test path traversal
        for url in urls:
            findings = self.test_path_traversal(url)
            all_findings.extend(findings)
            
        # Test exposed endpoints
        endpoint_findings = self.test_exposed_endpoints()
        all_findings.extend(endpoint_findings)
        
        return all_findings
