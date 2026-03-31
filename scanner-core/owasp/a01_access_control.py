"""
Broken Access Control Detection (OWASP A01:2021)
Improved version focused on testaspnet.vulnweb.com and hackyourselffirst.troyhunt.com
"""
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

class AccessControlModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        if http_client:
            self.http = http_client
        else:
            import requests
            self.http = requests

        # ASP.NET/Windows-focused sensitive paths
        self.sensitive_paths = [
            '/admin', '/administrator', '/dashboard', '/api/admin', '/api/users',
            '/trace.axd', '/elmah.axd', '/WebResource.axd', '/global.asax',
            '/bin/', '/App_Data/', '/App_Browsers/', '/web.config', 
            '/Trace.axd', '/elmah', 
        ]

        # IDOR test values (common pattern on these vulnerable sites)
        self.idor_test_values = ["0", "1", "999", "1000", "-1", "admin"]

    def test_idor(self, url: str) -> List[Dict[str, Any]]:
        """Test for Insecure Direct Object References (most relevant for these targets)"""
        findings = []
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                return findings

            for param_name, values in params.items():
                original_value = values[0] if values else "1"
                
                for test_id in self.idor_test_values:
                    if test_id == original_value:
                        continue
                        
                    test_params = params.copy()
                    test_params[param_name] = [test_id]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if test_params:
                        test_url += "?" + urlencode(test_params, doseq=True)
                    
                    try:
                        resp = self.http.get(test_url, timeout=8, allow_redirects=True)
                        
                        # Heuristic: if we get 200 and response is significantly different or contains user data
                        if resp.status_code == 200 and len(resp.text) > 100:
                            # Look for signs of successful IDOR (different user data)
                            if any(keyword in resp.text.lower() for keyword in ["user", "email", "password", "admin", "profile"]):
                                findings.append({
                                    "name": "Insecure Direct Object Reference (IDOR)",
                                    "severity": "high",
                                    "owasp_category": "A01:2021",
                                    "url": test_url,
                                    "parameter": param_name,
                                    "confidence": 75,
                                    "technique": "IDOR - Object ID Manipulation",
                                    "evidence": {
                                        "original_id": original_value,
                                        "tested_id": test_id,
                                        "status_code": resp.status_code
                                    },
                                    "poc": f"curl \"{test_url}\"",
                                    "remediation": "Implement proper authorization checks on every object access"
                                })
                                break  # One finding per parameter
                    except:
                        continue
        except Exception as e:
            print(f"[IDOR] Error: {str(e)}")
        
        return findings

    def test_path_traversal(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        windows_payloads = [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "....//....//....//windows/win.ini"
        ]
        
        for payload in windows_payloads:
            try:
                test_url = f"{url}?file={payload}"   # try common param names later
                resp = self.http.get(test_url, timeout=8)
                
                if '[extensions]' in resp.text or '127.0.0.1' in resp.text:
                    findings.append({
                        "name": "Path Traversal (Windows)",
                        "severity": "critical",
                        "owasp_category": "A01:2021",
                        "url": test_url,
                        "confidence": 90,
                        "technique": "Path Traversal",
                        "evidence": {"payload": payload, "snippet": resp.text[:300]},
                        "poc": f"curl \"{test_url}\"",
                        "remediation": "Canonicalize paths and use whitelisting"
                    })
                    break
            except:
                continue
        return findings

    def test_exposed_endpoints(self) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.sensitive_paths:
            try:
                test_url = base + path
                resp = self.http.get(test_url, timeout=6, allow_redirects=False)
                
                if resp.status_code in (200, 301, 302):
                    severity = "high" if "admin" in path or "trace.axd" in path else "medium"
                    findings.append({
                        "name": "Exposed Sensitive Endpoint",
                        "severity": severity,
                        "owasp_category": "A01:2021",
                        "url": test_url,
                        "confidence": 85,
                        "technique": "Sensitive Path Discovery",
                        "evidence": {"status_code": resp.status_code, "path": path},
                        "poc": f"curl -I {test_url}",
                        "remediation": "Restrict access using authentication and authorization"
                    })
            except:
                continue
        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        
        print(f"[AccessControlModule] Testing {len(urls)} URLs for IDOR + Access Control issues...")
        
        # IDOR Testing (highest value on these targets)
        for url in urls:
            idor_findings = self.test_idor(url)
            all_findings.extend(idor_findings)
            
            # Path Traversal (secondary)
            pt_findings = self.test_path_traversal(url)
            all_findings.extend(pt_findings)
        
        # Global exposed endpoints
        endpoint_findings = self.test_exposed_endpoints()
        all_findings.extend(endpoint_findings)
        
        print(f"[AccessControlModule] Found {len(all_findings)} access control findings.")
        return all_findings
