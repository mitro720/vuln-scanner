"""
Host Header Injection Module
Tests for vulnerabilities caused by trusting the HTTP Host header.
"""
import requests
from urllib.parse import urlparse
from typing import List, Dict, Any

class HostHeaderInjectionModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url # Base URL
        self.evil_host = "evil-host-header.com"
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        for url in urls:
            try:
                # 1. Basic Host Header Replacement
                headers = {"Host": self.evil_host}
                
                # By default requests doesn't let you override Host easily if you pass the full URL,
                # but if you pass it in headers, some versions respect it. We can also test X-Forwarded-Host.
                
                # We'll test standard replacements
                test_headers = [
                    {"Host": self.evil_host},
                    {"X-Forwarded-Host": self.evil_host},
                    {"X-Host": self.evil_host},
                ]
                
                for head in test_headers:
                    # Request without following redirects to see if the Location header is poisoned
                    resp = self.http.get(url, headers=head, timeout=5, allow_redirects=False)
                    
                    is_vulnerable = False
                    evidence = ""
                    
                    # Check if the evil host is reflected in the response body (e.g., links or password reset tokens)
                    if self.evil_host in resp.text:
                        is_vulnerable = True
                        evidence = f"Evil host '{self.evil_host}' was reflected in the response body."
                    
                    # Check if the evil host is reflected in a 3xx redirect Location header
                    elif str(resp.status_code).startswith('3') and "Location" in resp.headers and self.evil_host in resp.headers["Location"]:
                        is_vulnerable = True
                        evidence = f"Evil host '{self.evil_host}' poisoned the Location redirect header: {resp.headers['Location']}"
                        
                    if is_vulnerable:
                        header_injected = list(head.keys())[0]
                        findings.append({
                            "name": f"Host Header Injection ({header_injected})",
                            "severity": "medium",
                            "owasp_category": "A01:2021",  # Broken Access Control / Misconfig
                            "url": url,
                            "description": f"The application trusts the `{header_injected}` header, reflecting it in the response without validation. This can lead to password reset poisoning, cache poisoning, or routing bypass.",
                            "confidence": 90,
                            "technique": "Header Manipulation",
                            "evidence": evidence,
                            "remediation": "Validate the Host header against a whitelist of allowed domains. Do not blindly trust the Host or X-Forwarded-Host headers for generating links or redirects."
                        })
                        break # Only report once per URL
                        
            except Exception:
                pass
                
        return findings
