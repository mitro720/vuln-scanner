"""
Cross-Site Scripting (XSS) Detection
OWASP A03:2021 - Injection
Improved version for testaspnet.vulnweb.com and similar ASP.NET apps
"""
import html
import json
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

class XSSModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Use shared HttpClient if provided (recommended)
        if http_client:
            self.http = http_client
        else:
            import requests
            self.http = requests
        
        # Stronger, context-aware payloads
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'> <script>alert(1)</script>",
            "\"'><script>alert(1)</script>",
            "<script>alert(document.domain)</script>",
            "javascript:alert(1)",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<body onload=alert(1)>",
            # Unique marker payloads (best for detection)
            "xssTEST123<script>alert(1)</script>",
            "\"><img src=x onerror=alert('xssTEST123')>",
            "'; alert('xssTEST123'); //",
            "\"; alert('xssTEST123'); //",
        ]

    def _is_xss_success(self, response_text: str, payload: str) -> bool:
        """Smart detection: Check if payload executed or broke context"""
        text_lower = response_text.lower()
        marker = "xssTEST123"
        
        # Best case: Our unique marker appears unsanitized
        if marker in response_text:
            return True
        
        # Common successful patterns
        success_indicators = [
            "alert(1)",
            "alert(document.domain)",
            "onerror=alert",
            "<script>alert",
            "javascript:alert",
            "xssTEST123"  # fallback
        ]
        
        for indicator in success_indicators:
            if indicator in text_lower:
                # Extra check: make sure it's not HTML encoded
                if "&lt;script&gt;" not in response_text and "&amp;lt;" not in response_text:
                    return True
        return False

    def test_reflected_xss(self, url: str, param: str) -> List[Dict[str, Any]]:
        findings = []
        
        try:
            parsed = urlparse(url)
            base_params = parse_qs(parsed.query)
            
            for payload in self.payloads:
                test_params = base_params.copy()
                test_params[param] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if test_params:
                    test_url += "?" + urlencode(test_params, doseq=True)
                
                try:
                    response = self.http.get(test_url, timeout=8, allow_redirects=True)
                    
                    if self._is_xss_success(response.text, payload):
                        findings.append({
                            "name": "Reflected Cross-Site Scripting (XSS)",
                            "severity": "high",
                            "owasp_category": "A03:2021",
                            "url": test_url,
                            "parameter": param,
                            "confidence": 85,
                            "technique": "Reflected XSS",
                            "evidence": {
                                "payload": payload,
                                "status_code": response.status_code,
                                "response_length": len(response.text),
                                "snippet": response.text[response.text.find("xssTEST123")-80:response.text.find("xssTEST123")+120] 
                                           if "xssTEST123" in response.text else response.text[:300]
                            },
                            "poc": f"Visit: {test_url}",
                            "remediation": "Use proper output encoding (HtmlEncode) and implement CSP"
                        })
                        break  # One finding per parameter is enough
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"[XSS] Error testing {url}: {str(e)}")
        
        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Main scan method"""
        all_findings = []
        
        print(f"[XSSModule] Testing {len(urls)} URLs for reflected XSS...")
        
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if not params:
                # If no query params, try common ones
                for common_param in ["tfSearch", "search", "q", "id", "comment"]:
                    findings = self.test_reflected_xss(url, common_param)
                    all_findings.extend(findings)
            else:
                for param in params.keys():
                    findings = self.test_reflected_xss(url, param)
                    all_findings.extend(findings)
            
            # Light DOM check
            try:
                resp = self.http.get(url, timeout=6)
                if any(p in resp.text.lower() for p in ["innerhtml", "document.write", "eval("]):
                    all_findings.append({
                        "name": "Potential DOM-based XSS",
                        "severity": "medium",
                        "owasp_category": "A03:2021",
                        "url": url,
                        "confidence": 50,
                        "technique": "DOM XSS Pattern"
                    })
            except:
                pass
                
        print(f"[XSSModule] Scan complete. Found {len(all_findings)} XSS findings.")
        return all_findings
