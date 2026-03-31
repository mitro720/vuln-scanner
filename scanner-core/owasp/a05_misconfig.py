"""
Security Misconfiguration Detection (OWASP A05:2021)
Enhanced for ASP.NET vulnerable apps like testaspnet.vulnweb.com
"""
from typing import List, Dict, Any
from urllib.parse import urlparse

class MisconfigModule:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        if http_client:
            self.http = http_client
        else:
            import requests
            self.http = requests

        # Common ASP.NET misconfiguration endpoints
        self.misconfig_endpoints = [
            "/trace.axd",
            "/elmah.axd",
            "/elmah",
            "/WebResource.axd",
            "/global.asax",
            "/web.config",
            "/Trace.axd",
            "/App_Data/",
            "/bin/",
            "/error.aspx",           # often shows stack traces
            "/default.aspx?debug=true"
        ]

    def check_security_headers(self) -> List[Dict[str, Any]]:
        findings = []
        try:
            response = self.http.get(self.target_url, timeout=8)
            headers = response.headers

            missing = []
            critical_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]
            
            for header in critical_headers:
                if header not in headers and header.lower() not in [h.lower() for h in headers]:
                    missing.append(header)

            if missing:
                findings.append({
                    "name": "Missing Critical Security Headers",
                    "severity": "medium",
                    "owasp_category": "A05:2021",
                    "url": self.target_url,
                    "confidence": 90,
                    "technique": "Header Analysis",
                    "evidence": {"missing_headers": missing},
                    "poc": f"curl -I {self.target_url}",
                    "remediation": "Add CSP, HSTS, and X-Frame-Options headers"
                })

            # Server / Technology disclosure
            if 'Server' in headers or 'X-Powered-By' in headers:
                server_info = headers.get('Server') or headers.get('X-Powered-By')
                findings.append({
                    "name": "Server/Technology Information Disclosure",
                    "severity": "info",
                    "owasp_category": "A05:2021",
                    "url": self.target_url,
                    "confidence": 100,
                    "evidence": {"disclosed_info": server_info},
                    "remediation": "Remove or obfuscate Server and X-Powered-By headers"
                })
        except Exception as e:
            print(f"[Misconfig] Header check failed: {str(e)}")
        
        return findings

    def check_common_misconfigs(self) -> List[Dict[str, Any]]:
        """Probe for classic ASP.NET misconfigurations"""
        findings = []
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.misconfig_endpoints:
            try:
                test_url = base + path
                resp = self.http.get(test_url, timeout=7, allow_redirects=False)

                if resp.status_code in (200, 301, 302):
                    severity = "high" if any(x in path.lower() for x in ["trace.axd", "elmah"]) else "medium"
                    
                    findings.append({
                        "name": f"Exposed {path} - Security Misconfiguration",
                        "severity": severity,
                        "owasp_category": "A05:2021",
                        "url": test_url,
                        "confidence": 85,
                        "technique": "Active Probing",
                        "evidence": {
                            "status_code": resp.status_code,
                            "path": path,
                            "response_snippet": resp.text[:250] if resp.status_code == 200 else ""
                        },
                        "poc": f"curl {test_url}",
                        "remediation": "Disable tracing, ELMAH, and debug mode in production"
                    })
                
                # Check for debug/stack trace leakage in error pages
                elif resp.status_code >= 500:
                    if "stack trace" in resp.text.lower() or "at System." in resp.text or "ASP.NET" in resp.text:
                        findings.append({
                            "name": "Detailed Error / Stack Trace Exposure",
                            "severity": "high",
                            "owasp_category": "A05:2021",
                            "url": test_url,
                            "confidence": 80,
                            "technique": "Error Page Analysis",
                            "evidence": {"status_code": resp.status_code},
                            "remediation": "Set customErrors mode='On' and debug='false' in web.config"
                        })
            except:
                continue
                
        return findings

    def scan(self, urls: List[str] = None) -> List[Dict[str, Any]]:
        """Main scan entry point"""
        all_findings = []
        
        print("[MisconfigModule] Checking for security misconfigurations...")

        # Header checks
        all_findings.extend(self.check_security_headers())
        
        # Active misconfig probing
        all_findings.extend(self.check_common_misconfigs())

        # Optional: Check discovered URLs for misconfigs too
        if urls:
            for url in urls[:10]:  # limit to avoid too many requests
                try:
                    resp = self.http.get(url, timeout=6)
                    if "debug=true" in resp.text.lower() or "compilation debug" in resp.text.lower():
                        all_findings.append({
                            "name": "Debug Mode Enabled",
                            "severity": "high",
                            "owasp_category": "A05:2021",
                            "url": url,
                            "confidence": 70
                        })
                except:
                    continue

        print(f"[MisconfigModule] Completed. Found {len(all_findings)} misconfiguration findings.")
        return all_findings
