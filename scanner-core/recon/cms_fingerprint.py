"""
CMS Fingerprinting Module
Detects specific CMS platforms (WordPress, Joomla, Drupal) and enumerates exposed paths or versions.
"""
import requests
import re
from urllib.parse import urljoin
from typing import List, Dict, Any

class CMSFingerprinter:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url if target_url.endswith('/') else f"{target_url}/"
        self.findings = []
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
    def scan(self) -> List[Dict[str, Any]]:
        print(f"[*] Starting CMS Fingerprinting on {self.target_url}")
        
        try:
            resp = self.http.get(self.target_url, timeout=10)
            html = resp.text.lower()
            
            # Detect WordPress
            if "wp-content" in html or "wp-includes" in html or '<meta name="generator" content="wordpress' in html:
                self._analyze_wordpress()
                
            # Detect Joomla
            elif "joomla" in html or '<meta name="generator" content="joomla' in html:
                self._analyze_joomla()
                
            # Detect Drupal
            elif "drupal" in html or '<meta name="generator" content="drupal' in html:
                self._analyze_drupal()
                
        except requests.RequestException as e:
            print(f"[-] CMS Fingerprinting failed: {e}")
            
        return self.findings
        
    def _analyze_wordpress(self):
        print("[+] WordPress Detected. Probing common paths...")
        paths = [
            "wp-login.php",
            "wp-admin/",
            "xmlrpc.php",
            "wp-json/wp/v2/users",
            "wp-content/debug.log"
        ]
        
        for path in paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.http.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 401, 403]:
                    severity = "high" if "users" in path or "debug" in path else "info"
                    
                    self.findings.append({
                        "name": f"Exposed WordPress Path ({path})",
                        "severity": severity,
                        "owasp_category": "Recon",
                        "url": url,
                        "description": f"Target is running WordPress and exposes the widely known path: {path}",
                        "confidence": 100,
                        "technique": "Active Probing",
                        "evidence": f"Path responded with HTTP {r.status_code}",
                        "remediation": "Restrict access to sensitive WordPress directories (e.g., wp-admin) to internal IPs. Disable user enumeration via the REST API if not needed."
                    })
            except:
                pass

    def _analyze_joomla(self):
        print("[+] Joomla Detected. Probing common paths...")
        paths = [
            "administrator/",
            "components/",
            "language/",
            "templates/"
        ]
        for path in paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.http.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 401, 403]:
                    self.findings.append({
                        "name": f"Exposed Joomla Path ({path})",
                        "severity": "info",
                        "owasp_category": "Recon",
                        "url": url,
                        "description": f"Target is running Joomla and exposes the path: {path}",
                        "confidence": 100,
                        "technique": "Active Probing",
                        "evidence": f"Path responded with HTTP {r.status_code}"
                    })
            except:
                pass

    def _analyze_drupal(self):
        print("[+] Drupal Detected. Probing common paths...")
        paths = [
            "CHANGELOG.txt",
            "core/",
            "user/login"
        ]
        for path in paths:
            url = urljoin(self.target_url, path)
            try:
                r = self.http.get(url, timeout=5, allow_redirects=False)
                if r.status_code in [200, 401, 403]:
                    severity = "medium" if "CHANGELOG" in path else "info"
                    self.findings.append({
                        "name": f"Exposed Drupal Path ({path})",
                        "severity": severity,
                        "owasp_category": "Recon",
                        "url": url,
                        "description": f"Target is running Drupal and exposes the path: {path}",
                        "confidence": 100,
                        "technique": "Active Probing",
                        "evidence": f"Path responded with HTTP {r.status_code}"
                    })
            except:
                pass
