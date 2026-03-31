import requests
import time
from urllib.parse import urljoin
import logging

class SensitiveFileScanner:
    def __init__(self, target_url, max_requests_per_second=5, http_client=None):
        self.target_url = target_url if target_url.endswith('/') else f"{target_url}/"
        self.max_requests_per_second = max_requests_per_second
        self.delay = 1.0 / max_requests_per_second
        self.findings = []
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
        # Comprehensive list of common sensitive files
        self.sensitive_files = [
            # Environment & Config
            ".env",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Dockerfile",
            "web.config",
            ".htaccess",
            "config.php.bak",
            "config.bak",
            "config.json",
            
            # Source Control Exposure (Git, SVN, Mercurial)
            ".git/config",
            ".git/HEAD",
            ".git/logs/HEAD",
            ".git/index",
            ".gitignore",
            ".svn/entries",
            ".svn/wc.db",
            ".hg/requires",
            
            # Package Managers
            "package.json",
            "package-lock.json",
            "composer.json",
            "composer.lock",
            "yarn.lock",
            
            # Development & Info
            "phpinfo.php",
            "info.php",
            ".bash_history",
            ".DS_Store",
            "swagger.json",
            "openapi.json",
            
            # Backups & Databases
            "backup.sql",
            "db.sqlite",
            "db.sqlite3",
            "dump.sql"
        ]

    def scan(self):
        """Probes the target for sensitive files safely."""
        logging.info(f"[*] Starting Sensitive File Scan on {self.target_url}")
        
        for file_path in self.sensitive_files:
            url = urljoin(self.target_url, file_path)
            try:
                # Basic scope guard: check if the parsed URL still belongs to the target domain
                # (Simple check, can be enhanced for strict domain matching)
                if not url.startswith(self.target_url):
                     continue # Skipped, out of scope

                response = self.http.get(url, timeout=5, allow_redirects=False)
                
                # Check for explicit 200 OK
                if response.status_code == 200:
                    # Basic heuristic: ensure it's not a generic 404 disguised as a 200
                    # For instance, a generic text/html "Not Found" page
                    content_type = response.headers.get("Content-Type", "").lower()
                    content_length = len(response.content)
                    
                    if "text/html" not in content_type or (file_path.endswith('.php') and "text/html" in content_type):
                        self.findings.append({
                            "type": "Sensitive File Exposure",
                            "severity": "High",
                            "url": url,
                            "description": f"A potentially sensitive file ({file_path}) was discovered, which may leak configuration secrets or source code.",
                            "evidence": f"Status: {response.status_code}, Length: {content_length} bytes",
                            "remediation": "Restrict access to configuration, backup, and environment files. Ensure they are outside the web root or blocked via web server configuration (e.g., .htaccess or nginx.conf)."
                        })
                        logging.warning(f"[!] Found: {url}")
                
                # Rate Limiting
                time.sleep(self.delay)

            except requests.RequestException as e:
                logging.debug(f"Request to {url} failed: {str(e)}")
        
        return self.findings

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python sensitive_files.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    scanner = SensitiveFileScanner(url, max_requests_per_second=2)
    results = scanner.scan()
    import json
    print(json.dumps(results, indent=2))
