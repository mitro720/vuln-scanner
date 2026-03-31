"""
Technology Fingerprinting Module
"""

import requests
from typing import Dict, List, Any


class TechDetector:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        self.technologies = []
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
        
    def detect_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """Detect technologies from HTTP headers"""
        detected = []
        
        # Server detection
        if 'Server' in headers:
            server = headers['Server'].lower()
            if 'nginx' in server:
                detected.append(f"Nginx {server.split('/')[1] if '/' in server else ''}")
            elif 'apache' in server:
                detected.append(f"Apache {server.split('/')[1] if '/' in server else ''}")
            elif 'microsoft-iis' in server:
                detected.append("Microsoft IIS")
                
        # Framework detection
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            detected.append(powered_by)
            
        # ASP.NET detection
        if 'X-AspNet-Version' in headers:
            detected.append(f"ASP.NET {headers['X-AspNet-Version']}")
            
        # PHP detection
        if 'X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']:
            detected.append(headers['X-Powered-By'])
            
        return detected
        
    def detect_from_content(self, html: str) -> List[str]:
        """Detect technologies from HTML content"""
        detected = []
        html_lower = html.lower()
        
        # React detection
        if 'react' in html_lower or '__react' in html_lower:
            detected.append("React")
            
        # Vue.js detection
        if 'vue' in html_lower or 'v-if' in html_lower:
            detected.append("Vue.js")
            
        # Angular detection
        if 'ng-' in html_lower or 'angular' in html_lower:
            detected.append("Angular")
            
        # WordPress detection
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            detected.append("WordPress")
            
        # jQuery detection
        if 'jquery' in html_lower:
            detected.append("jQuery")
            
        return detected
        
    def detect(self) -> Dict[str, Any]:
        """Run technology detection"""
        try:
            response = self.http.get(self.target_url, timeout=10)
            
            # Detect from headers
            header_tech = self.detect_from_headers(response.headers)
            
            # Detect from content
            content_tech = self.detect_from_content(response.text)
            
            # Combine and deduplicate
            all_tech = list(set(header_tech + content_tech))
            
            return {
                "technologies": all_tech,
                "server": response.headers.get('Server', 'Unknown'),
                "status_code": response.status_code
            }
            
        except Exception as e:
            print(f"Error detecting technologies: {str(e)}")
            return {
                "technologies": [],
                "error": str(e)
            }
