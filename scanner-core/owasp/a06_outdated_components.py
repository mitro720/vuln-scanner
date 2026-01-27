"""
Vulnerable and Outdated Components Detection
OWASP A06:2021 - Vulnerable and Outdated Components
"""

import requests
import re
from typing import List, Dict, Any


class ComponentsModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        
        # Known vulnerable versions (examples)
        self.vulnerable_versions = {
            'jquery': {
                '1.': 'critical',
                '2.': 'high',
                '3.0': 'medium',
            },
            'bootstrap': {
                '3.': 'medium',
                '4.0': 'low',
            },
            'angular': {
                '1.': 'high',
            }
        }
        
    def detect_js_libraries(self, html: str) -> List[Dict[str, Any]]:
        """Detect JavaScript libraries and versions"""
        findings = []
        
        # Common library patterns
        patterns = {
            'jquery': r'jquery[/-](\d+\.\d+\.\d+)',
            'bootstrap': r'bootstrap[/-](\d+\.\d+\.\d+)',
            'angular': r'angular[/-](\d+\.\d+\.\d+)',
            'react': r'react[/-](\d+\.\d+\.\d+)',
            'vue': r'vue[/-](\d+\.\d+\.\d+)',
        }
        
        for lib, pattern in patterns.items():
            matches = re.findall(pattern, html.lower())
            
            if matches:
                version = matches[0]
                
                # Check if version is known to be vulnerable
                if lib in self.vulnerable_versions:
                    for vuln_version, severity in self.vulnerable_versions[lib].items():
                        if version.startswith(vuln_version):
                            findings.append({
                                "name": f"Vulnerable {lib.capitalize()} Version",
                                "severity": severity,
                                "owasp_category": "A06:2021",
                                "url": self.target_url,
                                "confidence": 90,
                                "technique": "Version Detection",
                                "evidence": {
                                    "library": lib,
                                    "version": version,
                                    "description": f"Using outdated/vulnerable {lib} version"
                                },
                                "poc": f"curl {self.target_url} | grep {lib}",
                                "remediation": f"Update {lib} to the latest stable version"
                            })
                            break
                            
        return findings
        
    def check_server_version(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Check for outdated server versions"""
        findings = []
        
        if 'Server' in headers:
            server = headers['Server']
            
            # Check for version numbers
            version_match = re.search(r'(\d+\.\d+)', server)
            
            if version_match:
                version = version_match.group(1)
                
                # Example: Check for old Apache versions
                if 'Apache' in server:
                    if version.startswith('2.2') or version.startswith('2.0'):
                        findings.append({
                            "name": "Outdated Apache Server",
                            "severity": "high",
                            "owasp_category": "A06:2021",
                            "url": self.target_url,
                            "confidence": 100,
                            "technique": "Header Analysis",
                            "evidence": {
                                "server": server,
                                "version": version
                            },
                            "poc": f"curl -I {self.target_url}",
                            "remediation": "Update Apache to version 2.4 or later"
                        })
                        
        return findings
        
    def scan(self) -> List[Dict[str, Any]]:
        """Scan for vulnerable components"""
        all_findings = []
        
        try:
            response = requests.get(self.target_url, timeout=10)
            
            # Detect JS libraries
            js_findings = self.detect_js_libraries(response.text)
            all_findings.extend(js_findings)
            
            # Check server version
            server_findings = self.check_server_version(response.headers)
            all_findings.extend(server_findings)
            
        except Exception as e:
            print(f"Error scanning components: {str(e)}")
            
        return all_findings
