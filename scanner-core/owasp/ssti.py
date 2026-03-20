"""
Server-Side Template Injection (SSTI) Scanner Module
"""
import requests
import re
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any

class SSTIModule:
    def __init__(self, target_url: str):
        self.target_url = target_url # Base URL
        
        # Payloads targeting various template engines
        self.payloads = [
            # Base math evaluations
            {"engine": "Generic", "payload": "{{7*7}}", "expected": "49"},
            {"engine": "Generic", "payload": "${7*7}", "expected": "49"},
            {"engine": "Generic", "payload": "<%= 7*7 %>", "expected": "49"},
            {"engine": "Generic", "payload": "[[5*5]]", "expected": "25"},
            
            # Jinja2 / Twig / Nunjucks
            {"engine": "Jinja2/Twig", "payload": "{{7*'7'}}", "expected": "7777777"},
            
            # Mako
            {"engine": "Mako", "payload": "${7*7}", "expected": "49"},
            
            # Smarty
            {"engine": "Smarty", "payload": "{math equation='7*7'}", "expected": "49"},
            
            # Pug/Jade
            {"engine": "Pug", "payload": "#{7*7}", "expected": "49"},
            
            # Handlebars (doesn't usually eval math directly, but can try helpers)
            # Java EL / OGNL (often used in Spring / Struts)
            {"engine": "Java EL", "payload": "${7 * 7}", "expected": "49"},
            {"engine": "FreeMarker", "payload": "<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}", "expected": "uid="},
        ]
        
    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        
        for url in urls:
            # We will test common parameter names, or if url has parameters, test those
            parsed = urlparse(url)
            
            # Note: For a real intensive scan, we would parse forms and inject everywhere.
            # Here, we do a quick check via query parameters on the URL
            
            test_params = ['name', 'id', 'q', 'search', 'template', 'view', 'page', 'doc']
            
            for param in test_params:
                for payload_info in self.payloads:
                    payload = payload_info['payload']
                    expected = payload_info['expected']
                    engine = payload_info['engine']
                    
                    test_url = f"{url}?{param}={payload}"
                    
                    try:
                        resp = requests.get(test_url, timeout=5)
                        
                        if expected in resp.text:
                            # Verify it's actually interpreting, not just reflecting the intended text
                            if expected == "49" and "7*7" not in resp.text:
                                findings.append({
                                    "name": "Server-Side Template Injection (SSTI)",
                                    "severity": "critical",
                                    "owasp_category": "Injection",
                                    "url": test_url,
                                    "description": f"Potential SSTI vulnerability detected. The template engine interpreted the payload and returned the evaluated result. Likely template engine: {engine}",
                                    "confidence": 95,
                                    "technique": "Active Probing",
                                    "evidence": f"Payload: {payload} | Evaluated result '{expected}' found in response body.",
                                    "remediation": "Validate and sanitize all user input before passing it to a template engine. Ensure logic-less templates are used where possible and restrict template engine features (sandboxing)."
                                })
                                break # Found one parameter vulnerable, move to next URL
                            
                            if expected == "7777777" and "7*'7'" not in resp.text:
                                findings.append({
                                    "name": "Server-Side Template Injection (SSTI)",
                                    "severity": "critical",
                                    "owasp_category": "Injection",
                                    "url": test_url,
                                    "description": f"Potential SSTI vulnerability detected. Likely Jinja2 or Twig engine.",
                                    "confidence": 95,
                                    "technique": "Active Probing",
                                    "evidence": f"Payload: {payload} | Evaluated result '{expected}' found in response body.",
                                    "remediation": "Use sandboxed environments for template execution."
                                })
                                break
                                
                    except requests.RequestException:
                        continue
                        
        return findings

