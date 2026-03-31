"""
WAF Detection Module
"""

import requests
from typing import Dict, Any, List


class WAFDetector:
    def __init__(self, target_url: str, http_client: Any = None):
        self.target_url = target_url
        
        # Inject custom HttpClient if provided
        if http_client:
            self.http = http_client
        else:
            import requests as r
            self.http = r
            
        # Known WAF signatures
        self.waf_signatures = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-"],
            "Akamai": ["akamai"],
            "Imperva": ["incapsula", "visid_incap"],
            "Sucuri": ["sucuri", "x-sucuri"],
            "ModSecurity": ["mod_security", "modsecurity"],
        }
        
    def detect(self) -> Dict[str, Any]:
        """Detect WAF presence"""
        detected_wafs = []
        
        try:
            # Normal request
            response = self.http.get(self.target_url, timeout=10)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check headers for WAF signatures
            for waf_name, signatures in self.waf_signatures.items():
                for signature in signatures:
                    for header, value in headers.items():
                        if signature.lower() in header.lower() or signature.lower() in value.lower():
                            detected_wafs.append(waf_name)
                            break
                            
            # Send malicious payload to trigger WAF
            malicious_url = f"{self.target_url}?test=<script>alert(1)</script>"
            try:
                mal_response = self.http.get(malicious_url, timeout=10)
                
                # Check for WAF block responses
                if mal_response.status_code in [403, 406, 419, 429, 503]:
                    if not detected_wafs:
                        detected_wafs.append("Generic WAF")
                        
            except:
                pass
                
            return {
                "waf_detected": len(detected_wafs) > 0,
                "wafs": list(set(detected_wafs)),
                "confidence": "high" if detected_wafs else "low"
            }
            
        except Exception as e:
            print(f"Error detecting WAF: {str(e)}")
            return {
                "waf_detected": False,
                "wafs": [],
                "error": str(e)
            }
