"""
SecureScan - Shared HTTP Client
Provides a consistent session with UA rotation, jittered delay, and WAF awareness.
"""

import requests
import random
import time
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlparse

# Modern Browser User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
]

class HttpClient:
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.session = requests.Session()
        self.base_delay = float(self.config.get("request_delay", 0.3))
        self.jitter = self.config.get("random_jitter", True)
        self.waf_detected = False
        
        # Initial headers
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })

    def _sleep(self):
        """Implement jittered delay and WAF-aware slowdown"""
        delay = self.base_delay
        
        # If WAF detected, significantly increase delay
        if self.waf_detected:
            delay = max(delay, 2.0)
            
        if self.jitter and delay > 0:
            # Add random variation -10% to +50%
            variation = delay * random.uniform(-0.1, 0.5)
            delay += variation
            
        if delay > 0:
            time.sleep(max(0.05, delay))

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Centralized request method with delay and UA rotation"""
        self._sleep()
        
        # Rotate UA occasionally (20% chance)
        if random.random() < 0.2:
            self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
            
        # Ensure timeout is set
        if "timeout" not in kwargs:
            kwargs["timeout"] = 10
            
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Auto-detect WAF behavior (403/429/503 from certain providers)
            if response.status_code in (403, 429):
                # Check for common WAF signatures in headers
                server = response.headers.get("Server", "").lower()
                if any(sig in server for sig in ["cloudflare", "akamai", "sucuri", "incapsula"]):
                    self.waf_detected = True
                    
            return response
        except requests.RequestException as e:
            logging.error(f"HTTP Request failed: {url} - {str(e)}")
            return None

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def set_auth_header(self, token: str, token_type: str = "Bearer"):
        self.session.headers.update({"Authorization": f"{token_type} {token}"})

    def set_cookies(self, cookies: Dict[str, str]):
        self.session.cookies.update(cookies)
