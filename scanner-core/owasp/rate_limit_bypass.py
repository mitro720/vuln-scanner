"""
Rate Limit Bypass Detection
OWASP A05:2021 - Security Misconfiguration
"""

import requests
import time
from typing import List, Dict, Any
from urllib.parse import urlparse


# IP spoofing headers used to bypass rate limits
BYPASS_HEADERS = [
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-IP': '127.0.0.1'},
    {'X-Remote-Addr': '127.0.0.1'},
    {'X-Client-IP': '127.0.0.1'},
    {'CF-Connecting-IP': '127.0.0.1'},
    {'True-Client-IP': '127.0.0.1'},
]


class RateLimitBypassModule:
    def __init__(self, target_url: str):
        self.target_url = target_url

    def _find_login_endpoints(self, urls: List[str]) -> List[str]:
        keywords = ['login', 'signin', 'auth', 'token', 'password', 'session']
        return [u for u in urls if any(k in u.lower() for k in keywords)]

    def test_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """
        Send 5 fast requests with baseline headers, then 5 with bypass headers.
        If baseline gets 429 but bypass headers don't — rate limit is bypassable.
        """
        findings = []
        REPEAT = 5

        # 1. Establish whether rate limit exists (baseline)
        baseline_statuses = []
        base_session = requests.Session()
        for _ in range(REPEAT):
            try:
                r = base_session.get(url, timeout=5)
                baseline_statuses.append(r.status_code)
            except Exception:
                break

        got_rate_limited = 429 in baseline_statuses or 403 in baseline_statuses

        if not got_rate_limited:
            # No rate limit at all  — still worth testing bypass but lower confidence
            pass

        # 2. Try each bypass header
        for header in BYPASS_HEADERS:
            bypass_statuses = []
            bypass_session = requests.Session()
            bypass_session.headers.update(header)
            for _ in range(REPEAT):
                try:
                    r = bypass_session.get(url, timeout=5)
                    bypass_statuses.append(r.status_code)
                except Exception:
                    break

            # Bypass confirmed: was blocked before, now not
            if got_rate_limited and 429 not in bypass_statuses and 403 not in bypass_statuses and bypass_statuses:
                findings.append({
                    "name": "Rate Limit Bypass via IP Spoofing Header",
                    "severity": "medium",
                    "owasp_category": "A05:2021",
                    "url": url,
                    "confidence": 88,
                    "technique": "Header-based IP Spoofing",
                    "evidence": {
                        "bypass_header": header,
                        "baseline_statuses": baseline_statuses,
                        "bypass_statuses": bypass_statuses,
                    },
                    "poc": f"curl '{url}' -H '{list(header.keys())[0]}: {list(header.values())[0]}'",
                    "remediation": "Never trust client-controlled IP headers for rate limiting. Use the real socket IP from the connection as the rate limit key."
                })
                break  # Found one, stop

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        # Focus on authentication / sensitive endpoints
        targets = self._find_login_endpoints(urls) or [self.target_url]
        for url in targets[:3]:  # Limit to avoid being too aggressive
            all_findings.extend(self.test_endpoint(url))
        return all_findings
