"""
Open Redirect Detection
OWASP A01:2021 - Broken Access Control
"""

import re
import requests
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse



REDIRECT_PAYLOADS = [
    'https://evil.com',
    '//evil.com',
    '//evil.com/%2F..',
    'https://evil.com/%09/',
    '///evil.com',
    'https:evil.com',
    '/%5Cevil.com',
]

REDIRECT_PARAMS = re.compile(
    r'^(url|redirect|redirect_url|next|return|return_url|return_to|goto|destination|to|target|redir|continue|link|location|forward)$',
    re.I
)

import re


class OpenRedirectModule:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'SecureScan/1.0'})

    def test_url(self, url: str) -> List[Dict[str, Any]]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        redirect_params = {k: v for k, v in params.items() if REDIRECT_PARAMS.match(k)}

        if not redirect_params:
            return findings

        for param in redirect_params:
            for payload in REDIRECT_PAYLOADS:
                test_params = {**{k: v[0] for k, v in params.items()}, param: payload}
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                    # Check if the redirect Location header points to our evil domain
                    location = resp.headers.get('Location', '')
                    if resp.status_code in (301, 302, 303, 307, 308) and 'evil.com' in location:
                        findings.append({
                            "name": "Open Redirect",
                            "severity": "medium",
                            "owasp_category": "A01:2021",
                            "url": test_url,
                            "parameter": param,
                            "confidence": 95,
                            "technique": "Redirect Parameter Injection",
                            "evidence": {
                                "payload": payload,
                                "status_code": resp.status_code,
                                "location_header": location
                            },
                            "poc": f"curl -I '{test_url}'",
                            "remediation": "Validate redirect URLs against a strict allowlist of trusted domains. Reject external URLs."
                        })
                        break
                except Exception:
                    continue

        return findings

    def scan(self, urls: List[str]) -> List[Dict[str, Any]]:
        all_findings = []
        for url in urls:
            all_findings.extend(self.test_url(url))
        return all_findings
